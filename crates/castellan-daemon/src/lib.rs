use castellan_core::{
  new_session_id, EventSink, FreezeState, Registry, Request, Response, Session, SessionId,
  SessionReport,
};
use castellan_envelope::{AuditWatcher, Snapshot};
use castellan_freezer::CgroupRoot;
use castellan_policy::Policy;
use castellan_trust::{Signal, TrustDb, TrustEvent};
use rustc_hash::FxHashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

struct SessionAudit {
  _watcher: AuditWatcher,
  baseline: Vec<(PathBuf, Snapshot)>,
}

#[derive(Default)]
struct SessionNotes {
  undo_upper: Option<PathBuf>,
}

/// A pending bless-broker expansion request.
#[derive(Debug, Clone)]
struct BlessRequest {
  session: SessionId,
  project: PathBuf,
  want: String,
  #[allow(dead_code)]
  reason: String,
  created_ts: u64,
}

#[derive(Clone)]
pub struct Daemon {
  root: Arc<CgroupRoot>,
  registry: Arc<Mutex<Registry>>,
  audits: Arc<Mutex<FxHashMap<SessionId, SessionAudit>>>,
  notes: Arc<Mutex<FxHashMap<SessionId, SessionNotes>>>,
  honeypot: Arc<castellan_canary::Honeypot>,
  trust: Arc<Mutex<TrustDb>>,
  bless: Arc<Mutex<FxHashMap<String, BlessRequest>>>,
}

impl Daemon {
  pub fn new() -> std::io::Result<Self> {
    let state = Self::state_dir();
    let trust = match TrustDb::open(&state) {
      Ok(t) => Arc::new(Mutex::new(t)),
      Err(e) => {
        eprintln!("castellan-daemon: trust.db unavailable ({e}) — trust scoring disabled");
        return Err(std::io::Error::other(format!("trust.db open failed: {e}")));
      }
    };
    let registry: Arc<Mutex<Registry>> = Arc::new(Mutex::new(Registry::default()));
    let trust_cb = Arc::clone(&trust);
    let reg_cb = Arc::clone(&registry);
    let honeypot = match castellan_canary::Honeypot::start_with_callback(
      &state,
      Arc::new(move |session: &str| {
        // canary hit: apply the negative trust signal to the session's project
        let project = reg_cb
          .lock()
          .unwrap()
          .get(&session.to_string())
          .map(|s| s.project.clone())
          .unwrap_or_else(|| PathBuf::from("/"));
        let mut db = trust_cb.lock().unwrap();
        let _ = db.apply(
          &project,
          &TrustEvent {
            ts: castellan_core::now_unix(),
            session: session.to_string(),
            signal: Signal::CanaryHit,
            evidence: "canary credential used against honeypot".into(),
          },
        );
      }),
    ) {
      Ok(h) => {
        eprintln!("castellan-daemon canary honeypot on 127.0.0.1:{}", h.port);
        Arc::new(h)
      }
      Err(e) => {
        // honeypot is optional infrastructure: sessions still run without it
        eprintln!("castellan-daemon: honeypot unavailable ({e}) — canaries disabled");
        Arc::new(castellan_canary::Honeypot::detached())
      }
    };
    Ok(Self {
      root: Arc::new(CgroupRoot::detect()?),
      registry,
      audits: Arc::new(Mutex::new(FxHashMap::default())),
      notes: Arc::new(Mutex::new(FxHashMap::default())),
      honeypot,
      trust,
      bless: Arc::new(Mutex::new(FxHashMap::default())),
    })
  }

  fn state_dir() -> PathBuf {
    std::env::var("XDG_STATE_HOME")
      .map(PathBuf::from)
      .unwrap_or_else(|_| {
        PathBuf::from(format!("/home/{}/.local/state", nix::unistd::User::from_uid(nix::unistd::Uid::current()).ok().and_then(|u| u.map(|u| u.name)).unwrap_or_default()))
      })
  }

  pub fn socket_path() -> PathBuf {
    let runtime = std::env::var("XDG_RUNTIME_DIR")
      .unwrap_or_else(|_| format!("/run/user/{}", nix::unistd::Uid::current().as_raw()));
    Path::new(&runtime).join("castellan.sock")
  }

  pub fn serve(&self) -> std::io::Result<()> {
    let path = Self::socket_path();
    let _ = std::fs::remove_file(&path);
    if let Some(parent) = path.parent() {
      std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(&path)?;
    eprintln!("castellan-daemon listening on {}", path.display());
    for stream in listener.incoming() {
      match stream {
        Ok(s) => {
          let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(30)));
          let daemon = self.clone();
          let _ = std::thread::Builder::new().name("conn".into()).spawn(move || {
            if let Err(e) = daemon.handle_conn(s) {
              eprintln!("conn error: {e}");
            }
          });
        }
        Err(e) => eprintln!("accept error: {e}"),
      }
    }
    Ok(())
  }

  fn handle_conn(&self, stream: UnixStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    loop {
      line.clear();
      if reader.read_line(&mut line)? == 0 {
        return Ok(());
      }
      let resp = match serde_json::from_str::<Request>(line.trim()) {
        Ok(req) => self.dispatch(req),
        Err(e) => Response::err(format!("bad request: {e}")),
      };
      let mut out = serde_json::to_string(&resp)?;
      out.push('\n');
      (&stream).write_all(out.as_bytes())?;
    }
  }

  fn dispatch(&self, req: Request) -> Response {
    match req {
      Request::Spawn { harness, project, pid } => self.spawn(harness, project, pid),
      Request::Adopt { session, pids } => self.adopt(&session, pids),
      Request::Freeze { session } => self.freeze(session.as_ref(), true),
      Request::Thaw { session } => self.freeze(session.as_ref(), false),
      Request::Kill { session } => self.kill(session.as_ref()),
      Request::Status => self.status(),
      Request::Note { session, kind, detail } => self.note(&session, &kind, &detail),
      Request::UndoDiff { session } => self.undo_diff(&session),
      Request::UndoDiscard { session } => self.undo_discard(&session),
      Request::UndoCommit { session } => self.undo_commit(&session),
      Request::CanaryRegister { session, project, harness } => {
        self.canary_register(&session, &project, &harness)
      }
      Request::HoneypotPort => {
        Response::ok().with_extra("port", serde_json::json!(self.honeypot.port))
      }
      Request::TrustScore { project } => self.trust_score(&project),
      Request::TrustSignal { project, session, signal, evidence } => {
        self.trust_signal(&project, &session, &signal, &evidence)
      }
      Request::BlessRequest { session, want, reason } => {
        self.bless_request(&session, &want, &reason)
      }
      Request::BlessApprove { nonce } => self.bless_approve(&nonce),
      Request::BlessReject { nonce } => self.bless_reject(&nonce),
      Request::Cert { session } => self.cert(&session),
      Request::Replay { session, narrower_project } => self.replay(&session, &narrower_project),
      Request::Radar { session, project } => self.radar(&session, &project),
    }
  }

  fn radar(&self, session: &str, project: &Path) -> Response {
    let state = Self::state_dir();
    let hv = match castellan_radar::encode_session_from_spine(session, &state) {
      Ok(hv) => hv,
      Err(e) => return Response::err(format!("radar encode failed: {e}")),
    };
    let events_encoded = castellan_core::EventSink::for_session(&state, session)
      .and_then(|s| s.read_all())
      .map(|e| e.len())
      .unwrap_or(0);
    // per-project prototype, persisted under castellan/radar/
    let proto_path = state
      .join("castellan/radar")
      .join(format!("{}.bin", castellan_radar::project_hash(project)));
    let mut prototype = match std::fs::read(&proto_path) {
      Ok(bytes) => castellan_radar::Prototype::from_bytes(&bytes),
      Err(_) => castellan_radar::Prototype::empty(),
    };
    let report = castellan_radar::radar_report(session, &hv, &prototype, events_encoded);
    prototype.fold(&hv);
    if let Some(dir) = proto_path.parent() {
      let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&proto_path, prototype.to_bytes());
    let json = serde_json::to_value(&report).unwrap_or(serde_json::Value::Null);
    Response::ok().with_extra("radar", json)
  }

  fn replay(&self, session: &str, narrower_project: &Path) -> Response {
    let project = {
      let reg = self.registry.lock().unwrap();
      match reg.get(&session.to_string()) {
        Some(s) => s.project.clone(),
        None => {
          let dir = Self::state_dir().join("castellan/sessions");
          let meta = std::fs::read_to_string(dir.join(format!("{session}.json")));
          match meta {
            Ok(m) => match serde_json::from_str::<serde_json::Value>(&m) {
              Ok(v) => v
                .get("project")
                .and_then(|p| p.as_str())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/")),
              Err(_) => return Response::err("unknown session"),
            },
            Err(_) => return Response::err("unknown session"),
          }
        }
      }
    };
    let harness = {
      let reg = self.registry.lock().unwrap();
      reg.get(&session.to_string()).map(|s| s.harness.clone()).unwrap_or_else(|| "claude".into())
    };
    let original = castellan_policy::Policy::new(session, &harness, project);
    let alternate = castellan_replay::narrower_policy(&original, narrower_project);
    match castellan_replay::replay_session(session, &Self::state_dir(), &original, &alternate) {
      Ok(out) => {
        let json = serde_json::to_value(&out).unwrap_or(serde_json::Value::Null);
        Response::ok().with_extra("replay", json)
      }
      Err(e) => Response::err(format!("replay failed: {e}")),
    }
  }

  fn cert(&self, session: &str) -> Response {
    let project = {
      let reg = self.registry.lock().unwrap();
      match reg.get(&session.to_string()) {
        Some(s) => s.project.clone(),
        None => {
          // finished session: read the durable mapping
          let dir = Self::state_dir().join("castellan/sessions");
          let meta = std::fs::read_to_string(dir.join(format!("{session}.json")));
          match meta {
            Ok(m) => match serde_json::from_str::<serde_json::Value>(&m) {
              Ok(v) => v
                .get("project")
                .and_then(|p| p.as_str())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/")),
              Err(_) => return Response::err("unknown session"),
            },
            Err(_) => return Response::err("unknown session"),
          }
        }
      }
    };
    match castellan_proof::certificate::assemble_certificate(
      session,
      &project,
      &Self::state_dir(),
    ) {
      Ok(cert) => {
        let json = serde_json::to_value(&cert).unwrap_or(serde_json::Value::Null);
        Response::ok().with_extra("cert", json)
      }
      Err(e) => Response::err(format!("certificate assembly failed: {e}")),
    }
  }

  fn trust_score(&self, project: &Path) -> Response {
    let db = self.trust.lock().unwrap();
    match db.score(project) {
      Ok(t) => Response::ok().with_extra(
        "trust",
        serde_json::json!({
          "score": t.score,
          "tier": t.tier.as_str(),
          "last_event_ts": t.last_event_ts,
        }),
      ),
      Err(e) => Response::err(format!("trust query failed: {e}")),
    }
  }

  fn trust_signal(&self, project: &Path, session: &str, signal: &str, evidence: &str) -> Response {
    let sig = match signal {
      "proof_passed" => Signal::ProofPassed,
      "clean_session" => Signal::CleanSession,
      "user_revert" => Signal::UserRevert,
      "envelope_escape" => Signal::EnvelopeEscape,
      "canary_hit" => Signal::CanaryHit,
      "audit_mismatch" => Signal::AuditMismatch,
      "forged_nonce" => Signal::ForgedNonce,
      other => return Response::err(format!("unknown signal: {other}")),
    };
    let ev = TrustEvent {
      ts: castellan_core::now_unix(),
      session: session.to_string(),
      signal: sig,
      evidence: evidence.to_string(),
    };
    let mut db = self.trust.lock().unwrap();
    match db.apply(project, &ev) {
      Ok(t) => Response::ok().with_extra(
        "trust",
        serde_json::json!({
          "score": t.score,
          "tier": t.tier.as_str(),
          "last_event_ts": t.last_event_ts,
        }),
      ),
      Err(e) => Response::err(format!("trust apply failed: {e}")),
    }
  }

  /// Bless-broker: register an expansion request. The nonce is returned
  /// to the CALLER (the human's terminal), never to the agent's env.
  /// Rate limits: 3/session, 10/project/day, 5min cooling-off.
  fn bless_request(&self, session: &str, want: &str, reason: &str) -> Response {
    let now = castellan_core::now_unix();
    let project = {
      let reg = self.registry.lock().unwrap();
      match reg.get(&session.to_string()) {
        Some(s) => s.project.clone(),
        None => return Response::err("unknown session"),
      }
    };
    // per-session cap: 3
    let session_count = {
      let b = self.bless.lock().unwrap();
      b.values().filter(|r| r.session == session).count()
    };
    if session_count >= 3 {
      return Response::err("expansion limit reached (3 per session)");
    }
    // per-project daily cap: 10
    let day = now / 86_400;
    let project_count = {
      let b = self.bless.lock().unwrap();
      b.values()
        .filter(|r| r.project == project && r.created_ts / 86_400 == day)
        .count()
    };
    if project_count >= 10 {
      return Response::err("expansion limit reached (10 per project per day)");
    }
    // cooling-off: 5 minutes between expansions for this session
    let last_ts = {
      let b = self.bless.lock().unwrap();
      b.values()
        .filter(|r| r.session == session)
        .map(|r| r.created_ts)
        .max()
        .unwrap_or(0)
    };
    if now - last_ts < 300 {
      return Response::err("cooling-off period active (5 minutes between expansions)");
    }
    let nonce = castellan_core::new_bless_nonce();
    let req = BlessRequest {
      session: session.to_string(),
      project,
      want: want.to_string(),
      reason: reason.to_string(),
      created_ts: now,
    };
    self.bless.lock().unwrap().insert(nonce.clone(), req);
    Response::ok().with_extra(
      "bless",
      serde_json::json!({
        "nonce": nonce,
        "want": want,
        "session": session,
        "note": "nonce is for the human operator only — never pass it to the agent",
      }),
    )
  }

  /// Bless-broker: approve by nonce. Unknown nonce = forged attempt:
  /// floor the project's trust at 0 (forged_nonce signal).
  fn bless_approve(&self, nonce: &str) -> Response {
    let req = {
      let mut b = self.bless.lock().unwrap();
      match b.remove(nonce) {
        Some(r) => r,
        None => {
          // forged nonce: floor the project's trust at 0
          let project = self
            .registry
            .lock()
            .unwrap()
            .values()
            .find(|s| s.id == nonce)
            .map(|s| s.project.clone())
            .unwrap_or_else(|| PathBuf::from("/"));
          let mut db = self.trust.lock().unwrap();
          let _ = db.apply(
            &project,
            &TrustEvent {
              ts: castellan_core::now_unix(),
              session: "bless".into(),
              signal: Signal::ForgedNonce,
              evidence: format!("approve with unknown nonce {nonce}"),
            },
          );
          return Response::err("unknown nonce — approval forged?");
        }
      }
    };
    // v1: approval is recorded; the restart-with-wider-envelope
    // orchestration is a follow-up (documented in bless-broker.md).
    Response::ok().with_extra(
      "bless",
      serde_json::json!({
        "approved": true,
        "session": req.session,
        "want": req.want,
        "note": "v1 records approval; envelope re-mint + restart is P4",
      }),
    )
  }

  fn bless_reject(&self, nonce: &str) -> Response {
    let removed = self.bless.lock().unwrap().remove(nonce).is_some();
    if removed {
      Response::ok().with_message("rejected")
    } else {
      Response::err("unknown nonce")
    }
  }

  fn canary_register(&self, session: &str, _project: &Path, _harness: &str) -> Response {
    // the session must exist (spawned before launch continues)
    if !self.registry.lock().unwrap().contains(&session.to_string()) {
      return Response::err("unknown session");
    }
    let scratch = Self::state_dir().join("castellan/sessions").join(session);
    let planted = match castellan_canary::plant(session, &scratch) {
      Ok(p) => p,
      Err(e) => return Response::err(format!("canary plant failed: {e}")),
    };
    for s in &planted.secrets {
      self.honeypot.register(s);
    }
    let secrets: Vec<serde_json::Value> =
      planted.secrets.iter().map(|s| serde_json::Value::String(s.value.clone())).collect();
    Response::ok()
      .with_message("canaries planted")
      .with_extra(
        "canary",
        serde_json::json!({
          "dir": planted.dir.display().to_string(),
          "port": self.honeypot.port,
          "secrets": secrets,
        }),
      )
  }

  fn note(&self, session: &str, kind: &str, detail: &str) -> Response {
    let mut notes = self.notes.lock().unwrap();
    let entry = notes.entry(session.to_string()).or_default();
    match kind {
      "undo" => entry.undo_upper = Some(PathBuf::from(detail)),
      _ => return Response::err(format!("unknown note kind: {kind}")),
    }
    Response::ok().with_message(format!("noted {kind}"))
  }

  fn undo_diff(&self, session: &str) -> Response {
    let upper = {
      let notes = self.notes.lock().unwrap();
      match notes.get(session).and_then(|n| n.undo_upper.clone()) {
        Some(u) => u,
        None => return Response::err("no undo layer recorded for this session"),
      }
    };
    match castellan_ledger::diff_upper(&upper) {
      Ok(changes) => {
        let files: Vec<serde_json::Value> = changes
          .iter()
          .map(|c| serde_json::json!({ "path": c.path, "kind": c.kind, "size": c.size }))
          .collect();
        Response::ok()
          .with_message(format!("{} change(s)", files.len()))
          .with_extra("changes", serde_json::Value::Array(files))
      }
      Err(e) => Response::err(format!("diff failed: {e}")),
    }
  }

  fn undo_discard(&self, session: &str) -> Response {
    let (upper, work) = {
      let mut notes = self.notes.lock().unwrap();
      let Some(n) = notes.get_mut(session) else {
        return Response::err("no undo layer recorded for this session");
      };
      match n.undo_upper.take() {
        Some(upper) => {
          let work = upper.with_file_name("work");
          (upper, work)
        }
        None => return Response::err("no undo layer recorded for this session"),
      }
    };
    // freeze first so nothing writes while we wipe
    if !self.freeze(Some(&session.to_string()), true).ok {
      eprintln!("freeze-before-undo failed");
    }
    let project = {
      let reg = self.registry.lock().unwrap();
      reg.get(&session.to_string()).map(|s| s.project.clone())
    };
    let _ = self.kill(Some(&session.to_string()));
    match castellan_ledger::discard(&upper, &work) {
      Ok(()) => {
        // user reverted the session: negative trust signal
        if let Some(project) = project {
          let mut db = self.trust.lock().unwrap();
          let _ = db.apply(
            &project,
            &TrustEvent {
              ts: castellan_core::now_unix(),
              session: session.to_string(),
              signal: Signal::UserRevert,
              evidence: "user invoked castellan undo".into(),
            },
          );
        }
        Response::ok().with_message("discarded")
      }
      Err(e) => Response::err(format!("discard failed: {e}")),
    }
  }

  fn undo_commit(&self, session: &str) -> Response {
    let (upper, work) = {
      let mut notes = self.notes.lock().unwrap();
      let Some(n) = notes.get_mut(session) else {
        return Response::err("no undo layer recorded for this session");
      };
      match n.undo_upper.take() {
        Some(upper) => {
          let work = upper.with_file_name("work");
          (upper, work)
        }
        None => return Response::err("no undo layer recorded for this session"),
      }
    };
    // commit needs the real project root — read it from the registry
    let project = {
      let reg = self.registry.lock().unwrap();
      match reg.get(&session.to_string()) {
        Some(s) => s.project.clone(),
        None => return Response::err("unknown session"),
      }
    };
    if !self.freeze(Some(&session.to_string()), true).ok {
      eprintln!("freeze-before-commit failed");
    }
    let _ = self.kill(Some(&session.to_string()));
    // placebo-controlled proof: a real fix must drop the danger signal
    // more than a neutral placeholder. Only a passing proof earns the
    // proof_passed signal (+10). No danger-reducing edits = vacuous,
    // honestly labeled (no signal). Runs on the upper layer BEFORE
    // commit materializes it onto the project.
    let proofs = castellan_proof::run_session_placebo(&project, &upper);
    let passed: Vec<&castellan_proof::ProofResult> =
      proofs.iter().filter(|p| p.passed).collect();
    match castellan_ledger::commit(&project, &upper) {
      Ok(applied) => {
        let _ = castellan_ledger::discard(&upper, &work);
        // user kept the session: positive trust signal
        let mut db = self.trust.lock().unwrap();
        let _ = db.apply(
          &project,
          &TrustEvent {
            ts: castellan_core::now_unix(),
            session: session.to_string(),
            signal: Signal::CleanSession,
            evidence: format!("user kept session; {} change(s) committed", applied.len()),
          },
        );
        if !passed.is_empty() {
          let _ = db.apply(
            &project,
            &TrustEvent {
              ts: castellan_core::now_unix(),
              session: session.to_string(),
              signal: Signal::ProofPassed,
              evidence: format!(
                "{} placebo-controlled proof(s) passed; strengths: {}",
                passed.len(),
                passed
                  .iter()
                  .map(|p| format!("{:.2}", p.strength()))
                  .collect::<Vec<_>>()
                  .join(", ")
              ),
            },
          );
        }
        // Factor A: daemon re-runs the pre-existing test suite in a
        // side-scope reading post-edit state. Configured per project via
        // .reliary/castellan.toml [proof] test_cmd. Skipped + honestly
        // labeled when unconfigured.
        let test_ok = self.run_project_tests(session, &project);
        if test_ok {
          let _ = db.apply(
            &project,
            &TrustEvent {
              ts: castellan_core::now_unix(),
              session: session.to_string(),
              signal: Signal::ProofPassed,
              evidence: "daemon re-ran pre-existing test suite; passed".into(),
            },
          );
        }
        let lines: Vec<serde_json::Value> =
          applied.iter().map(|l| serde_json::Value::String(l.clone())).collect();
        Response::ok()
          .with_message(format!("committed {} change(s)", applied.len()))
          .with_extra("applied", serde_json::Value::Array(lines))
      }
      Err(e) => Response::err(format!("commit failed: {e}")),
    }
  }

  /// Factor A: daemon-side test re-run. The config is read from the
  /// project — inside the agent's write roots — so the sha256 pinned
  /// at spawn is the authority: if the config changed since launch,
  /// the command is refused (it may be attacker-written). Runs the
  /// test_cmd with the project as cwd and a 300s timeout. Returns
  /// true only on exit 0.
  fn run_project_tests(&self, session: &str, project: &Path) -> bool {
    let pinned = {
      let reg = self.registry.lock().unwrap();
      reg.get(&session.to_string()).and_then(|s| s.config_sha.clone())
    };
    let current = project_config_sha(project);
    match verify_config_pin(&pinned, &current) {
      ConfigVerdict::NotPinned => {
        eprintln!("castellan-daemon: project config not pinned at launch — test re-run refused");
        return false;
      }
      ConfigVerdict::Drifted => {
        eprintln!(
          "castellan-daemon: project config changed since launch — test re-run REFUSED (possible agent tampering)"
        );
        if let Ok(sink) = EventSink::for_session(&Self::state_dir(), session) {
          let _ = sink.emit("config_drift", ".reliary/castellan.toml", "deny");
        }
        return false;
      }
      ConfigVerdict::Ok => {}
    }
    let cfg_path = project.join(".reliary/castellan.toml");
    let Ok(cfg) = std::fs::read_to_string(&cfg_path) else {
      eprintln!("castellan-daemon: no .reliary/castellan.toml — test re-run skipped");
      return false;
    };
    let Ok(parsed) = cfg.parse::<toml::Value>() else {
      eprintln!("castellan-daemon: unparseable .reliary/castellan.toml — test re-run skipped");
      return false;
    };
    let Some(cmd) = parsed
      .get("proof")
      .and_then(|p| p.get("test_cmd"))
      .and_then(|c| c.as_str())
    else {
      eprintln!("castellan-daemon: no [proof] test_cmd — test re-run skipped");
      return false;
    };
    let mut child = match std::process::Command::new("sh")
      .arg("-c")
      .arg(cmd)
      .current_dir(project)
      .stdout(std::process::Stdio::null())
      .stderr(std::process::Stdio::null())
      .spawn()
    {
      Ok(c) => c,
      Err(e) => {
        eprintln!("castellan-daemon: test re-run spawn failed: {e}");
        return false;
      }
    };
    // 300s timeout: kill the test if it hangs
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    loop {
      match child.try_wait() {
        Ok(Some(status)) => return status.success(),
        Ok(None) => {
          if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("castellan-daemon: test re-run timed out after 300s");
            return false;
          }
          std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Err(e) => {
          eprintln!("castellan-daemon: test re-run wait failed: {e}");
          return false;
        }
      }
    }
  }

  fn spawn(&self, harness: String, project: PathBuf, pid: Option<u32>) -> Response {
    let id = new_session_id();
    if let Err(e) = self.root.create_session(&id) {
      return Response::err(format!("cgroup create failed: {e}"));
    }
    if let Some(pid) = pid {
      if let Err(e) = self.root.write_procs(&id, &[pid]) {
        let _ = self.root.destroy_session(&id);
        return Response::err(format!("failed to move pid into scope: {e}"));
      }
    }
    let config_sha = project_config_sha(&project);
    let pinned = config_sha.clone();
    self.registry.lock().unwrap().insert(Session {
      id: id.clone(),
      harness: harness.clone(),
      project: project.clone(),
      config_sha: pinned,
    });
    self.start_audit(&id, &harness, &project);
    // durable session->project mapping: certificates must work for
    // finished sessions (transferable proof), so persist at spawn
    let _ = self.persist_session(&id, &project, &harness, &config_sha);
    Response::ok().with_message(format!("spawned session {id}"))
  }

  fn persist_session(
    &self,
    id: &str,
    project: &Path,
    harness: &str,
    config_sha: &Option<String>,
  ) -> std::io::Result<()> {
    let dir = Self::state_dir().join("castellan/sessions");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
      dir.join(format!("{id}.json")),
      serde_json::json!({
        "session": id,
        "project": project.display().to_string(),
        "harness": harness,
        "config_sha": config_sha,
      })
      .to_string(),
    )
  }

  fn start_audit(&self, id: &SessionId, harness: &str, project: &Path) {
    let policy = Policy::new(id, harness, project.to_path_buf());
    let mut baseline = Vec::new();
    for dir in castellan_policy::harness_state_dirs(harness) {
      if dir.is_dir() {
        let snap = Snapshot::take(dir.clone());
        baseline.push((dir, snap));
      }
    }
    if let Ok(sink) = EventSink::for_session(&Self::state_dir(), id) {
      let watcher = AuditWatcher::start(policy, sink);
      self.audits.lock().unwrap().insert(id.clone(), SessionAudit { _watcher: watcher, baseline });
    }
  }

  fn end_audit(&self, id: &SessionId, harness: &str) -> Option<usize> {
    let audit = self.audits.lock().unwrap().remove(id)?;
    audit._watcher.stop();
    let mut drift = Vec::new();
    for (dir, base) in &audit.baseline {
      drift.extend(Snapshot::take(dir.clone()).diff_since(base));
    }
    if drift.is_empty() {
      return Some(0);
    }
    if let Ok(sink) = EventSink::for_session(&Self::state_dir(), id) {
      for d in &drift {
        let path = d.split_once(' ').map(|(_, p)| p).unwrap_or(d);
        let _ = sink.emit("harness_drift", path, "quarantine");
      }
    }
    eprintln!("castellan-daemon: session {id} ({harness}) harness-state drift: {} file(s)", drift.len());
    Some(drift.len())
  }

  fn adopt(&self, session: &SessionId, pids: Vec<u32>) -> Response {
    {
      let reg = self.registry.lock().unwrap();
      if !reg.contains(session) {
        return Response::err(format!("unknown session {session}"));
      }
    }
    match self.root.write_procs(session, &pids) {
      Ok(n) => Response::ok().with_message(format!("adopted {n} pids into {session}")),
      Err(e) => Response::err(format!("adopt failed: {e}")),
    }
  }

  fn freeze(&self, session: Option<&SessionId>, freeze: bool) -> Response {
    let targets = self.resolve_targets(session);
    if targets.is_empty() {
      return Response::ok()
        .with_message(if freeze { "no sessions to freeze" } else { "no sessions to thaw" });
    }
    let msgs: Vec<String> = targets
      .iter()
      .map(|id| match self.root.set_freeze(id, freeze) {
        Ok(state) => format!("{id}: {}", state.as_str()),
        Err(e) => format!("{id}: error {e}"),
      })
      .collect();
    Response::ok().with_message(msgs.join(", ")).with_sessions(self.reports())
  }

  fn kill(&self, session: Option<&SessionId>) -> Response {
    let targets = self.resolve_targets(session);
    let mut msgs = Vec::new();
    for id in targets {
      let harness = self.registry.lock().unwrap().get(&id).map(|s| s.harness.clone());
      if let Some(h) = harness {
        self.end_audit(&id, &h);
      }
      let _ = self.root.set_freeze(&id, false);
      msgs.push(match self.root.kill_all(&id) {
        Ok(n) => format!("{id}: killed {n}"),
        Err(e) => format!("{id}: error {e}"),
      });
      let _ = self.root.destroy_session(&id);
      self.registry.lock().unwrap().remove(&id);
    }
    let joined = msgs.join(", ");
    Response::ok()
      .with_message(if msgs.is_empty() { "nothing to kill" } else { joined.as_str() })
      .with_sessions(self.reports())
  }

  fn status(&self) -> Response {
    {
      let mut reg = self.registry.lock().unwrap();
      for id in reg.ids() {
        if self.root.freeze_state(&id).unwrap_or(FreezeState::Missing) == FreezeState::Missing {
          reg.remove(&id);
        }
      }
    }
    let reports = self.reports();
    let frozen = reports.iter().filter(|r| r.state == FreezeState::Frozen).count();
    Response::ok()
      .with_message(format!("{} session(s), {} frozen", reports.len(), frozen))
      .with_sessions(reports)
  }

  fn resolve_targets(&self, session: Option<&SessionId>) -> Vec<SessionId> {
    match session {
      Some(id) => vec![id.clone()],
      None => self.registry.lock().unwrap().ids(),
    }
  }

  fn reports(&self) -> Vec<SessionReport> {
    self
      .registry
      .lock()
      .unwrap()
      .values()
      .map(|s| SessionReport {
        id: s.id.clone(),
        harness: s.harness.clone(),
        project: s.project.display().to_string(),
        state: self.root.freeze_state(&s.id).unwrap_or(FreezeState::Missing),
        pids: self.root.populate_count(&s.id),
      })
      .collect()
  }
}

// ---------------- config pinning (S0 audit fix) ----------------

pub enum ConfigVerdict {
  Ok,
  NotPinned,
  Drifted,
}

/// Pin check: the project config lives inside the agent's write roots,
/// so a test_cmd may only run if the config is byte-identical to the
/// launch-time pin. No pin (config absent at launch) = never run.
pub fn verify_config_pin(pinned: &Option<String>, current: &Option<String>) -> ConfigVerdict {
  match (pinned, current) {
    (Some(p), Some(c)) if p == c => ConfigVerdict::Ok,
    (Some(_), _) => ConfigVerdict::Drifted,
    (None, _) => ConfigVerdict::NotPinned,
  }
}

/// sha256 of the project's .reliary/castellan.toml, or None if absent.
pub fn project_config_sha(project: &Path) -> Option<String> {
  use sha2::{Digest, Sha256};
  let bytes = std::fs::read(project.join(".reliary/castellan.toml")).ok()?;
  let digest = Sha256::digest(&bytes);
  Some(digest.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn config_pin_ok_when_identical() {
    let pin = Some("a".into());
    assert!(matches!(
      verify_config_pin(&pin, &Some("a".into())),
      ConfigVerdict::Ok
    ));
  }

  #[test]
  fn config_pin_drifted_when_changed_or_removed() {
    let pin = Some("a".into());
    assert!(matches!(
      verify_config_pin(&pin, &Some("b".into())),
      ConfigVerdict::Drifted
    ));
    assert!(matches!(verify_config_pin(&pin, &None), ConfigVerdict::Drifted));
  }

  #[test]
  fn config_pin_not_pinned_when_absent_at_launch() {
    assert!(matches!(
      verify_config_pin(&None, &Some("b".into())),
      ConfigVerdict::NotPinned
    ));
    assert!(matches!(verify_config_pin(&None, &None), ConfigVerdict::NotPinned));
  }

  #[test]
  fn project_config_sha_roundtrip() {
    let dir = std::env::temp_dir().join("castellan-cfg-pin-test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".reliary")).unwrap();
    assert_eq!(project_config_sha(&dir), None);
    std::fs::write(dir.join(".reliary/castellan.toml"), "[proof]\ntest_cmd = \"true\"\n").unwrap();
    let sha = project_config_sha(&dir).unwrap();
    assert_eq!(sha.len(), 64);
    // same content, same hash
    assert_eq!(project_config_sha(&dir).as_deref(), Some(sha.as_str()));
    let _ = std::fs::remove_dir_all(&dir);
  }
}
