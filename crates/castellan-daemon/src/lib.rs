use castellan_core::{
  new_session_id, EventSink, FreezeState, Registry, Request, Response, Session, SessionId,
  SessionReport,
};
use castellan_envelope::{AuditWatcher, Snapshot};
use castellan_freezer::CgroupRoot;
use castellan_policy::Policy;
use castellan_trust::{Signal, TrustDb, TrustEvent};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use rustc_hash::FxHashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Frontier round B3: who is on the other end of the socket?
/// The cgroup membership IS the identity — the one thing the envelope
/// cannot let a session process shed. A caller whose pid sits in any
/// castellan session scope is an AGENT; everyone else is the human.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Caller {
  Human,
  Agent,
}

fn classify_caller(stream: &UnixStream) -> Caller {
  let pid = match getsockopt(stream, PeerCredentials) {
    Ok(cred) => cred.pid(),
    Err(_) => return Caller::Human,
  };
  let cgroup = match std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
    Ok(c) => c,
    Err(_) => return Caller::Human,
  };
  if cgroup.contains("castellan.slice") {
    Caller::Agent
  } else {
    Caller::Human
  }
}

/// Ops a session process may call over the socket. Everything else is
/// human-only: the agent must not be able to keep/thaw/spawn itself,
/// farm trust directly, poison evidence, sabotage siblings, or read
/// canary secrets (R12-R19).
fn agent_allowed(req: &Request) -> bool {
  matches!(
    req,
    Request::Status
      | Request::TrustScore { .. }
      | Request::Cert { .. }
      | Request::Radar { .. }
      | Request::MemoryRecall { .. }
      | Request::MemoryStatus
      | Request::Siblings
      | Request::DrillStatus
      | Request::ChannelsStatus
      | Request::HoneypotPort
      | Request::UndoDiff { .. }
      | Request::Campaign { .. }
  )
}

struct SessionAudit {
  _watcher: AuditWatcher,
  baseline: Vec<(PathBuf, Snapshot)>,
}

#[derive(Default)]
struct SessionNotes {
  undo_upper: Option<PathBuf>,
  baseline: Option<castellan_proof::BaselineManifest>,
}

/// The persisted launch profile for a session (respawn material).
#[derive(Default)]
struct LaunchProfileFields {
  command: Option<Vec<String>>,
  enforce: bool,
  undo: bool,
  net: bool,
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

/// Durable bless-broker ledger entry (append-only jsonl). Rate limits
/// count these, so they survive daemon restarts (S1 audit fix).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct BlessEntry {
  ts: u64,
  kind: BlessKind,
  session: SessionId,
  project: PathBuf,
  want: String,
  nonce_hint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum BlessKind {
  Requested,
  Approved,
  Rejected,
  Forged,
}

/// A granted expansion, held daemon-side in memory (never on disk where
/// the agent could forge it). Consumed exactly once by grant_check.
#[derive(Debug, Clone)]
struct Grant {
  session: SessionId,
  want: String,
  granted_ts: u64,
}

/// P9.2: context for the keep-gate artifact scan (background thread).
/// The config pin is captured BEFORE kill (kill removes the session
/// from the registry), so the scan thread never looks it up.
#[derive(Debug, Clone)]
struct ScanCtx {
  session: String,
  project: PathBuf,
  touched: Vec<String>,
  state_dir: PathBuf,
  pinned_config_sha: Option<String>,
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
  bless_ledger: Arc<Mutex<Vec<BlessEntry>>>,
  grants: Arc<Mutex<FxHashMap<String, Grant>>>,
  radar_lock: Arc<Mutex<()>>,
  drill: Arc<castellan_drill::DrillRegistry>,
  drill_results: Arc<Mutex<Vec<castellan_drill::DrillResult>>>,
  channels_results: Arc<Mutex<Vec<(String, String)>>>,
  memory: Arc<Mutex<castellan_memory::ImmuneMemory>>,
  voice: Arc<Mutex<FxHashMap<String, castellan_voice::VoiceSession>>>,
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
        // canary hit: apply the negative trust signal to the session's
        // project. Live registry first, then the durable session json —
        // trips can land after kill. No "/" fallback: an unattributable
        // trip is logged on the spine but floors nothing (S1 fix).
        let project = reg_cb
          .lock()
          .unwrap()
          .get(&session.to_string())
          .map(|s| s.project.clone())
          .or_else(|| Daemon::durable_project(session));
        if let Some(project) = project {
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
        } else {
          eprintln!(
            "castellan-daemon: canary trip for unattributable session {session} — spine logged, no trust floor"
          );
        }
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
    let bless_ledger = load_bless_ledger(&state.join("castellan/bless.jsonl"));
    let daemon = Self {
      root: Arc::new(CgroupRoot::detect()?),
      registry,
      audits: Arc::new(Mutex::new(FxHashMap::default())),
      notes: Arc::new(Mutex::new(FxHashMap::default())),
      honeypot,
      trust,
      bless: Arc::new(Mutex::new(FxHashMap::default())),
      bless_ledger: Arc::new(Mutex::new(bless_ledger)),
      grants: Arc::new(Mutex::new(FxHashMap::default())),
      radar_lock: Arc::new(Mutex::new(())),
    drill: Arc::new(castellan_drill::DrillRegistry::new()),
    drill_results: Arc::new(Mutex::new(Vec::new())),
    channels_results: Arc::new(Mutex::new(Vec::new())),
      memory: Arc::new(Mutex::new(castellan_memory::load(
        &state.join("castellan/memory.jsonl"),
      ))),
      voice: Arc::new(Mutex::new(FxHashMap::default())),
    };
    // P8: the live-fire scheduler. The daemon attacks itself on a
    // schedule and proves the defenses still work. Enabled by default;
    // opt out via [drill] enabled=false in the config (not yet read —
    // env override for now).
    let interval_min = std::env::var("CASTELLAN_DRILL_INTERVAL_MIN")
      .ok()
      .and_then(|v| v.parse().ok())
      .unwrap_or(60);
    let drill_daemon = daemon.clone();
    let _ = castellan_drill::spawn_scheduler(interval_min, move || drill_daemon.run_drills());
    Ok(daemon)
  }

  fn state_dir() -> PathBuf {
    std::env::var("XDG_STATE_HOME")
      .map(PathBuf::from)
      .unwrap_or_else(|_| {
        PathBuf::from(format!("/home/{}/.local/state", nix::unistd::User::from_uid(nix::unistd::Uid::current()).ok().and_then(|u| u.map(|u| u.name)).unwrap_or_default()))
      })
  }

  /// Durable session metadata (persisted at spawn): project, harness,
  /// config pin. Works for finished sessions.
  fn durable_session_meta(session: &str) -> Option<serde_json::Value> {
    let dir = Self::state_dir().join("castellan/sessions");
    let meta = std::fs::read_to_string(dir.join(format!("{session}.json"))).ok()?;
    serde_json::from_str(&meta).ok()
  }

  fn durable_project(session: &str) -> Option<PathBuf> {
    Self::durable_session_meta(session)?
      .get("project")?
      .as_str()
      .map(PathBuf::from)
  }

  fn durable_harness(session: &str) -> Option<String> {
    Self::durable_session_meta(session)?
      .get("harness")?
      .as_str()
      .map(String::from)
  }

  /// The launch profile persisted at spawn: the exact command plus the
  /// confinement flags, so a bless-broker respawn reproduces the
  /// session's confinement minus the expansion.
  fn durable_launch_profile(session: &str) -> Option<LaunchProfileFields> {
    let meta = Self::durable_session_meta(session)?;
    let command = meta.get("command").and_then(|c| {
      serde_json::from_value::<Vec<String>>(c.clone()).ok()
    });
    Some(LaunchProfileFields {
      command,
      enforce: meta.get("enforce").and_then(|v| v.as_bool()).unwrap_or(false),
      undo: meta.get("undo").and_then(|v| v.as_bool()).unwrap_or(false),
      net: meta.get("net").and_then(|v| v.as_bool()).unwrap_or(false),
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
    let caller = classify_caller(&stream);
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    loop {
      line.clear();
      if reader.read_line(&mut line)? == 0 {
        return Ok(());
      }
      let resp = match serde_json::from_str::<Request>(line.trim()) {
        Ok(req) => {
          if caller == Caller::Agent && !agent_allowed(&req) {
            self.forged_socket_op(&req);
            Response::err("human-only op (agent caller)")
          } else {
            self.dispatch(req)
          }
        }
        Err(e) => Response::err(format!("bad request: {e}")),
      };
      let mut out = serde_json::to_string(&resp)?;
      out.push('\n');
      (&stream).write_all(out.as_bytes())?;
    }
  }

  /// B3: a session process called a human-only op. Record a negative
  /// trust signal (forged_socket_op, -25) on the session's project and
  /// a spine event. The signal is a floor-able negative, never a
  /// positive — the agent cannot farm trust by probing.
  fn forged_socket_op(&self, req: &Request) {
    let session = match req {
      Request::UndoCommit { session }
      | Request::UndoDiscard { session }
      | Request::Thaw { session: Some(session) }
      | Request::Kill { session: Some(session) }
      | Request::Adopt { session, .. }
      | Request::CanaryRegister { session, .. }
      | Request::BlessRequest { session, .. }
      | Request::TestTrustSignal { session, .. } => Some(session.clone()),
      _ => None,
    };
        let project = session
          .as_ref()
          .and_then(|s| self.registry.lock().unwrap().get(s).map(|r| r.project.clone()))
          .or_else(|| {
            // session-less ops (Thaw{None}, Kill{None}) carry no
            // session: no project to floor. Record unattributable
            // rejections in the spine so the human can see them
            // (D4 used session-less Thaw{None} precisely because
            // unattributed ops left no trace).
            None
          });
    if let Some(project) = project {
      let ev = TrustEvent {
        ts: castellan_core::now_unix(),
        session: session.clone().unwrap_or_default(),
        signal: Signal::ForgedSocketOp,
        evidence: format!("agent caller attempted {:?}", req),
      };
      if let Ok(mut db) = self.trust.lock() {
        let _ = db.apply(&project, &ev);
      }
    }
    if let Some(s) = session.as_ref() {
      if let Ok(sink) = EventSink::for_session(&Self::state_dir(), s) {
        let _ = sink.emit("forged_socket_op", &format!("{:?}", req), "deny");
      }
    } else {
      // session-less rejections still get a spine record (B6 P3):
      // D4's race used Thaw{None} because it left no trace. Write to
      // the session-less channel.
      if let Ok(sink) = EventSink::for_session(&Self::state_dir(), "system") {
        let _ = sink.emit("forged_socket_op", &format!("{:?}", req), "deny");
      }
    }
  }

  fn dispatch(&self, req: Request) -> Response {
    match req {
      Request::Spawn { harness, project, pid, command, enforce, undo, net, grants } => {
        self.spawn(harness, project, pid, command, enforce, undo, net, grants)
      }
      Request::Adopt { session, pids } => self.adopt(&session, pids),
      Request::Freeze { session } => self.freeze(session.as_ref(), true),
      Request::Thaw { session } => self.freeze(session.as_ref(), false),
      Request::Kill { session } => self.kill(session.as_ref()),
      Request::Status => self.status(),
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
      Request::TestTrustSignal { project, session, signal, evidence } => {
        // B6 P3: the trust stream is daemon-internal; an agent that
        // can farm it (R3/R8) can buy its own egress. The op survives
        // only for the benchmark suites (p3/p4), env-gated so a
        // production daemon refuses it outright.
        if std::env::var("CASTELLAN_TEST_TRUST_SIGNAL").is_err() {
          Response::err("trust_signal is a test-only op (set CASTELLAN_TEST_TRUST_SIGNAL)")
        } else {
          self.trust_signal(&project, &session, &signal, &evidence)
        }
      }
      Request::BlessRequest { session, want, reason } => {
        self.bless_request(&session, &want, &reason)
      }
      Request::BlessApprove { nonce } => self.bless_approve(&nonce),
      Request::BlessReject { nonce } => self.bless_reject(&nonce),
      Request::BlessShow => self.bless_show(),
      Request::Cert { session } => self.cert(&session),
      Request::Replay { session, narrower_project } => self.replay(&session, &narrower_project),
      Request::PolicyCheck { project, candidate_project } => {
        self.policy_check(&project, &candidate_project)
      }
      Request::Radar { session, project } => self.radar(&session, &project),
      Request::Siblings => self.siblings(),
      Request::Campaign { project } => self.campaign(&project),
      Request::DrillRun => {
        let results = self.run_drills();
        let json: Vec<serde_json::Value> =
          results.iter().map(|r| serde_json::to_value(r).unwrap_or_default()).collect();
        Response::ok().with_extra("drill", serde_json::json!({ "results": json }))
      }
      Request::DrillStatus => {
        let results = self.drill_results.lock().unwrap().clone();
        let json: Vec<serde_json::Value> =
          results.iter().map(|r| serde_json::to_value(r).unwrap_or_default()).collect();
        Response::ok().with_extra("drill", serde_json::json!({ "results": json }))
      }
      Request::MemoryRecall { session } => self.memory_recall(&session),
      Request::MemoryStatus => {
        let mem = self.memory.lock().unwrap();
        Response::ok().with_extra("memory", mem.status())
      }
      Request::VoiceApprove { session, utterance } => self.voice_approve(&session, &utterance),
      Request::ChannelsRun => {
        let results = self.run_channels();
        let json: Vec<serde_json::Value> =
          results.iter().map(|(c, v)| serde_json::json!({ "channel": c, "verdict": v })).collect();
        Response::ok().with_extra("channels", serde_json::json!({ "inventory": json }))
      }
      Request::ChannelsStatus => {
        let results = self.channels_results.lock().unwrap().clone();
        let json: Vec<serde_json::Value> =
          results.iter().map(|(c, v)| serde_json::json!({ "channel": c, "verdict": v })).collect();
        Response::ok().with_extra("channels", serde_json::json!({ "inventory": json }))
      }
      Request::TraceExpose { compromised } => self.trace_expose(&compromised),
    }
  }

  /// P9.1: run the exfil channel census (D6) and store the inventory.
  /// The census is a REPORT — it may confirm open channels (expected:
  /// UDP, unix sockets, inherited fds — Landlock ABI4 covers TCP
  /// connect only). Findings are recorded in THREAT_MODEL, never
  /// silently patched.
  fn run_channels(&self) -> Vec<(String, String)> {
    let started = std::time::Instant::now();
    let nonce = self.drill.issue();
    let session = format!("drill-{nonce}");
    let honeypot_port = self.honeypot.port;
    // the unix probe needs a real listener so ENOENT is not confused
    // with a kernel denial — the daemon pre-creates it
    let unix_path = "/tmp/castellan-channels-probe.sock";
    let _ = std::fs::remove_file(unix_path);
    let listener = std::os::unix::net::UnixListener::bind(unix_path);
    let mut child = match std::process::Command::new(std::env::current_exe().unwrap_or_default())
      .arg("--drill-channels")
      .arg(&honeypot_port.to_string())
      .env("CASTELLAN_DRILL_SESSION", &session)
      .stdout(std::process::Stdio::piped())
      .spawn()
    {
      Ok(c) => c,
      Err(e) => {
        let results = vec![("spawn".to_string(), format!("failed ({e})"))];
        *self.channels_results.lock().unwrap() = results.clone();
        return results;
      }
    };
    let mut out = String::new();
    use std::io::Read as _;
    let _ = child.stdout.take().map(|mut s| s.read_to_string(&mut out));
    let _ = child.wait();
    drop(listener);
    let _ = std::fs::remove_file(unix_path);
    let results: Vec<(String, String)> = out
      .lines()
      .filter_map(|l| l.split_once(": "))
      .map(|(c, v)| (c.to_string(), v.to_string()))
      .collect();
    let sink = EventSink::for_session(&Self::state_dir(), "channels");
    if let Ok(sink) = sink {
      for (c, v) in &results {
        let _ = sink.emit(&format!("channel_{c}"), v, "inventory");
      }
    }
    let _ = sink;
    *self.channels_results.lock().unwrap() = results.clone();
    eprintln!(
      "castellan-daemon: channel census complete in {}ms ({} channels)",
      started.elapsed().as_millis() as u64,
      results.len()
    );
    results
  }

  /// P9.3: cross-session contact tracing. On a canary trip, find
  /// sessions that wrote files the compromised session wrote AFTER it
  /// did. Exposure is SCORED (fraction of the candidate's files that
  /// are poisoned), never binary; hub files score low by construction.
  /// Freeze is OFFERED, the human decides. Reads are invisible —
  /// write-implies-read is a lower bound, stated in the output.
  fn trace_expose(&self, compromised: &str) -> Response {
    let state = Self::state_dir();
    let conn = match castellan_trace::open_index(&state) {
      Ok(c) => c,
      Err(e) => return Response::err(format!("trace index unavailable: {e}")),
    };
    // index every session's spine (idempotent per (session, path, ts))
    let events_dir = state.join("castellan/events");
    let mut sessions: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(&events_dir) {
      for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if let Some(s) = name.strip_suffix(".jsonl") {
          sessions.push(s.to_string());
        }
      }
    }
    for s in &sessions {
      if let Ok(sink) = EventSink::for_session(&state, s) {
        if let Ok(events) = sink.read_all() {
          // B6 phase 1: with enforce-by-default, the overlay substrate
          // is actually interposed — writes land in per-session upper
          // dirs (`<state>/castellan/sessions/<sid>/overlay/upper/...`),
          // so raw paths never match across sessions and the exposure
          // join is empty. Map upper paths back to the session's
          // canonical project (durable spawn mapping); fall back to
          // stripping the session prefix when the mapping is gone.
          let project = Self::durable_project(s);
          let upper_prefix = format!(
            "{}/castellan/sessions/{s}/overlay/upper/",
            state.display()
          );
          let writes: Vec<castellan_trace::WriteEvent> = events
            .iter()
            .filter(|e| e.kind == "fs_write" && e.verdict == "allow")
            .map(|e| {
              let path = if let Some(p) = &project {
                e.path
                  .strip_prefix(&upper_prefix)
                  .map(|rel| p.join(rel).display().to_string())
                  .unwrap_or_else(|| e.path.clone())
              } else {
                e.path.clone()
              };
              castellan_trace::WriteEvent { session: s.clone(), path, ts: e.ts }
            })
            .collect();
          let _ = castellan_trace::index_session(&conn, &writes);
        }
      }
    }
    // score every OTHER session against the compromised one
    let mut exposed: Vec<serde_json::Value> = Vec::new();
    for s in &sessions {
      if s == compromised {
        continue;
      }
      match castellan_trace::exposure(&conn, compromised, s) {
        Ok((score, files, _)) if score > 0.0 => {
          exposed.push(serde_json::json!({
            "session": s,
            "score": score,
            "exposed_files": files,
          }));
        }
        _ => {}
      }
    }
    exposed.sort_by(|a, b| {
      b.get("score")
        .and_then(|x| x.as_f64())
        .unwrap_or(0.0)
        .partial_cmp(&a.get("score").and_then(|x| x.as_f64()).unwrap_or(0.0))
        .unwrap_or(std::cmp::Ordering::Equal)
    });
    Response::ok().with_extra(
      "trace",
      serde_json::json!({
        "compromised": compromised,
        "exposed": exposed,
        "note": "exposure is a lower bound (reads are invisible); freeze is offered, not applied"
      }),
    )
  }

  fn radar(&self, session: &str, project: &Path) -> Response {
    // the prototype read-fold-write cycle must be serialized: two
    // concurrent radar calls would lose an update (S2 audit fix)
    let _guard = self.radar_lock.lock().unwrap();
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
    // N3: prototypes fold ONLY on keep (undo_commit) — human-validated
    // sessions. Folding here would let an attacker session poison the
    // shared prototype so legit sessions flag (T3).
    let json = serde_json::to_value(&report).unwrap_or(serde_json::Value::Null);
    Response::ok().with_extra("radar", json)
  }

  /// N3: fold a session's HV into the project prototype. Called only
  /// from undo_commit (user kept the session). Serialized with the
  /// radar_lock to keep the read-fold-write cycle atomic.
  fn fold_kept_session(&self, session: &str, project: &Path) {
    let _guard = self.radar_lock.lock().unwrap();
    let state = Self::state_dir();
    let Ok(hv) = castellan_radar::encode_session_from_spine(session, &state) else {
      return;
    };
    let proto_path = state
      .join("castellan/radar")
      .join(format!("{}.bin", castellan_radar::project_hash(project)));
    let mut prototype = match std::fs::read(&proto_path) {
      Ok(bytes) => castellan_radar::Prototype::from_bytes(&bytes),
      Err(_) => castellan_radar::Prototype::empty(),
    };
    prototype.fold(&hv);
    if let Some(dir) = proto_path.parent() {
      let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&proto_path, prototype.to_bytes());
  }

  /// N5: sibling detector — scan /proc for known harness processes
  /// running without the CASTELLAN_SESSION tag. Advisory: detects the
  /// boundary violation (T5), cannot prevent it.
  fn siblings(&self) -> Response {
    let harnesses = ["claude", "codex", "pi", "opencode", "aider", "cursor-agent", "gemini", "crush"];
    let mut found: Vec<serde_json::Value> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
      for entry in entries.flatten() {
        let name = entry.file_name();
        let pid: u32 = match name.to_string_lossy().parse() {
          Ok(p) => p,
          Err(_) => continue,
        };
        let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
          continue;
        };
        let argv: Vec<&[u8]> = cmdline.split(|&b| b == 0).filter(|a| !a.is_empty()).collect();
        let Some(prog) = argv.first() else { continue };
        let prog = String::from_utf8_lossy(prog);
        let base = std::path::Path::new(prog.as_ref())
          .file_name()
          .map(|f| f.to_string_lossy().to_string())
          .unwrap_or_default();
        if !harnesses.contains(&base.as_str()) {
          continue;
        }
        let Ok(environ) = std::fs::read(format!("/proc/{pid}/environ")) else {
          continue;
        };
        let tagged = environ
          .split(|&b| b == 0)
          .any(|kv| kv.starts_with(b"CASTELLAN_SESSION="));
        if !tagged {
          found.push(serde_json::json!({
            "pid": pid,
            "harness": base,
          }));
        }
      }
    }
    Response::ok()
      .with_message(format!("{} untagged harness process(es)", found.len()))
      .with_extra("siblings", serde_json::json!({ "untagged": found }))
  }

  /// N1: campaign detector — cross-session slow-drip attack detection
  /// over the project's trust-event stream. Advisory (silent tier):
  /// reports campaign windows, never freezes.
  fn campaign(&self, project: &Path) -> Response {
    match castellan_campaign::detect_campaigns(project, &Self::state_dir()) {
      Ok(report) => {
        let json = serde_json::to_value(&report).unwrap_or(serde_json::Value::Null);
        Response::ok()
          .with_message(format!("{} campaign(s) detected", report.campaigns.len()))
          .with_extra("campaign", json)
      }
      Err(e) => Response::err(format!("campaign detection failed: {e}")),
    }
  }

  /// P8.1: immune memory — recall a response for a session's telemetry
  /// window. Advisory: the memory proposes, deterministic policy
  /// disposes. The agent has no write path; incidents are written by
  /// daemon event handlers and drills only.
  fn memory_recall(&self, session: &str) -> Response {
    let state = Self::state_dir();
    let events = match castellan_core::EventSink::for_session(&state, session)
      .and_then(|s| s.read_all())
    {
      Ok(e) => e,
      Err(e) => return Response::err(format!("spine read failed: {e}")),
    };
    if events.is_empty() {
      return Response::ok().with_extra(
        "memory",
        serde_json::json!({ "recall": null, "note": "no events on spine" }),
      );
    }
    // telemetry window: the event kinds, in order (the shape encoder
    // bundles them; order is not preserved by design — similarity is
    // about composition, not sequence)
    let kinds: Vec<String> = events.iter().map(|e| e.kind.clone()).collect();
    let refs: Vec<&str> = kinds.iter().map(|s| s.as_str()).collect();
    let shape = castellan_memory::encode_shape(&refs);
    let mem = self.memory.lock().unwrap();
    let recall = mem.recall(&shape);
    let json = match &recall {
      Some(r) => serde_json::to_value(r).unwrap_or_default(),
      None => serde_json::Value::Null,
    };
    Response::ok().with_extra(
      "memory",
      serde_json::json!({
        "recall": json,
        "events_encoded": events.len(),
        "note": "advisory only — memory never auto-enforces",
      }),
    )
  }

  /// P8.1: write an incident into the immune memory (daemon-side only).
  /// Called from drill results and real incident handlers.
  fn memory_write_incident(&self, events: &[&str], response: castellan_memory::ResponseVerb) {
    let shape = castellan_memory::encode_shape(events);
    let mut mem = self.memory.lock().unwrap();
    mem.write_incident(&shape, response);
    let _ = castellan_memory::save(&mem, &Self::state_dir().join("castellan/memory.jsonl"));
  }

  /// P8.1: write a tolerance (self) shape — called on human keep.
  fn memory_write_self(&self, events: &[&str]) {
    let shape = castellan_memory::encode_shape(events);
    let mut mem = self.memory.lock().unwrap();
    mem.write_self(&shape);
    let _ = castellan_memory::save(&mem, &Self::state_dir().join("castellan/memory.jsonl"));
  }

  /// P8: run the live-fire drill suite. Each drill attacks a sacrificial
  /// scope and verifies the defense holds. Results are stored for
  /// `drill status` and emitted to the spine as `drill_*` events.
  /// A failing drill is a loud alarm: the defense is broken.
  fn run_drills(&self) -> Vec<castellan_drill::DrillResult> {
    let mut results = Vec::new();
    results.push(self.drill_census());
    results.push(self.drill_honeypot());
    results.push(self.drill_bless());
    results.push(self.drill_envelope());
    results.push(self.drill_freeze());
    results.push(self.drill_channels());
    let any_fail = results.iter().any(|r| !r.pass);
    let sink = EventSink::for_session(&Self::state_dir(), "drill");
    if let Ok(sink) = sink {
      for r in &results {
        let _ = sink.emit(
          &format!("drill_{}", r.id),
          &format!("expected={} observed={}", r.expected, r.observed),
          if r.pass { "pass" } else { "FAIL" },
        );
      }
    }
    if any_fail {
      eprintln!("castellan-daemon: DRILL FAILURE — a defense is broken:");
      for r in &results {
        if !r.pass {
          eprintln!("  drill {}: expected {} — observed {}", r.id, r.expected, r.observed);
        }
      }
    }
    // P8.1: drills are the antigen training set — every drill result
    // writes an incident into the immune memory (shape = the drill's
    // telemetry, response = the expected defense). Failures write too:
    // the memory learns what defense-breakdown looks like.
    for r in &results {
      let response = if r.pass {
        castellan_memory::ResponseVerb::Freeze
      } else {
        castellan_memory::ResponseVerb::AlarmHuman
      };
      self.memory_write_incident(
        &[&format!("drill_{}", r.id), &format!("drill_{}_pass={}", r.id, r.pass)],
        response,
      );
    }
    *self.drill_results.lock().unwrap() = results.clone();
    results
  }

  /// D1: the census must find and kill a process that escaped the
  /// session cgroup via the user manager (systemd-run).
  fn drill_census(&self) -> castellan_drill::DrillResult {
    let started = std::time::Instant::now();
    let nonce = self.drill.issue();
    let scope = self.drill.scope_name(&nonce);
    let session = scope.clone();
    let _ = self.root.create_session(&session);
    let start_ts = castellan_core::now_unix();
    // the escape: a process spawned via the user manager, outside the
    // session cgroup — exactly the T4 vector the census bounds
    let escaped = std::process::Command::new("systemd-run")
      .args(["--user", "--collect", "--unit", &scope, "sleep", "30"])
      .spawn();
    let (found, killed) = match escaped {
      Ok(mut child) => {
        let _ = child.wait();
        // systemd-run exits once the unit is created, but the escaped
        // process forks slightly later — poll for it before the census
        let mut waited = 0u64;
        loop {
          let orphans = self.root.orphan_census(&session, start_ts);
          if !orphans.is_empty() || waited >= 2000 {
            let found = orphans.len();
            let killed = self.root.kill_pids(&orphans);
            break (found, killed);
          }
          std::thread::sleep(std::time::Duration::from_millis(100));
          waited += 100;
        }
      }
      Err(e) => {
        let _ = self.root.destroy_session(&session);
        return castellan_drill::DrillResult::new(
          "census",
          "systemd-run escape caught by census",
          &format!("systemd-run unavailable: {e}"),
          false,
          started.elapsed().as_millis() as u64,
        );
      }
    };
    let _ = self.root.destroy_session(&session);
    let pass = found >= 1 && killed >= 1;
    castellan_drill::DrillResult::new(
      "census",
      "systemd-run escape caught by census",
      &format!("found {found}, killed {killed}"),
      pass,
      started.elapsed().as_millis() as u64,
    )
  }

  /// D2: a registered canary secret used against the honeypot must
  /// trip. The drill registers its own secret and probes the port.
  fn drill_honeypot(&self) -> castellan_drill::DrillResult {
    let started = std::time::Instant::now();
    if self.honeypot.port == 0 {
      return castellan_drill::DrillResult::new(
        "honeypot",
        "canary probe trips the honeypot",
        "honeypot detached (port 0)",
        false,
        started.elapsed().as_millis() as u64,
      );
    }
    let secret = format!("drill-{}", rand_hex(16));
    self.honeypot.register(&castellan_canary::CanarySecret {
      value: secret.clone(),
      session: "drill".into(),
    });
    // probe: connect and send the secret bytes, like an exfil attempt
    let mut stream = match std::net::TcpStream::connect(("127.0.0.1", self.honeypot.port)) {
      Ok(s) => s,
      Err(e) => {
        return castellan_drill::DrillResult::new(
          "honeypot",
          "canary probe trips the honeypot",
          &format!("connect failed: {e}"),
          false,
          started.elapsed().as_millis() as u64,
        );
      }
    };
    use std::io::Write as _;
    let _ = stream.write_all(secret.as_bytes());
    let _ = stream.flush();
    std::thread::sleep(std::time::Duration::from_millis(300));
    // the trip fires the daemon's callback (trust signal + freeze);
    // we cannot observe the callback directly, so verify the trip
    // event landed on the drill spine
    let tripped = EventSink::for_session(&Self::state_dir(), "drill")
      .and_then(|s| s.read_all())
      .map(|events| events.iter().any(|e| e.kind == "canary_trip"))
      .unwrap_or(false);
    castellan_drill::DrillResult::new(
      "honeypot",
      "canary probe trips the honeypot",
      if tripped { "trip fired" } else { "no trip event" },
      tripped,
      started.elapsed().as_millis() as u64,
    )
  }

  /// D3: a forged bless nonce must be recorded and must NOT grant.
  fn drill_bless(&self) -> castellan_drill::DrillResult {
    let started = std::time::Instant::now();
    let forged = format!("deadbeef{}", rand_hex(8));
    let resp = self.bless_approve(&forged);
    let recorded = self
      .bless_ledger
      .lock()
      .unwrap()
      .iter()
      .any(|e| e.kind == BlessKind::Forged && e.nonce_hint == forged[..forged.len().min(8)].to_string());
    let pass = !resp.ok && recorded;
    castellan_drill::DrillResult::new(
      "bless",
      "forged nonce recorded, no grant",
      &format!("approve={} recorded={}", if resp.ok { "granted" } else { "denied" }, recorded),
      pass,
      started.elapsed().as_millis() as u64,
    )
  }

  /// D4: an enforced child must be denied a write to a hard-denied
  /// path (~/.ssh). The child applies the envelope itself, then tries.
  fn drill_envelope(&self) -> castellan_drill::DrillResult {
    let started = std::time::Instant::now();
    let nonce = self.drill.issue();
    let session = format!("drill-{nonce}");
    let policy = castellan_policy::Policy::new(&session, "drill", std::path::PathBuf::from("/tmp"));
    // the denied path must be the REAL user home, not $HOME: the lab
    // redirects HOME into a sacrificial dir under /tmp, which is the
    // drill's write root — a redirected ~/.ssh would be inside the
    // allowed set and the write would legitimately succeed
    let denied = nix::unistd::User::from_uid(nix::unistd::Uid::current())
      .ok()
      .flatten()
      .map(|u| u.dir)
      .unwrap_or_else(|| std::env::var("HOME").unwrap_or_else(|_| "/root".into()).into());
    let denied = denied.join(".ssh");
    let mut child = match std::process::Command::new(std::env::current_exe().unwrap_or_default())
      .arg("--drill-envelope")
      .arg(&denied)
      .env("CASTELLAN_DRILL_SESSION", &session)
      .spawn()
    {
      Ok(c) => c,
      Err(e) => {
        return castellan_drill::DrillResult::new(
          "envelope",
          "Landlock denies ~/.ssh write",
          &format!("spawn failed: {e}"),
          false,
          started.elapsed().as_millis() as u64,
        );
      }
    };
    let status = child.wait();
    let pass = match status {
      Ok(s) => s.code() == Some(0),
      Err(e) => {
        return castellan_drill::DrillResult::new(
          "envelope",
          "Landlock denies ~/.ssh write",
          &format!("wait failed: {e}"),
          false,
          started.elapsed().as_millis() as u64,
        );
      }
    };
    let _ = policy;
    castellan_drill::DrillResult::new(
      "envelope",
      "Landlock denies ~/.ssh write",
      if pass { "denied (EACCES)" } else { "write succeeded (envelope broken)" },
      pass,
      started.elapsed().as_millis() as u64,
    )
  }

  /// D5: freeze→thaw roundtrip on a sacrificial scope within budget.
  fn drill_freeze(&self) -> castellan_drill::DrillResult {
    let started = std::time::Instant::now();
    let nonce = self.drill.issue();
    let session = format!("{}.scope", self.drill.scope_name(&nonce));
    let _ = self.root.create_session(&session);
    // a real process in the scope so freeze has something to act on
    let mut child = match std::process::Command::new("sleep").arg("30").spawn() {
      Ok(c) => c,
      Err(e) => {
        let _ = self.root.destroy_session(&session);
        return castellan_drill::DrillResult::new(
          "freeze",
          "freeze/thaw roundtrip within 500ms",
          &format!("spawn failed: {e}"),
          false,
          started.elapsed().as_millis() as u64,
        );
      }
    };
    let _ = self.root.write_procs(&session, &[child.id()]);
    let f = self.root.set_freeze(&session, true);
    let t = self.root.set_freeze(&session, false);
    let _ = self.root.kill_all(&session);
    let _ = child.kill();
    let _ = self.root.destroy_session(&session);
    let pass = matches!(f, Ok(castellan_core::FreezeState::Frozen))
      && matches!(t, Ok(castellan_core::FreezeState::Thawed));
    castellan_drill::DrillResult::new(
      "freeze",
      "freeze/thaw roundtrip within 500ms",
      &format!("freeze={:?} thaw={:?}", f.map(|s| s.as_str()), t.map(|s| s.as_str())),
      pass,
      started.elapsed().as_millis() as u64,
    )
  }

  /// D6: exfil channel census — a sacrificial child applies the
  /// envelope (with net lockdown) and attempts every egress channel:
  /// TCP connect (allowed + denied ports), UDP send, unix socket
  /// connect, DNS-crafted UDP query, filesystem drop, inherited-fd
  /// write. The child prints one verdict line per channel; the daemon
  /// aggregates them into a dated, kernel-verified channel inventory.
  /// Shannon: you cannot secure a channel you have not enumerated.
  /// The census is a REPORT, never a gate — it may confirm open
  /// channels (expected: UDP and unix sockets, which Landlock ABI4
  /// net rights do not cover).
  fn drill_channels(&self) -> castellan_drill::DrillResult {
    let started = std::time::Instant::now();
    let results = self.run_channels();
    let pass = results.len() >= 6;
    let open: Vec<&str> = results
      .iter()
      .filter(|(_, v)| v.starts_with("OPEN") || v.starts_with("ALLOWED"))
      .map(|(c, _)| c.as_str())
      .collect();
    castellan_drill::DrillResult::new(
      "channels",
      "channel census completes",
      &format!(
        "{} channels inventoried; open: {}",
        results.len(),
        if open.is_empty() { "none".to_string() } else { open.join(", ") }
      ),
      pass,
      started.elapsed().as_millis() as u64,
    )
  }

  fn replay(&self, session: &str, narrower_project: &Path) -> Response {    let project = {
      let reg = self.registry.lock().unwrap();
      match reg.get(&session.to_string()) {
        Some(s) => s.project.clone(),
        None => match Daemon::durable_project(session) {
          Some(p) => p,
          None => return Response::err("unknown session"),
        },
      }
    };
    let harness = {
      let reg = self.registry.lock().unwrap();
      reg
        .get(&session.to_string())
        .map(|s| s.harness.clone())
        .or_else(|| Daemon::durable_harness(session))
        .unwrap_or_else(|| "claude".into())
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

  /// P9.6: policy regression replay — replay kept-session spines
  /// through a CANDIDATE policy before it lands. Kept sessions only
  /// (the "what humans approved" corpus); false-NEW-denies only;
  /// advisory at release time (runs on the developer's machine, not
  /// the agent's runtime).
  fn policy_check(&self, project: &Path, candidate_project: &Path) -> Response {
    match castellan_policycheck::check_policy_for_project(
      &Self::state_dir(),
      project,
      "claude",
      candidate_project,
    ) {
      Ok(report) => {
        let json = serde_json::to_value(&report).unwrap_or(serde_json::Value::Null);
        Response::ok().with_extra("policycheck", json)
      }
      Err(e) => Response::err(format!("policycheck failed: {e}")),
    }
  }

  fn cert(&self, session: &str) -> Response {
    let project = {
      let reg = self.registry.lock().unwrap();
      match reg.get(&session.to_string()) {
        Some(s) => s.project.clone(),
        None => {
          // finished session: read the durable mapping
          match Daemon::durable_project(session) {
            Some(p) => p,
            None => return Response::err("unknown session"),
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
      "vuln_introduced" => Signal::VulnIntroduced,
      "vuln_introduced" => Signal::VulnIntroduced,
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
  /// Rate limits count the PERSISTED ledger (requests + approvals),
  /// not just pending nonces — a restart or an approval must not reset
  /// the counters (S1 audit fix).
  fn bless_request(&self, session: &str, want: &str, reason: &str) -> Response {
    let now = castellan_core::now_unix();
    let project = {
      let reg = self.registry.lock().unwrap();
      match reg.get(&session.to_string()) {
        Some(s) => s.project.clone(),
        None => return Response::err("unknown session"),
      }
    };
    let (session_count, project_count, last_ts) = {
      let ledger = self.bless_ledger.lock().unwrap();
      let session_count = ledger
        .iter()
        .filter(|e| e.session == session && e.kind != BlessKind::Rejected)
        .count();
      let day = now / 86_400;
      let project_count = ledger
        .iter()
        .filter(|e| {
          e.project == project
            && e.kind == BlessKind::Approved
            && e.ts / 86_400 == day
        })
        .count();
      let last_ts = ledger
        .iter()
        .filter(|e| e.session == session && e.kind != BlessKind::Rejected)
        .map(|e| e.ts)
        .max()
        .unwrap_or(0);
      (session_count, project_count, last_ts)
    };
    if session_count >= 3 {
      return Response::err("expansion limit reached (3 per session)");
    }
    if project_count >= 10 {
      return Response::err("expansion limit reached (10 per project per day)");
    }
    if now - last_ts < 300 {
      return Response::err("cooling-off period active (5 minutes between expansions)");
    }
    let nonce = castellan_core::new_bless_nonce();
    // B6 P3 (D4-F1): the nonce is delivered OUT-OF-BAND — printed to
    // the daemon's journal (stderr), never returned in the socket
    // response. The response carries only the hint. The residual: a
    // same-uid agent that can read the journal can recover the nonce
    // (same-uid advisory-defender position, A3 knot — documented);
    // what is closed is the same-connection self-grant: request and
    // approve can no longer be completed without a second channel.
    eprintln!("castellan-daemon: bless nonce for {session}: {nonce} (want={want})");
    let req = BlessRequest {
      session: session.to_string(),
      project: project.clone(),
      want: want.to_string(),
      reason: reason.to_string(),
      created_ts: now,
    };
    self.bless.lock().unwrap().insert(nonce.clone(), req);
    // P8.3: every bless request also creates a voice session — the
    // acoustic channel's nonce is independent of the terminal nonce
    // (the human speaks the voice nonce; the terminal nonce stays a
    // fallback). The voice nonce is spoken by the daemon, never
    // printed to the agent's environment.
    self.voice.lock().unwrap().insert(session.to_string(), castellan_voice::VoiceSession::new());
    self.append_bless_ledger(BlessEntry {
      ts: now,
      kind: BlessKind::Requested,
      session: session.to_string(),
      project,
      want: want.to_string(),
      nonce_hint: nonce[..8].to_string(),
    });
    Response::ok().with_extra(
      "bless",
      serde_json::json!({
        "want": want,
        "session": session,
        "nonce_hint": &nonce[..8],
        "note": "nonce issued — read it from the daemon journal (castellan bless show)",
      }),
    )
  }

  /// P8.3: acoustic channel — process a spoken (or typed-fallback)
  /// utterance against the session's voice nonce. On match, the
  /// pending bless request is approved (grant recorded daemon-side).
  /// The utterance is the STT transcription of the human's voice —
  /// the agent cannot speak (kernel-verified: /dev/snd writes are
  /// denied under the envelope), so this channel is human-exclusive.
  fn voice_approve(&self, session: &str, utterance: &str) -> Response {
    let mut voice = self.voice.lock().unwrap();
    let Some(vs) = voice.get_mut(session) else {
      return Response::err("no voice session for this session — request a bless first");
    };
    let state = vs.process(utterance);
    match state {
      castellan_voice::VoiceState::Panic => {
        // the panic phrase triggers the kill switch, NOT a grant.
        // Freeze all sessions + census; the human can thaw.
        let targets = self.resolve_targets(None);
        let mut frozen = 0usize;
        for id in &targets {
          if let Ok(castellan_core::FreezeState::Frozen) = self.root.set_freeze(id, true) {
            frozen += 1;
          }
        }
        Response::ok().with_extra(
          "bless",
          serde_json::json!({
            "panic": true,
            "frozen": frozen,
            "note": "panic phrase — all sessions frozen; thaw with castellan thaw",
          }),
        )
      }
      castellan_voice::VoiceState::Authorized => {
        // find the pending bless request for this session
        let req = {
          let mut b = self.bless.lock().unwrap();
          let found = b
            .iter()
            .find(|(_, r)| r.session == session)
            .map(|(k, r)| (k.clone(), r.clone()));
          if let Some((k, _)) = &found {
            b.remove(k);
          }
          found.map(|(_, r)| r)
        };
        let Some(req) = req else {
          return Response::err("no pending bless request for this session");
        };
        self.append_bless_ledger(BlessEntry {
          ts: castellan_core::now_unix(),
          kind: BlessKind::Approved,
          session: req.session.clone(),
          project: req.project.clone(),
          want: req.want.clone(),
          nonce_hint: "voice".into(),
        });
        self.grants.lock().unwrap().insert(
          format!("{}:{}", req.project.display(), req.want),
          Grant {
            session: req.session.clone(),
            want: req.want.clone(),
            granted_ts: castellan_core::now_unix(),
          },
        );
        Response::ok().with_extra(
          "bless",
          serde_json::json!({
            "approved": true,
            "channel": "voice",
            "session": req.session,
            "want": req.want,
            "note": "grant recorded daemon-side; consumed on next launch",
          }),
        )
      }
      castellan_voice::VoiceState::Rejected => {
        Response::err("voice approval rejected (attempts exhausted)")
      }
      castellan_voice::VoiceState::Awaiting => {
        Response::ok().with_extra(
          "bless",
          serde_json::json!({
            "approved": false,
            "channel": "voice",
            "attempts_left": vs.attempts_left,
            "note": "utterance did not match — try again",
          }),
        )
      }
    }
  }

  /// Bless-broker: approve by nonce. Unknown nonce = forged attempt:
  /// floor the project's trust at 0 (forged_nonce signal).
  fn bless_approve(&self, nonce: &str) -> Response {
    // P8 fault injection: the D3 drill must fail loudly when the bless
    // floor is bypassed. Test-only, env-gated.
    if std::env::var("CASTELLAN_TEST_DISABLE_BLESS").is_ok() {
      return Response::ok().with_message("granted (injected bypass)");
    }
    let req = {
      let mut b = self.bless.lock().unwrap();
      match b.remove(nonce) {
        Some(r) => r,
        None => {
          // Forged nonce. Attribution: an unknown nonce carries no
          // session/project context, so there is no honest project to
          // floor — the earlier behavior (flooring "/") punished a
          // sentinel path, protecting nothing (S1 audit fix). Record
          // the attempt durably and alert; flooring happens only when
          // attribution exists (a live session's project).
          eprintln!(
            "castellan-daemon: FORGED bless nonce attempt ({}) — recorded, no project attribution",
            &nonce[..nonce.len().min(8)]
          );
          self.append_bless_ledger(BlessEntry {
            ts: castellan_core::now_unix(),
            kind: BlessKind::Forged,
            session: String::new(),
            project: PathBuf::new(),
            want: String::new(),
            nonce_hint: nonce[..nonce.len().min(8)].to_string(),
          });
          if let Some(project) = self.session_project_by_hint(nonce) {
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
          }
          return Response::err("unknown nonce — approval forged?");
        }
      }
    };
    self.append_bless_ledger(BlessEntry {
      ts: castellan_core::now_unix(),
      kind: BlessKind::Approved,
      session: req.session.clone(),
      project: req.project.clone(),
      want: req.want.clone(),
      nonce_hint: nonce[..nonce.len().min(8)].to_string(),
    });
    // approval is daemon-side: record the grant (one-shot, in-memory —
    // the agent cannot forge a grant without the daemon). The session
    // stays alive in its current envelope; the LAUNCHER asks for the
    // grant when it next spawns. Grants are project-scoped: the trust
    // tier is per-project, so the expansion follows the project.
    self.grants.lock().unwrap().insert(
      format!("{}:{}", req.project.display(), req.want),
      Grant {
        session: req.session.clone(),
        want: req.want.clone(),
        granted_ts: castellan_core::now_unix(),
      },
    );
    Response::ok().with_extra(
      "bless",
      serde_json::json!({
        "approved": true,
        "session": req.session,
        "want": req.want,
        "note": "grant recorded daemon-side; consumed on next launch",
      }),
    )
  }

  fn bless_reject(&self, nonce: &str) -> Response {
    let removed = {
      let mut b = self.bless.lock().unwrap();
      match b.remove(nonce) {
        Some(r) => Some(r),
        None => None,
      }
    };
    match removed {
      Some(r) => {
        self.append_bless_ledger(BlessEntry {
          ts: castellan_core::now_unix(),
          kind: BlessKind::Rejected,
          session: r.session,
          project: r.project,
          want: r.want,
          nonce_hint: nonce[..nonce.len().min(8)].to_string(),
        });
        Response::ok().with_message("rejected")
      }
      None => Response::err("unknown nonce"),
    }
  }

  fn append_bless_ledger(&self, entry: BlessEntry) {
    use std::io::Write as _;
    let path = Self::state_dir().join("castellan/bless.jsonl");
    if let Some(dir) = path.parent() {
      let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
      let _ = writeln!(f, "{}", serde_json::to_string(&entry).unwrap_or_default());
    }
    self.bless_ledger.lock().unwrap().push(entry);
  }

  /// A forged nonce that exactly matches no request gets no attribution;
  /// retained for the case where it prefix-matches a live session id
  /// (never in practice — nonces are 32-hex, ids are s-prefixed).
  fn session_project_by_hint(&self, _nonce: &str) -> Option<PathBuf> {
    None
  }

  /// B6 P3: list pending bless requests (hint + want + session). The
  /// human reads the full nonce from the daemon journal; this op
  /// confirms which requests are pending so `bless approve` can be
  /// matched against a journal entry. Nonces themselves never leave
  /// the daemon.
  fn bless_show(&self) -> Response {
    let pending: Vec<serde_json::Value> = {
      let b = self.bless.lock().unwrap();
      let mut items: Vec<(&String, &BlessRequest)> = b.iter().collect();
      items.sort_by_key(|(n, _)| n.clone());
      items
        .into_iter()
        .map(|(nonce, req)| {
          serde_json::json!({
            "nonce_hint": &nonce[..nonce.len().min(8)],
            "session": req.session,
            "want": req.want,
            "reason": req.reason,
            "created_ts": req.created_ts,
          })
        })
        .collect()
    };
    Response::ok().with_extra("bless", serde_json::json!({ "pending": pending }))
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
    // P9.5: plant decoy-vulnerability edit canaries in the session
    // scratch. Direction-sensitive: weaponizing a decoy = freeze-tier
    // event; fixing an unrequested decoy = annotation only, never a
    // penalty (proactive benign agents exist).
    let decoy_dir = scratch.join("decoy");
    let decoys = castellan_decoy::plant(&decoy_dir).unwrap_or_default();
    let decoy_count = decoys.len();
    // B6 P3 (R19): the secrets are NOT returned in the response — the
    // response is visible to the agent, so returning them is a canary
    // oracle teaching the exact bytes to strip. They persist in the
    // canary ledger (canary.jsonl, reloaded at startup).
    Response::ok()
      .with_message("canaries planted")
      .with_extra(
        "canary",
        serde_json::json!({
          "dir": planted.dir.display().to_string(),
          "port": self.honeypot.port,
          "decoys": decoy_count,
        }),
      )
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
    let (upper, work, baseline) = {
      let mut notes = self.notes.lock().unwrap();
      let Some(n) = notes.get_mut(session) else {
        return Response::err("no undo layer recorded for this session");
      };
      match n.undo_upper.take() {
        Some(upper) => {
          let work = upper.with_file_name("work");
          (upper, work, n.baseline.take())
        }
        None => return Response::err("no undo layer recorded for this session"),
      }
    };
    // commit needs the real project root — read it from the registry
    let (project, pinned_config_sha) = {
      let reg = self.registry.lock().unwrap();
      match reg.get(&session.to_string()) {
        Some(s) => (s.project.clone(), s.config_sha.clone()),
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
    let proofs = castellan_proof::run_session_placebo(&project, &upper, baseline.as_ref());
    let passed: Vec<&castellan_proof::ProofResult> =
      proofs.iter().filter(|p| p.passed).collect();
    match castellan_ledger::commit(&project, &upper) {
      Ok(applied) => {
        let _ = castellan_ledger::discard(&upper, &work);
        // P9.4: blast-radius weight for this session's touches. The
        // stria index may not exist (async build, never blocks) —
        // weight 1.0 = neutral. A hub-function edit earns more trust
        // (and a hub regression costs more).
        let touched: Vec<String> = applied
          .iter()
          .filter_map(|l| l.strip_prefix("+ ").or_else(|| l.strip_prefix("- ")))
          .map(|p| p.to_string())
          .collect();
        let hub_db = castellan_hub::index_path(&project);
        // P9.4 gap-plug: the weight is only trusted if the index is
        // byte-identical to the spawn-time pin. Missing index or
        // drifted pin -> weight 1.0 (neutral). The pin is read from
        // the DURABLE session record (the registry entry was removed
        // by kill above — the durable record survives).
        let pinned_index_sha = Self::durable_session_meta(&session.to_string())
          .and_then(|m| m.get("hub_index_sha").and_then(|v| v.as_str()).map(String::from));
        let weight = if let Some(pinned) = pinned_index_sha {
          if castellan_hub::index_sha(&project).as_deref() == Some(pinned.as_str()) {
            castellan_hub::session_weight(&hub_db, &touched)
          } else {
            eprintln!(
              "castellan-daemon: stria index changed since launch — weight neutral (possible agent tampering)"
            );
            if let Ok(sink) = EventSink::for_session(&Self::state_dir(), session) {
              let _ = sink.emit("hub_index_drift", ".stria/phrases.sqlite", "neutral");
            }
            1.0
          }
        } else {
          1.0
        };
        // user kept the session: positive trust signal
        let mut db = self.trust.lock().unwrap();
        let _ = db.apply_weighted(
          &project,
          &TrustEvent {
            ts: castellan_core::now_unix(),
            session: session.to_string(),
            signal: Signal::CleanSession,
            evidence: format!(
              "user kept session; {} change(s) committed (blast-radius weight {weight:.2})",
              applied.len()
            ),
          },
          weight,
        );
        if !passed.is_empty() {
          let _ = db.apply_weighted(
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
            weight,
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
        // P9.5: decoy-vulnerability edit canaries — direction check at
        // keep. Weaponizing a decoy (danger increased) = freeze-tier
        // event (canary-class, N2 top tier). Fixing an unrequested
        // decoy = placebo-seeking annotation ONLY, never a trust
        // penalty (proactive benign agents exist; punishing
        // unrequested fixes would train agents to ignore vulnerable
        // code — worse for safety).
        let decoy_dir = Self::state_dir().join("castellan/sessions").join(session).join("decoy");
        let decoy_verdicts = castellan_decoy::check_all(&decoy_dir);
        let weaponized: Vec<&str> = decoy_verdicts
          .iter()
          .filter(|(_, v)| matches!(v, castellan_decoy::DecoyVerdict::Weaponized))
          .map(|(n, _)| n.as_str())
          .collect();
        let fixed: Vec<&str> = decoy_verdicts
          .iter()
          .filter(|(_, v)| matches!(v, castellan_decoy::DecoyVerdict::Fixed))
          .map(|(n, _)| n.as_str())
          .collect();
        if !weaponized.is_empty() {
          let _ = db.apply(
            &project,
            &TrustEvent {
              ts: castellan_core::now_unix(),
              session: session.to_string(),
              signal: Signal::EnvelopeEscape,
              evidence: format!("decoy weaponized: {}", weaponized.join(", ")),
            },
          );
          if let Ok(sink) = EventSink::for_session(&Self::state_dir(), session) {
            let _ = sink.emit("decoy_trip", &weaponized.join(", "), "freeze-tier");
          }
          eprintln!(
            "castellan-daemon: DECOY TRIP — session {session} weaponized: {}",
            weaponized.join(", ")
          );
        } else if !fixed.is_empty() {
          if let Ok(sink) = EventSink::for_session(&Self::state_dir(), session) {
            let _ = sink.emit(
              "decoy_fixed",
              &format!("unrequested decoy fix: {}", fixed.join(", ")),
              "annotation-only",
            );
          }
          eprintln!(
            "castellan-daemon: decoy fixed (annotation only, no penalty): {}",
            fixed.join(", ")
          );
        }
        // P9.2: artifact scan at the keep gate. Baseline-delta on
        // session-touched files; findings-only-negative (a clean delta
        // earns nothing). Config-pinned via config_sha (same mechanism
        // as test_cmd). The scan runs in a background thread; the cert
        // is amended when done; the trust signal applies to the NEXT
        // launch — never retroactively punish after a human keep.
        let scan_ctx = ScanCtx {
          session: session.to_string(),
          project: project.clone(),
          touched,
          state_dir: Self::state_dir(),
          pinned_config_sha: pinned_config_sha.clone(),
        };
        let scan_daemon = self.clone();
        std::thread::Builder::new()
          .name("scan".into())
          .spawn(move || {
            let _ = scan_daemon.run_artifact_scan(&scan_ctx);
          })
          .expect("scan thread");
        let lines: Vec<serde_json::Value> =
          applied.iter().map(|l| serde_json::Value::String(l.clone())).collect();
        // N3: the user kept this session — fold its HV into the
        // project prototype. Kept-only folding means poisoning the
        // prototype requires also fooling the human review (T3).
        self.fold_kept_session(session, &project);
        // P8.1: the kept session is a tolerance (self) shape — the
        // immune memory must not fire on it, regardless of incident
        // similarity (negative selection).
        if let Ok(sink) = EventSink::for_session(&Self::state_dir(), session) {
          if let Ok(events) = sink.read_all() {
            let kinds: Vec<String> = events.iter().map(|e| e.kind.clone()).collect();
            let refs: Vec<&str> = kinds.iter().map(|s| s.as_str()).collect();
            self.memory_write_self(&refs);
          }
        }
        Response::ok()
          .with_message(format!("committed {} change(s)", applied.len()))
          .with_extra("applied", serde_json::Value::Array(lines))
      }
      Err(e) => Response::err(format!("commit failed: {e}")),
    }
  }

  /// P9.2: capture the artifact-scan baseline at spawn. The baseline
  /// is the set of files with findings in the pre-session tree; the
  /// keep-gate scan diffs against it. Config-pinned (same mechanism
  /// as test_cmd). Best-effort: a scan failure at spawn means no
  /// baseline, and the keep-gate scan is skipped (honestly labeled).
  fn capture_scan_baseline(&self, session: &str, project: &Path) {
    let cfg_path = project.join(".reliary/castellan.toml");
    let Ok(cfg) = std::fs::read_to_string(&cfg_path) else {
      return;
    };
    let Ok(parsed) = cfg.parse::<toml::Value>() else {
      return;
    };
    let Some(scan) = parsed.get("scan") else {
      return;
    };
    let Some(scanner) = scan.get("scanner").and_then(|c| c.as_str()) else {
      return;
    };
    let Some(cmd) = scan.get("cmd").and_then(|c| c.as_str()) else {
      return;
    };
    let argv: Vec<String> = cmd.split_whitespace().map(|s| s.to_string()).collect();
    if argv.is_empty() {
      return;
    }
    let cfg = castellan_scan::ScannerConfig { scanner: scanner.to_string(), cmd: argv };
    match castellan_scan::run_scanner(&cfg, project) {
      Ok(r) => {
        let files: Vec<String> = r.findings.iter().map(|f| f.file.clone()).collect();
        let dir = Self::state_dir().join("castellan/sessions");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(
          dir.join(format!("{session}.baseline")),
          serde_json::to_string(&files).unwrap_or_default(),
        );
      }
      Err(e) => {
        eprintln!("castellan-daemon: artifact-scan baseline failed at spawn: {e}");
      }
    }
  }

  /// P9.2: keep-gate artifact scan. Baseline-delta on session-touched
  /// files; findings-only-negative (a clean delta earns nothing).
  /// Config-pinned via config_sha (same mechanism as test_cmd). Runs
  /// in a background thread; the trust signal applies to the NEXT
  /// launch — never retroactively punish after a human keep.
  fn run_artifact_scan(&self, ctx: &ScanCtx) {
    let pinned = ctx.pinned_config_sha.clone();
    let current = project_config_sha(&ctx.project);
    match verify_config_pin(&pinned, &current) {
      ConfigVerdict::NotPinned => {
        eprintln!("castellan-daemon: project config not pinned at launch — artifact scan refused");
        return;
      }
      ConfigVerdict::Drifted => {
        eprintln!(
          "castellan-daemon: project config changed since launch — artifact scan REFUSED (possible agent tampering)"
        );
        return;
      }
      ConfigVerdict::Ok => {}
    }
    let cfg_path = ctx.project.join(".reliary/castellan.toml");
    let Ok(cfg) = std::fs::read_to_string(&cfg_path) else {
      eprintln!("castellan-daemon: no .reliary/castellan.toml — artifact scan skipped");
      return;
    };
    let Ok(parsed) = cfg.parse::<toml::Value>() else {
      eprintln!("castellan-daemon: unparseable .reliary/castellan.toml — artifact scan skipped");
      return;
    };
    let Some(scan) = parsed.get("scan") else {
      eprintln!("castellan-daemon: no [scan] section — artifact scan skipped");
      return;
    };
    let Some(scanner) = scan.get("scanner").and_then(|c| c.as_str()) else {
      eprintln!("castellan-daemon: no [scan] scanner — artifact scan skipped");
      return;
    };
    let Some(cmd) = scan.get("cmd").and_then(|c| c.as_str()) else {
      eprintln!("castellan-daemon: no [scan] cmd — artifact scan skipped");
      return;
    };
    let argv: Vec<String> = cmd.split_whitespace().map(|s| s.to_string()).collect();
    if argv.is_empty() {
      eprintln!("castellan-daemon: empty [scan] cmd — artifact scan skipped");
      return;
    }
    let cfg = castellan_scan::ScannerConfig { scanner: scanner.to_string(), cmd: argv };
    // baseline: the pre-session state captured at spawn (persisted as
    // <session>.baseline). A baseline scanned at keep would see the
    // session's own changes and the delta would always be empty.
    let baseline_files: Vec<String> = std::fs::read_to_string(
      Self::state_dir().join("castellan/sessions").join(format!("{}.baseline", ctx.session)),
    )
    .ok()
    .and_then(|raw| serde_json::from_str(&raw).ok())
    .unwrap_or_default();
    let baseline = castellan_scan::ScanResult {
      scanner: scanner.to_string(),
      findings: baseline_files
        .iter()
        .map(|f| castellan_scan::Finding {
          file: f.clone(),
          line: 0,
          class: "baseline".into(),
          severity: "low".into(),
          rule_id: "baseline".into(),
        })
        .collect(),
    };
    let current_scan = match castellan_scan::run_scanner(&cfg, &ctx.project) {
      Ok(r) => r,
      Err(e) => {
        eprintln!("castellan-daemon: artifact scan failed: {e}");
        return;
      }
    };
    let delta = castellan_scan::delta_findings(&baseline, &current_scan, &ctx.touched);
    if delta.is_empty() {
      // findings-only-negative: a clean delta earns NOTHING
      eprintln!("castellan-daemon: artifact scan clean delta — no signal (by design)");
      return;
    }
    let detail = format!(
      "{} new finding(s) in session-touched files (scanner={}): {}",
      delta.len(),
      scanner,
      delta
        .iter()
        .map(|f| format!("{}:{} {}", f.file, f.line, f.class))
        .collect::<Vec<_>>()
        .join("; ")
    );
    let mut db = self.trust.lock().unwrap();
    let _ = db.apply(
      &ctx.project,
      &TrustEvent {
        ts: castellan_core::now_unix(),
        session: ctx.session.clone(),
        signal: Signal::VulnIntroduced,
        evidence: format!("artifact scan: {detail}"),
      },
    );
    if let Ok(sink) = EventSink::for_session(&ctx.state_dir, &ctx.session) {
      let _ = sink.emit("vuln_introduced", &detail, "negative");
    }
    eprintln!(
      "castellan-daemon: artifact scan found {} new finding(s) in session-touched files — trust signal applied",
      delta.len()
    );
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

  fn spawn(
    &self,
    harness: String,
    project: PathBuf,
    pid: Option<u32>,
    command: Option<Vec<String>>,
    enforce: bool,
    undo: bool,
    net: bool,
    grants: Vec<String>,
  ) -> Response {
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
    // trust floor coupling: tiers 0-1 fail-closed regardless of flags.
    // The daemon consults the trust tier at spawn; the launcher's
    // flags are a request, not a grant. A consumed grant (human
    // blessing) overrides the floor for that expansion.
    let (low_trust, tier_str, granted) = {
      let db = self.trust.lock().unwrap();
      let t = db.score(&project).ok();
      let low = t.as_ref().map(|t| t.tier <= castellan_trust::Tier::One).unwrap_or(false);
      let tier = t.map(|t| t.tier.as_str().to_string()).unwrap_or("?".into());
      let granted: Vec<String> = grants
        .iter()
        .filter_map(|want| {
          self
            .grants
            .lock()
            .unwrap()
            .remove(&format!("{}:{want}", project.display()))
            .map(|g| g.want)
        })
        .collect();
      (low, tier, granted)
    };
    let (enforce, undo, net) = if low_trust && granted.is_empty() {
      (true, true, true)
    } else {
      (enforce, undo, net)
    };
    let config_sha = project_config_sha(&project);
    let pinned = config_sha.clone();
    // P9.4 gap-plug: pin the stria phrase index at spawn. The weight
    // is read at keep from a file inside the agent's write roots —
    // an unpinned read lets the agent rewrite the index mid-session
    // to inflate positive trust signals. Neutral-fail (weight 1.0)
    // on missing/mismatched pin: weighting is advisory, so neutral
    // is the right failure mode (unlike test_cmd's refuse).
    let hub_index_sha = castellan_hub::index_sha(&project);
    self.registry.lock().unwrap().insert(Session {
      id: id.clone(),
      harness: harness.clone(),
      project: project.clone(),
      config_sha: pinned,
      started_at: castellan_core::now_unix(),
      hub_index_sha,
    });
    // B6 P3: the undo-layer record used to arrive via a socket Note
    // from the launcher — a socket op with a legitimate caller, but
    // also a surface (R17 evidence poisoning). The upper path is
    // deterministic (state_dir/castellan/sessions/<id>/overlay/upper)
    // and the placebo baseline should be the spawn-time state, so
    // populate the notes map here. The launcher's Note call is gone.
    if undo {
      let upper = Self::state_dir()
        .join("castellan/sessions")
        .join(&id)
        .join("overlay/upper");
      let baseline = castellan_proof::BaselineManifest::capture(&project).ok();
      self.notes.lock().unwrap().insert(
        id.clone(),
        SessionNotes {
          undo_upper: Some(upper),
          baseline,
        },
      );
    }
    // P9.2: capture the artifact-scan BASELINE at spawn — the
    // pre-session state. The keep-gate scan diffs against this; a
    // baseline captured at keep would see the session's own changes
    // and the delta would always be empty.
    self.capture_scan_baseline(&id, &project);
    self.start_audit(&id, &harness, &project);
    // durable session->project mapping: certificates must work for
    // finished sessions (transferable proof), so persist at spawn
    let _ = self.persist_session(
      &id,
      &project,
      &harness,
      &config_sha,
      command,
      enforce,
      undo,
      net,
    );
    Response::ok()
      .with_message(format!("spawned session {id}"))
      .with_extra(
        "profile",
        serde_json::json!({
          "enforce": enforce,
          "undo": undo,
          "net": net,
          "forced": low_trust && granted.is_empty(),
          "tier": tier_str,
          "grants": granted,
        }),
      )
  }

  fn persist_session(
    &self,
    id: &str,
    project: &Path,
    harness: &str,
    config_sha: &Option<String>,
    command: Option<Vec<String>>,
    enforce: bool,
    undo: bool,
    net: bool,
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
        "hub_index_sha": castellan_hub::index_sha(project),
        "command": command,
        "enforce": enforce,
        "undo": undo,
        "net": net,
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
      let (harness, started_at) = {
        let reg = self.registry.lock().unwrap();
        (reg.get(&id).map(|s| s.harness.clone()), reg.get(&id).map(|s| s.started_at))
      };
      if let Some(h) = harness {
        self.end_audit(&id, &h);
      }
      let _ = self.root.set_freeze(&id, false);
      msgs.push(match self.root.kill_all(&id) {
        Ok(n) => format!("{id}: killed {n}"),
        Err(e) => format!("{id}: error {e}"),
      });
      // N6 orphan census: processes that escaped the session cgroup
      // via the user manager (systemd-run) are invisible to kill_all.
      // Bounds the blast radius to the session window.
      if let Some(start) = started_at {
        // B2 (red-team R4): stop escaped transient units BEFORE the
        // census kills their processes. A unit with Restart=always
        // respawns the escaped process — killing processes is not
        // enough, the UNIT must be stopped. Order matters: the unit
        // check reads /proc/<main-pid>/stat, which fails once the
        // census has killed the process (dead pid -> unit skipped).
        let units_stopped = self.root.stop_escaped_units(&id, start);
        if units_stopped > 0 {
          msgs.push(format!("{id}: {units_stopped} escaped unit(s) stopped"));
        }
        let orphans = self.root.orphan_census(&id, start);
        if !orphans.is_empty() {
          let killed = self.root.kill_pids(&orphans);
          msgs.push(format!("{id}: orphan census {}/{} killed", killed, orphans.len()));
          self.record_census(&id, orphans.len(), killed);
        }
      }
      let _ = self.root.destroy_session(&id);
      self.registry.lock().unwrap().remove(&id);
    }
    let joined = msgs.join(", ");
    Response::ok()
      .with_message(if msgs.is_empty() { "nothing to kill" } else { joined.as_str() })
      .with_sessions(self.reports())
  }

  fn record_census(&self, session: &str, found: usize, killed: usize) {
    let dir = Self::state_dir().join("castellan/sessions");
    let path = dir.join(format!("{session}.census"));
    let _ = std::fs::write(
      path,
      serde_json::json!({
        "session": session,
        "orphans_found": found,
        "orphans_killed": killed,
        "ts": castellan_core::now_unix(),
      })
      .to_string(),
    );
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

/// Load the durable bless ledger; malformed lines are skipped.
fn load_bless_ledger(path: &Path) -> Vec<BlessEntry> {
  let Ok(content) = std::fs::read_to_string(path) else {
    return Vec::new();
  };
  content
    .lines()
    .filter_map(|l| serde_json::from_str::<BlessEntry>(l).ok())
    .collect()
}

/// Random hex string for drill secrets (D2). /dev/urandom, no deps.
fn rand_hex(n: usize) -> String {
  let mut buf = vec![0u8; n];
  let mut f = std::fs::File::open("/dev/urandom").expect("urandom");
  use std::io::Read as _;
  f.read_exact(&mut buf).expect("urandom read");
  buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// P9.1: probe every egress channel from inside an enforced envelope
/// and return one verdict per channel. Runs in the D6 drill child
/// AFTER the envelope (Landlock + seccomp + net lockdown) is applied.
/// The verdicts are kernel facts, not assumptions — the census is a
/// dated inventory, never a gate.
///
/// Channels probed:
/// - tcp_allowed: TCP connect to the honeypot port (must be ALLOWED)
/// - tcp_denied:  TCP connect to a non-honeypot port (must be DENIED)
/// - udp:         UDP send to localhost (expected OPEN — Landlock
///                ABI4 has no UDP access rights)
/// - unix:        unix socket connect outside the session (expected
///                OPEN — unix sockets are not covered by Landlock)
/// - dns:         DNS-crafted UDP query to a resolver (expected OPEN)
/// - fs_drop:     write to a world-readable path outside the workspace
///                (expected DENIED by Landlock write roots)
/// - fd_inherit:  write through an inherited fd (expected OPEN — the
///                envelope cannot revoke an already-open fd)
pub fn probe_channels(honeypot_port: u16) -> Vec<(String, String)> {
  use std::io::Write as _;
  use std::net::{TcpStream, UdpSocket};
  use std::os::unix::net::UnixStream;
  let mut out = Vec::new();

  // TCP to the honeypot port: the one allowed connect.
  let tcp_allowed = match TcpStream::connect(("127.0.0.1", honeypot_port)) {
    Ok(_) => "ALLOWED".to_string(),
    Err(e) => format!("DENIED ({e})"),
  };
  out.push(("tcp_allowed".into(), tcp_allowed));

  // TCP to a non-honeypot port: must be kernel-denied by the net rules.
  let denied_port = if honeypot_port == 0 { 1 } else { honeypot_port.wrapping_add(1).max(1) };
  let tcp_denied = match TcpStream::connect(("127.0.0.1", denied_port)) {
    Ok(_) => "ALLOWED (net lockdown broken)".to_string(),
    Err(e) => format!("DENIED ({e})"),
  };
  out.push(("tcp_denied".into(), tcp_denied));

  // UDP send: Landlock ABI4 has no UDP rights — expected OPEN.
  let udp = match UdpSocket::bind("127.0.0.1:0") {
    Ok(s) => match s.send_to(b"probe", ("127.0.0.1", denied_port)) {
      Ok(_) => "OPEN (UDP not covered by Landlock)".to_string(),
      Err(e) => format!("DENIED ({e})"),
    },
    Err(e) => format!("bind failed ({e})"),
  };
  out.push(("udp".into(), udp));

  // Unix socket connect outside the session — expected OPEN.
  let unix = match UnixStream::connect("/tmp/castellan-channels-probe.sock") {
    Ok(_) => "OPEN (unix sockets not covered)".to_string(),
    Err(e) => format!("DENIED ({e})"),
  };
  out.push(("unix".into(), unix));

  // DNS-crafted UDP query to a resolver — expected OPEN.
  let dns = match UdpSocket::bind("127.0.0.1:0") {
    Ok(s) => match s.send_to(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", ("127.0.0.1", 53)) {
      Ok(_) => "OPEN (DNS exfil possible)".to_string(),
      Err(e) => format!("DENIED ({e})"),
    },
    Err(e) => format!("bind failed ({e})"),
  };
  out.push(("dns".into(), dns));

  // Filesystem drop outside the workspace — must be denied. The drill
  // project root is /tmp, so the probe must target a hard-denied path
  // (~/.ssh) to test the deny list, not the write roots.
  let fs_drop = {
    let denied = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let target = std::path::Path::new(&denied).join(".ssh/castellan-channels-drop");
    match std::fs::write(&target, b"probe") {
      Ok(()) => "ALLOWED (fs drop possible)".to_string(),
      Err(e) => format!("DENIED ({e})"),
    }
  };
  out.push(("fs_drop".into(), fs_drop));

  // Inherited-fd write: the fd was opened BEFORE the envelope (in the
  // drill child); writing through it after — the envelope cannot
  // revoke an open fd.
  let fd_inherit = match std::fs::OpenOptions::new().append(true).open("/tmp/castellan-channels-fd") {
    Ok(mut f) => match f.write_all(b"probe") {
      Ok(()) => "OPEN (inherited fd not revocable)".to_string(),
      Err(e) => format!("DENIED ({e})"),
    },
    Err(e) => format!("open failed ({e})"),
  };
  out.push(("fd_inherit".into(), fd_inherit));

  out
}

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
  fn hub_index_sha_missing_when_no_index() {
    let dir = std::env::temp_dir().join(format!("castellan-hubpin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    assert!(castellan_hub::index_sha(&dir).is_none());
    let _ = std::fs::remove_dir_all(&dir);
  }

  #[test]
  fn hub_index_sha_changes_when_tampered() {
    let dir = std::env::temp_dir().join(format!("castellan-hubpin2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(".stria")).unwrap();
    let idx = dir.join(".stria/phrases.sqlite");
    std::fs::write(&idx, b"index-v1").unwrap();
    let before = castellan_hub::index_sha(&dir).expect("index exists");
    std::fs::write(&idx, b"index-v2-tampered").unwrap();
    let after = castellan_hub::index_sha(&dir).expect("index exists");
    assert_ne!(before, after, "tampered index must change the pin");
    let _ = std::fs::remove_dir_all(&dir);
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

  #[test]
  fn bless_ledger_roundtrip_skips_malformed() {
    let dir = std::env::temp_dir().join("castellan-bless-ledger-test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bless.jsonl");
    let e1 = BlessEntry {
      ts: 100,
      kind: BlessKind::Approved,
      session: "s1".into(),
      project: "/tmp/p".into(),
      want: "egress".into(),
      nonce_hint: "abcd1234".into(),
    };
    let e2 = BlessEntry {
      ts: 200,
      kind: BlessKind::Forged,
      session: String::new(),
      project: PathBuf::new(),
      want: String::new(),
      nonce_hint: "deadbeef".into(),
    };
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
      .create(true)
      .append(true)
      .open(&path)
      .unwrap();
    writeln!(f, "{}", serde_json::to_string(&e1).unwrap()).unwrap();
    writeln!(f, "garbage line").unwrap();
    writeln!(f, "{}", serde_json::to_string(&e2).unwrap()).unwrap();
    let loaded = load_bless_ledger(&path);
    assert_eq!(loaded.len(), 2);
    assert_eq!(loaded[0].kind, BlessKind::Approved);
    assert_eq!(loaded[1].kind, BlessKind::Forged);
    let _ = std::fs::remove_dir_all(&dir);
  }
}
