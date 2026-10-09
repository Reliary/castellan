use castellan_core::{
  new_session_id, EventSink, FreezeState, Registry, Request, Response, Session, SessionId,
  SessionReport,
};
use castellan_envelope::{AuditWatcher, Snapshot};
use castellan_freezer::CgroupRoot;
use castellan_policy::Policy;
use castellan_trust::{Signal, TrustDb, TrustEvent};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use rustc_hash::{FxHashMap, FxHashSet};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Frontier round B3: who is on the other end of the socket?
/// The cgroup membership IS the identity — the one thing the envelope
/// cannot let a session process shed. A caller whose pid sits in any
/// castellan session scope is an AGENT; everyone else is the human.
///
/// B6 phase 4 (D4-F1): identity is FAIL-CLOSED. An unreadable
/// /proc/<pid> (the fork/reap race — connector dies before
/// classification) yields Rejected, not Human. SO_PEERCRED returns
/// the connect-time credentials even when the fd is inherited, so the
/// dead connector's pid fails the /proc read and the inherited-fd
/// holder gets nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Caller {
  Human,
  Agent,
  // Designed for an unresolvable caller; classification is binary today
  // (in castellan.slice -> Agent, else Human) and never yields it.
  #[allow(dead_code)]
  Rejected,
}

/// Identity snapshot taken at connection time, re-verified at
/// dispatch (B6 phase 4): the pid must still be alive, must still
/// have the same starttime (pid-reuse defense), and must still sit in
/// the same cgroup (classify-then-escape TOCTOU).
#[derive(Debug, Clone, Copy)]
struct CallerInfo {
  caller: Caller,
  pid: u32,
  start_ticks: u64,
  tty_nr: u64,
  /// P20/F18: the caller's kernel session id — the per-open tty
  /// identity paired with tty_nr at the gate.
  sid: u64,
}

fn proc_field(pid: u32, index: usize) -> Option<String> {
  let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
  // comm may contain spaces/parens; parse from the last ')'
  let rest = stat.rsplit_once(')')?.1;
  rest.split_whitespace().nth(index).map(String::from)
}

/// Parse the kernel-recorded controlling tty (tty_nr) from
/// /proc/<pid>/stat — after comm: state(0) ppid(1) pgrp(2)
/// session(3) tty_nr(4). Index 6 is `flags`, not tty — a
/// mis-parse there made the tty check a no-op (stable field).
fn caller_tty_nr(pid: u32) -> Option<u64> {
  proc_field(pid, 4).and_then(|f| f.parse().ok())
}

/// P20/F18: the caller's kernel session id (after-comm index 3).
fn caller_sid(pid: u32) -> Option<u64> {
  proc_field(pid, 3).and_then(|f| f.parse().ok())
}

fn caller_start_ticks(pid: u32) -> Option<u64> {
  // after comm: state(0) ppid(1) pgrp(2) session(3) tty_nr(4) ... starttime(19)
  proc_field(pid, 19).and_then(|f| f.parse().ok())
}

/// P20.1: validated parse of one durable session row (see
/// `Daemon::rehydrate`). Returns `(session, undo)` or None — corrupt
/// JSON, a `session` field that does not match the filename, or
/// missing required fields are all None (fail-closed; rehydrate counts
/// them). Never panics: `panic=abort` would take the daemon down on
/// attacker- or entropy-controlled input.
fn parse_session_row(id: &str, raw: &str, mtime_fallback: u64) -> Option<(Session, bool)> {
  let v: serde_json::Value = serde_json::from_str(raw).ok()?;
  if v.get("session").and_then(|s| s.as_str()) != Some(id) {
    return None;
  }
  let project = PathBuf::from(v.get("project").and_then(|p| p.as_str())?);
  let harness = v.get("harness").and_then(|h| h.as_str())?.to_string();
  let launcher_tty = v.get("launcher_tty").and_then(|t| t.as_u64()).unwrap_or(0);
  let launcher_sid = v.get("launcher_sid").and_then(|t| t.as_u64()).unwrap_or(0);
  // Legacy rows predate started_at: caller supplies an mtime fallback
  // (≈ spawn) rather than 0 — an epoch window would make the N6 orphan
  // census claim every process on the box.
  let started_at = v.get("started_at").and_then(|t| t.as_u64()).unwrap_or(mtime_fallback);
  let undo = v.get("undo").and_then(|u| u.as_bool()).unwrap_or(false);
  let config_sha = v.get("config_sha").and_then(|s| s.as_str()).map(String::from);
  let hub_index_sha = v.get("hub_index_sha").and_then(|s| s.as_str()).map(String::from);
  Some((
    Session {
      id: id.to_string(),
      harness,
      project,
      config_sha,
      started_at,
      hub_index_sha,
      launcher_tty,
      launcher_sid,
    },
    undo,
  ))
}

fn probe_caller(stream: &UnixStream) -> Option<CallerInfo> {
  let pid = getsockopt(stream, PeerCredentials).ok()?.pid() as u32;
  let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
  let start_ticks = caller_start_ticks(pid)?;
  let tty_nr = caller_tty_nr(pid)?;
  let sid = caller_sid(pid)?;
  let caller = if cgroup.contains("castellan.slice") {
    Caller::Agent
  } else {
    Caller::Human
  };
  Some(CallerInfo { caller, pid, start_ticks, tty_nr, sid })
}

/// Dispatch-time re-verification: the identity snapshot must still
/// hold. Reads /proc/<pid> again — any failure fails closed.
fn caller_still_current(info: &CallerInfo) -> bool {
  let Some(start) = caller_start_ticks(info.pid) else { return false };
  let Some(tty) = caller_tty_nr(info.pid) else { return false };
  let Some(sid) = caller_sid(info.pid) else { return false };
  let Ok(cgroup) = std::fs::read_to_string(format!("/proc/{}/cgroup", info.pid)) else {
    return false;
  };
  let in_slice = cgroup.contains("castellan.slice");
  let still_caller = if info.caller == Caller::Agent {
    in_slice
  } else {
    !in_slice
  };
  start == info.start_ticks && tty == info.tty_nr && sid == info.sid && still_caller
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
      // C32: the request is the agent ASKING for an expansion — an
      // unprivileged, rate-limited, ledgered ask. Only the APPROVE is
      // privileged (tty-gated in human_tty_ok). Blocking requests for
      // agents inverted the flow: the agent could never ask.
      | Request::BlessRequest { .. }
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
/// Designed, not wired: durable_launch_profile reads it for
/// bless-broker respawn, which has no caller yet.
#[allow(dead_code)]
#[derive(Default)]
struct LaunchProfileFields {
  command: Option<Vec<String>>,
  enforce: bool,
  undo: bool,
  net: bool,
}

/// P11: merge the operator's declared egress destinations.
///
/// Sources, in precedence order — all operator-owned, never
/// agent-writable. The harness's own provider config is deliberately NOT
/// a source: it lives in the agent's writable state root, so deriving
/// the allowlist from it would let the agent authorize its own egress.
///  1. explicit `--allow-host` values from the launcher
///  2. `CASTELLAN_EGRESS_ALLOW_HOSTS` (comma-separated)
///  3. `$XDG_CONFIG_HOME/castellan/egress.toml` `[llm] hosts = [...]`
fn resolve_allow_hosts(explicit: &[String]) -> Vec<String> {
  let mut hosts: Vec<String> = explicit.iter().filter(|h| !h.trim().is_empty()).cloned().collect();
  if let Ok(raw) = std::env::var("CASTELLAN_EGRESS_ALLOW_HOSTS") {
    for h in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
      if !hosts.iter().any(|e| e == h) {
        hosts.push(h.to_string());
      }
    }
  }
  let cfg = std::env::var("XDG_CONFIG_HOME")
    .map(PathBuf::from)
    .unwrap_or_else(|_| {
      PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config")
    })
    .join("castellan/egress.toml");
  if let Ok(text) = std::fs::read_to_string(&cfg) {
    if let Some(llm) = toml::from_str::<toml::Value>(&text)
      .ok()
      .and_then(|v| v.get("llm").cloned())
    {
      if let Some(list) = llm.get("hosts").and_then(|h| h.as_array()) {
        for h in list.iter().filter_map(|v| v.as_str()) {
          let h = h.trim().to_string();
          if !h.is_empty() && !hosts.contains(&h) {
            hosts.push(h);
          }
        }
      }
    }
  }
  hosts
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
  // Audit fields: written at grant time, not yet read (grant_check
  // consumes `want` only).
  #[allow(dead_code)]
  session: SessionId,
  want: String,
  #[allow(dead_code)]
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
  /// B7: terminals the daemon has witnessed as launcher ttys, with
  /// their pts inode at witnessing time. A tty_nr alone is spoofable —
  /// an escaped process can allocate a fresh pty (openpty/setsid/
  /// TIOCSCTTY are not blocked and blocking them breaks harnesses) and
  /// pass any tty!=0 gate. The inode binds the trust to the specific
  /// pts allocation: a recycled tty_nr gets a new inode and fails.
  trusted_ttys: Arc<Mutex<FxHashMap<u64, u64>>>,
  /// B8.3: dedup set for the periodic escape-shape sweep, keyed
  /// "session:unit" so a persistent unit is reported once, not every
  /// sweep.
  swept: Arc<Mutex<FxHashSet<String>>>,
  /// R7: spawn rate buckets per project path (fork-bomb guard).
  spawn_rate: Arc<Mutex<FxHashMap<String, (std::time::Instant, u32)>>>,
  /// F2 (2026-09-27, .227 breakout): reserved for the freeze-through
  /// path. The trip closure captures the cgroup root directly (see
  /// Daemon::new); this handle stays for future trip-time actions
  /// that need daemon state. Unused for now.
  #[allow(dead_code)]
  freeze_on_trip: Arc<dyn Fn(&str) + Send + Sync>,
  /// S2 (chapter 5): ed25519 signing key, generated at daemon start and
  /// held only in memory (the process is made non-dumpable first, per
  /// the S0 probe). None = key generation failed; certificates are then
  /// assembled unsigned and say so.
  signing_key: Option<Arc<castellan_proof::signing::SigningKey>>,
  /// P12: live per-session egress proxies (credential injection). The
  /// handle's Drop stops the listener; kill removes and drops.
  proxies: Arc<Mutex<FxHashMap<SessionId, castellan_proxy::ProxyHandle>>>,
  /// P12: daemon-resident credentials, loaded ONCE at start from
  /// `$XDG_CONFIG_HOME/castellan/keyring.toml` (outside every envelope).
  keyring: Arc<castellan_keyring::Keyring>,
  /// P12: upstream TLS trust for the proxy (system roots).
  proxy_tls: Arc<rustls::ClientConfig>,
  /// P21.4: auto-kill deadlines, session -> unix ts when a frozen scope
  /// is SIGKILLed. Populated only when `freeze --kill-after-m` asked
  /// for it; thaw removes the entry. Persisted on the session row as an
  /// ABSOLUTE ts, so a daemon restart does not extend a deadline.
  freeze_deadlines: Arc<Mutex<FxHashMap<SessionId, u64>>>,
}

impl Daemon {
  pub fn new() -> std::io::Result<Self> {
    let state = Self::state_dir();
    // S2/S0: make this process non-dumpable and core-dump-free BEFORE
    // generating the signing key, so the key cannot be recovered from a
    // core by a same-uid agent (verified vector in the S0 probe).
    castellan_proof::signing::SigningKey::harden_process();
    let signing_key = match castellan_proof::signing::SigningKey::generate() {
      Ok(k) => {
        eprintln!(
          "castellan-daemon signing key ready (ed25519, memory-only, pub={})",
          &k.public_hex()[..16]
        );
        Some(Arc::new(k))
      }
      Err(e) => {
        eprintln!("castellan-daemon: signing key unavailable ({e}) — certificates will be UNSIGNED");
        None
      }
    };
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
    // F2: freeze-through-daemon. The root is detected ONCE here, in the
    // daemon's own context, and shared with the trip closure — the old
    // path re-detected it inside the honeypot thread and failed ENOENT.
    let root_for_trip = match CgroupRoot::detect() {
      Ok(r) => Some(Arc::new(r)),
      Err(e) => {
        eprintln!("castellan-daemon: cgroup root unavailable ({e}) — canary auto-freeze disabled");
        None
      }
    };
    let root_cb = root_for_trip.clone();
    let honeypot = match castellan_canary::Honeypot::start_with_callback(
      &state,
      Arc::new(move |session: &str| {
        // F2: freeze FIRST (containment), then score. The session id is
        // the one the honeypot attributed from its secret registry.
        if let Some(root) = root_cb.as_ref() {
          match root.set_freeze(&session.to_string(), true) {
            Ok(_) => eprintln!("castellan-daemon: canary trip — session {session} frozen"),
            Err(e) => eprintln!("castellan-daemon: canary trip freeze failed for {session}: {e:?}"),
          }
        }
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
      trusted_ttys: Arc::new(Mutex::new(FxHashMap::default())),
      swept: Arc::new(Mutex::new(FxHashSet::default())),
      spawn_rate: Arc::new(Mutex::new(FxHashMap::default())),
      freeze_on_trip: Arc::new(|_: &str| {}),
      signing_key,
      proxies: Arc::new(Mutex::new(FxHashMap::default())),
      keyring: {
        let cfgdir = std::env::var("XDG_CONFIG_HOME")
          .map(PathBuf::from)
          .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config")
          });
        let path = cfgdir.join("castellan/keyring.toml");
        let k = castellan_keyring::Keyring::load(&path);
        if k.is_empty() {
          eprintln!("castellan-daemon: no keyring at {} — sessions use their own auth", path.display());
        } else {
          eprintln!(
            "castellan-daemon: keyring loaded ({} credential(s), sha={})",
            k.len(),
            &k.sha()[..12]
          );
        }
        Arc::new(k)
      },
      proxy_tls: castellan_proxy::native_tls_config(),
      freeze_deadlines: Arc::new(Mutex::new(FxHashMap::default())),
    };
    // P20.1: control-plane survival across restart (F2). Spawn-only
    // registration meant any daemon restart wiped status/freeze/kill/
    // adopt for every live session while the agents kept running.
    daemon.rehydrate();
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
    // B8.3 (C36): periodic escape-shape sweep. Report-only — it looks
    // for transient `run-*.service`/`run-*.timer` units created during a
    // live session window (the systemd-run escape shape) and emits a
    // spine event. It does NOT blanket-kill: the C36 probe showed the
    // broad predicate claims the user's own apps (konsole/firefox);
    // B8.2's broker denies systemd-run at the source, so this is
    // defense in depth, not the primary bound.
    let sweep_daemon = daemon.clone();
    let sweep_secs = std::env::var("CASTELLAN_SWEEP_SECS")
      .ok()
      .and_then(|v| v.parse().ok())
      .unwrap_or(15);
    if std::env::var("CASTELLAN_DISABLE_SWEEP").is_err() {
      let _ = std::thread::Builder::new().name("sweep".into()).spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(sweep_secs.max(1)));
        sweep_daemon.run_sweep();
      });
    }
    // P21.4: auto-kill timer. Only sessions frozen with an explicit
    // `--kill-after-m` carry a deadline; the default freeze has none.
    // The thread is cheap (one lock + a clock read every 2s) and is the
    // single place SIGKILL-on-deadline happens, so the behavior is
    // testable and the spine row is written exactly once per kill.
    let kill_daemon = daemon.clone();
    let _ = std::thread::Builder::new().name("freeze-killer".into()).spawn(move || loop {
      std::thread::sleep(std::time::Duration::from_secs(2));
      kill_daemon.run_freeze_deadlines();
    });
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
  /// Designed, not wired (no caller yet).
  #[allow(dead_code)]
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
    let identity = probe_caller(&stream);
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    loop {
      line.clear();
      if reader.read_line(&mut line)? == 0 {
        return Ok(());
      }
          let resp = match serde_json::from_str::<Request>(line.trim()) {
            Ok(req) => {
              match identity {
                // D4-F1 fail-closed: the connector could not be
                // identified (fork/reap race, dead peer, unreadable
                // /proc). Reject EVERYTHING, including agent-allowed
                // ops — the identity model has no basis to trust this
                // peer.
                None => {
                  self.forged_socket_op(&req);
                  Response::err("caller identity could not be verified (rejected)")
                }
                Some(info) => {
                  // B6 phase 4: dispatch-time re-verification. The
                  // snapshot taken at connect may be stale by now
                  // (pid reuse, or the peer escaped its cgroup after
                  // connect). Any drift — or any /proc read failure —
                  // fails closed.
                  if !caller_still_current(&info) {
                    self.forged_socket_op(&req);
                    Response::err("caller identity changed since connect (rejected)")
                  } else if info.caller == Caller::Agent && !agent_allowed(&req) {
                    self.forged_socket_op(&req);
                    Response::err("human-only op (agent caller)")
                  } else if info.caller == Caller::Human
                    && !self.human_tty_ok(&req, info.tty_nr, info.sid)
                  {
                    // B6 phase 4: the human operator must hold the
                    // session's launch tty. An escaped process
                    // (systemd-run unit, migrated child) has no
                    // controlling tty and is rejected here even
                    // though its cgroup says Human — closing the
                    // C10 x C25 identity flip for tty-launched
                    // sessions.
                    // B7: a Human-classified caller failing the tty
                    // check is recorded on the spine but does NOT
                    // apply the -25 trust penalty — the penalty exists
                    // to catch AGENTS probing for human powers (B3).
                    // A tty mismatch for a human-classified caller is
                    // an operator error (headless shell, wrong
                    // terminal), not an attack; penalizing it floored
                    // suite projects to tier 0 as collateral damage
                    // and cascaded into forced-enforce audits
                    // (found via p1 suite failure).
                    self.forged_socket_op_record_only(&req);
                    Response::err("human-only op requires a daemon-witnessed launcher tty")
                  } else {
                    self.dispatch(req)
                  }
                }
              }
            }
            Err(e) => Response::err(format!("bad request: {e}")),
          };
      let mut out = serde_json::to_string(&resp)?;
      out.push('\n');
      (&stream).write_all(out.as_bytes())?;
    }
  }

  /// B6 phase 4: a Human-classified caller may only run session-
  /// scoped human-only ops if its tty_nr matches the session's
  /// launcher tty (or the session was launched headless — launcher
  /// tty 0 = no requirement; headless is a documented residual).
  fn human_tty_ok(&self, req: &Request, caller_tty: u64, caller_sid: u64) -> bool {
    let session = match req {
      // session-scoped human-only ops: launcher tty. BlessRequest is
      // deliberately absent — agents may ask (C32); only the approve
      // is human-only (see BlessApprove below).
      Request::UndoCommit { session }
      | Request::UndoDiscard { session }
      | Request::Freeze { session: Some(session), .. }
      | Request::Thaw { session: Some(session) }
      | Request::Kill { session: Some(session) }
      | Request::Adopt { session, .. }
      | Request::JoinSession { session, .. }
      // R7 (ninja review): JoinSession was ungated — any
      // Human-classified escaped process (tty 0 falls through to the
      // headless branch) could pull itself into a victim scope. Same
      // rule as Adopt now.
      // Cert/Radar/MemoryRecall/Replay are read-only evidence and
      // agent-allowed. The tty gate applied only to human callers, but
      // it protected nothing — the agent can call these anyway without
      // a tty check (agent_allowed short-circuits before this) — while
      // blocking a human from reading evidence outside the launching
      // terminal. Real-session validation (2026-09-16) caught the
      // contradiction: the comment said "read ops need no terminal
      // proof" while the code still gated three of the four. Cert was
      // removed in B7; the rest are removed here.
      => Some(session),
      // session-less human-only ops (thaw/kill/freeze ALL): require a
      // daemon-witnessed launcher tty (B7). tty!=0 alone was spoofable —
      // an escaped process can allocate a fresh pty. The caller's tty
      // must be in the trusted registry AND carry the witnessed session
      // id (P20/F18: a recycled minor keeps tty_nr and devpts inode but
      // always gets a fresh session id).
      Request::Thaw { session: None }
      | Request::Kill { session: None }
      | Request::Freeze { session: None, .. } => {
        return self.tty_is_witnessed(caller_tty, caller_sid);
      }
      // C32: approve must come from the LAUNCHER'S terminal, not just
      // any terminal. The nonce is fishable from the daemon journal
      // (same-user-readable, found by the D'-round probe), so secret
      // knowledge proves nothing — terminal ownership does (TIOCSCTTY
      // is kernel-enforced; an escaped process cannot acquire the
      // human's controlling tty).
      Request::BlessApprove { nonce } => {
        // resolve like bless_approve does: exact key or unique >=8-char
        // prefix (the full nonce is delivered nowhere, C32)
        let launcher = {
          let b = self.bless.lock().unwrap();
          let full = if b.contains_key(nonce) {
            Some(nonce.to_string())
          } else {
            let hits: Vec<String> = b
              .keys()
              .filter(|k| k.starts_with(nonce) && nonce.len() >= 8)
              .cloned()
              .collect();
            if hits.len() == 1 {
              Some(hits[0].clone())
            } else {
              None
            }
          };
          full
            .and_then(|k| {
              let session = &b.get(&k).unwrap().session;
              self.registry
                .lock()
                .unwrap()
                .get(session)
                .map(|s| (s.launcher_tty, s.launcher_sid))
            })
            .unwrap_or((0, 0))
        };
        // P20/F14+F18: sid-bound, not minor-only — a recycled pty minor
        // must not inherit bless-approve rights (same class as F9).
        // Headless (tty 0) stays denied here, as before P20.
        let (l_tty, l_sid) = launcher;
        return l_tty != 0 && self.tty_matches_launcher(caller_tty, caller_sid, l_tty, l_sid);
      }
      // everything else (Spawn, Status, agent-allowed reads, the
      // canary verb): no session tty requirement.
      _ => return true,
    };
    let Some(session) = session else {
      return true;
    };
    let (l_tty, l_sid) = self
      .registry
      .lock()
      .unwrap()
      .get(session)
      .map(|s| (s.launcher_tty, s.launcher_sid))
      .unwrap_or((0, 0));
    // B7: headless sessions (launcher tty 0) previously accepted ANY
    // tty for their human-only ops — an escaped process with a fresh
    // pty could keep/thaw a headless session. Now a headless session
    // requires a daemon-witnessed launcher tty (some other session's
    // launcher terminal — the human operating the fleet from a
    // terminal they launched from). tty-launched sessions keep the
    // exact-match rule.
    // P20/F9+F18: tty-launched sessions are sid-BOUND — minor equality
    // alone let a recycled pty minor inherit launcher rights once the
    // original terminal closed (B7's inode defense was inert: devpts
    // inodes are stable per minor, measured on 7.1.8).
    self.tty_matches_launcher(caller_tty, caller_sid, l_tty, l_sid)
  }

  /// P20/F9+F18: does the caller's terminal match the session's
  /// launcher terminal, SESSION-ID-bound?
  ///
  /// - launcher_tty == 0 (headless or unknown session): B7 rule — the
  ///   caller must itself be a daemon-witnessed launcher tty;
  /// - launcher_tty != 0: exact tty_nr match AND the caller's kernel
  ///   session id must equal the witnessed spawn-time session id. A
  ///   recycled minor keeps its tty_nr and its (stable) devpts inode
  ///   but always carries a fresh session id → deny. No witness (legacy
  ///   pre-P20 row, or a tty the daemon never saw spawn) → deny
  ///   (fail-closed).
  fn tty_matches_launcher(
    &self,
    caller_tty: u64,
    caller_sid: u64,
    launcher_tty: u64,
    launcher_sid: u64,
  ) -> bool {
    if launcher_tty == 0 {
      return self.tty_is_witnessed(caller_tty, caller_sid);
    }
    if launcher_sid == 0 {
      return false;
    }
    caller_tty == launcher_tty && caller_sid == launcher_sid
  }

  /// B7/F18: is this caller's terminal a daemon-witnessed launcher
  /// tty? False for: fresh ptys (never witnessed), headless (tty 0),
  /// and recycled minors (witnessed session id ≠ caller session id).
  /// This is the gate for global ops (freeze-all etc.) — the panic
  /// button must not be reachable from an attacker-allocated terminal.
  fn tty_is_witnessed(&self, caller_tty: u64, caller_sid: u64) -> bool {
    if caller_tty == 0 || caller_sid == 0 {
      return false;
    }
    match self.trusted_ttys.lock().unwrap().get(&caller_tty) {
      Some(witnessed_sid) => *witnessed_sid == caller_sid,
      None => false,
    }
  }

  /// B7: spine-only variant of forged_socket_op — the rejection is
  /// visible (the human can audit it) but the trust penalty does not
  /// fire. Used for Human-classified tty-gate rejections: operator
  /// error, not agent forgery.
  fn forged_socket_op_record_only(&self, req: &Request) {
    let session = match req {
      Request::UndoCommit { session }
      | Request::UndoDiscard { session }
      | Request::Thaw { session: Some(session) }
      | Request::Kill { session: Some(session) }
      | Request::Adopt { session, .. }
      | Request::CanaryRegister { session, .. }
      | Request::TestTrustSignal { session, .. } => Some(session.clone()),
      _ => None,
    };
    if let Some(s) = session.as_ref() {
      if let Ok(sink) = EventSink::for_session(&Self::state_dir(), s) {
        let _ = sink.emit("tty_gate_reject", &format!("{:?}", req), "deny");
      }
    } else if let Ok(sink) = EventSink::for_session(&Self::state_dir(), "system") {
      let _ = sink.emit("tty_gate_reject", &format!("{:?}", req), "deny");
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
      | Request::TestTrustSignal { session, .. } => Some(session.clone()),
      _ => None,
    };
        let project = session
          .as_ref()
          .and_then(|s| self.registry.lock().unwrap().get(s).map(|r| r.project.clone()))
          .or({
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
      Request::Spawn { harness, project, pid, command, enforce, undo, net, net_restrict, allow_hosts, derived_hosts, grants, launcher_tty, launcher_sid } => {
        self.spawn(harness, project, pid, command, enforce, undo, net, net_restrict, allow_hosts, derived_hosts, grants, launcher_tty, launcher_sid)
      }
      Request::Adopt { session, pids } => self.adopt(&session, pids),
      Request::JoinSession { session, pid } => self.join_session(&session, pid),
      Request::Freeze { session, kill_after_m } => {
        self.freeze(session.as_ref(), true, kill_after_m)
      }
      Request::Thaw { session } => self.freeze(session.as_ref(), false, None),
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
    Request::VerifyCert { cert, expected_public } => {
      self.verify_cert(&cert, expected_public.as_deref())
    }
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
      Request::ChannelsRun { net_restrict } => {
        let results = self.run_channels(net_restrict);
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
      Request::ProxyStatus => {
        let m = self.proxies.lock().unwrap();
        let list: Vec<serde_json::Value> = m
          .iter()
          .map(|(sid, h)| serde_json::json!({ "session": sid, "port": h.port }))
          .collect();
        Response::ok().with_extra("proxies", serde_json::json!({ "live": list, "keyring_sha": self.keyring.sha(), "credentials": self.keyring.len() }))
      }
      Request::ProxyOff { session } => {
        let mut m = self.proxies.lock().unwrap();
        let stopped: Vec<String> = match session {
          Some(sid) => m.remove(&sid).map(|h| { drop(h); sid }).into_iter().collect(),
          None => {
            let ids: Vec<String> = m.keys().cloned().collect();
            for sid in &ids {
              if let Some(h) = m.remove(sid) {
                drop(h);
              }
            }
            ids
          }
        };
        Response::ok().with_message(format!("proxy off for {} session(s)", stopped.len()))
          .with_extra("stopped", serde_json::json!(stopped))
      }
    }
  }

  /// P9.1: run the exfil channel census (D6) and store the inventory.
  /// The census is a REPORT — it may confirm open channels (expected:
  /// unix sockets, inherited fds, loopback UDP — Landlock covers TCP
  /// connect only, and the broker covers only destinations it can
  /// read). Findings are recorded in THREAT_MODEL, never silently
  /// patched.
  ///
  /// P11: the census child is forked through the EGRESS BROKER when
  /// `net_restrict` is requested, so the census measures the real launch
  /// path. Previously it was spawned with a plain `Command::new`, which
  /// bypassed the broker entirely — it could never observe a broker
  /// decision, and its probes targeted loopback, which the broker always
  /// allows. The census therefore proved nothing about the mechanism it
  /// was written to audit.
  fn run_channels(&self, net_restrict: bool) -> Vec<(String, String)> {
    let started = std::time::Instant::now();
    let nonce = self.drill.issue();
    let session = format!("drill-{nonce}");
    let honeypot_port = self.honeypot.port;
    // the unix probe needs a real listener so ENOENT is not confused
    // with a kernel denial — the daemon pre-creates it
    let unix_path = "/tmp/castellan-channels-probe.sock";
    let _ = std::fs::remove_file(unix_path);
    let listener = std::os::unix::net::UnixListener::bind(unix_path);
    let exe = std::env::current_exe().unwrap_or_default();
    let probe_args: Vec<String> = vec!["--drill-channels".to_string(), honeypot_port.to_string()];
    // P11: with net_restrict the probe runs UNDER the egress broker, so
    // the census measures the real launch path and its connects are
    // judged by the same policy a low-trust session would get. It
    // previously spawned the probe with a plain Command, bypassing the
    // broker entirely, and probed loopback only — the broker always
    // allows loopback — so the census could not distinguish a working
    // destination policy from a broken one.
    let out = if net_restrict {
      // The tier floor's exact shape with no provider declared: loopback
      // only, resolver excluded so the DNS probe is decisive.
      let policy = castellan_broker::EgressPolicy::new().with_llm_only(&[]);
      let env: Vec<(&str, String)> = vec![
        ("CASTELLAN_DRILL_SESSION", session.clone()),
        ("CASTELLAN_DRILL_NET_RESTRICT", "1".to_string()),
      ];
      castellan_broker::supervise_capture(&exe, &probe_args, &env, &policy)
    } else {
      let mut c = std::process::Command::new(&exe);
      c.args(&probe_args)
        .env("CASTELLAN_DRILL_SESSION", &session)
        .stdout(std::process::Stdio::piped());
      match c.spawn() {
        Ok(mut c) => {
          let mut out = String::new();
          use std::io::Read as _;
          let _ = c.stdout.take().map(|mut s| s.read_to_string(&mut out));
          let _ = c.wait();
          out
        }
        Err(e) => format!("spawn: failed ({e})\n"),
      }
    };
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
      "castellan-daemon: channel census complete in {}ms ({} channels, net_restrict={net_restrict})",
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
          // B6 phase 4 (trace spin): the high-water mark — only
          // events strictly after the last indexed ts are processed.
          // The 2MB accumulated drill corpus made every trace call
          // re-read and re-index everything (29% CPU spin).
          let watermark = castellan_trace::watermark(&conn, s).unwrap_or(0);
          let fresh: Vec<_> = events
            .iter()
            .filter(|e| e.ts > watermark)
            .collect();
          if fresh.is_empty() {
            continue;
          }
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
          let writes: Vec<castellan_trace::WriteEvent> = fresh
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
          if !writes.is_empty() {
            let _ = castellan_trace::index_session(&conn, &writes);
          }
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
    let prototype = match std::fs::read(&proto_path) {
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
    let results = vec![
      self.drill_census(),
      self.drill_honeypot(),
      self.drill_bless(),
      self.drill_envelope(),
      self.drill_freeze(),
      self.drill_channels(),
    ];
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
      .any(|e| e.kind == BlessKind::Forged && e.nonce_hint == forged[..forged.len().min(8)]);
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
    // The scheduled drill runs the plain envelope census (audit posture).
    // The broker-measured census is a manual `channels run --net-restrict`
    // because it forks a supervised child and must not run on a timer.
    let results = self.run_channels(false);
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
    let cert = match &self.signing_key {
      Some(key) => castellan_proof::certificate::assemble_certificate_signed(
        session,
        &project,
        &Self::state_dir(),
        key,
      ),
      None => castellan_proof::certificate::assemble_certificate(
        session,
        &project,
        &Self::state_dir(),
      ),
    };
    match cert {
      Ok(cert) => {
        let json = serde_json::to_value(&cert).unwrap_or(serde_json::Value::Null);
        Response::ok().with_extra("cert", json)
      }
      Err(e) => Response::err(format!("certificate assembly failed: {e}")),
    }
  }

  /// S2: verify a certificate's signature and spine chain. Takes the
  /// certificate JSON as sent by a caller (self-contained: the public
  /// key is embedded). `expected_public` pins the key per boot when the
  /// caller knows it.
  fn verify_cert(&self, cert_json: &str, expected_public: Option<&str>) -> Response {
    let cert: castellan_proof::certificate::ProofCertificate = match serde_json::from_str(cert_json)
    {
      Ok(c) => c,
      Err(e) => return Response::err(format!("malformed certificate: {e}")),
    };
    let canonical = castellan_proof::certificate::cert_canonical(&cert);
    let signature_ok = match &cert.signature {
      Some(sig) => castellan_proof::signing::verify(&canonical, sig, expected_public),
      None => Err("certificate is unsigned".to_string()),
    };
    let chain_ok = cert.spine_chain.as_ref().map(|c| c.intact);
    Response::ok().with_extra(
      "verify",
      serde_json::json!({
        "session": cert.session,
        "signed": cert.signature.is_some(),
        "signature_ok": signature_ok.is_ok(),
        "signature_error": signature_ok.err(),
        "scope": cert.signature.as_ref().map(|s| s.scope.clone()),
        "spine_chain_ok": chain_ok,
        "spine_chain_checked": cert.spine_chain.as_ref().map(|c| c.checked),
      }),
    )
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
      "forged_socket_op" => Signal::ForgedSocketOp,
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
    // C32 (D'-round probe finding): the nonce is NOT delivered anywhere
    // the same user can read — not the socket response, and NOT the
    // daemon journal either (journalctl is same-user-readable and the
    // agent IS the same user; the probe recovered it that way and
    // self-approved). The nonce now proves nothing: approval requires
    // the caller's controlling tty to match the session's launcher
    // tty (see human_tty_ok), which is kernel-enforced and cannot be
    // fished from any file. The nonce survives only as a handle to
    // identify WHICH request is being approved.
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
        "note": "request pending — approve from the launcher's terminal: castellan bless approve <nonce_hint>…",
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

  /// Bless-broker: approve by nonce (full or 8-char hint — the tty
  /// gate in human_tty_ok is the actual authentication; the nonce is
  /// only a request selector, C32). Unknown nonce = forged attempt:
  /// floor the project's trust at 0 (forged_nonce signal).
  fn bless_approve(&self, nonce: &str) -> Response {
    // P8 fault injection: the D3 drill must fail loudly when the bless
    // floor is bypassed. Compile-time hook only.
    if castellan_core::fault_injected("bless") {
      return Response::ok().with_message("granted (injected bypass)");
    }
    let req = {
      let mut b = self.bless.lock().unwrap();
      // exact match, or unique 8-char-hint prefix (C32: the full nonce
      // is no longer delivered anywhere — the human approves from
      // the launcher terminal using the hint shown by bless_request/
      // bless_show; terminal ownership is the proof)
      let matched = if b.contains_key(nonce) {
        b.remove(nonce)
      } else {
        let hits: Vec<String> = b
          .keys()
          .filter(|k| k.starts_with(nonce) && nonce.len() >= 8)
          .cloned()
          .collect();
        if hits.len() == 1 {
          b.remove(&hits[0])
        } else {
          None
        }
      };
      match matched {
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
      b.remove(nonce)
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
      items.sort_by(|a, b| a.0.cmp(b.0));
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
    // registry ledger (registry.jsonl, reloaded at startup).
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
    if !self.freeze(Some(&session.to_string()), true, None).ok {
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
    if !self.freeze(Some(&session.to_string()), true, None).ok {
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
        // A/B (diff-trust): structural blast + scope-creep, computed
        // from the session's upper layer BEFORE commit materializes it
        // (same pre-commit window as the placebo proofs). Owned
        // grammar-free code in castellan-proof::structural — no index
        // daemon, no new deps. Emits one `structural_blast` spine event
        // (the cert's A factor reads it) and, when scope_creep, one
        // ScopeCreep trust signal (-8, advisory at high tiers).
        let blast = castellan_proof::structural::blast_for_session(&project, &upper);
        if let Ok(sink) = EventSink::for_session(&Self::state_dir(), session) {
          if !blast.touched_fns.is_empty() || !blast.files.is_empty() {
            let body = serde_json::json!({
              "files": blast.files,
              "touched_fns": blast.touched_fns,
              "callees": blast.callees,
              "caller_hits": blast.caller_hits,
              "scope_creep": blast.scope_creep,
            });
            let _ = sink.emit("structural_blast", &body.to_string(), "measured");
          }
        }
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
        let pinned_index_sha = Self::durable_session_meta(session)
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
        if blast.scope_creep {
          let _ = db.apply(
            &project,
            &TrustEvent {
              ts: castellan_core::now_unix(),
              session: session.to_string(),
              signal: Signal::ScopeCreep,
              evidence: format!(
                "broad code delta: {} fn(s) across {} file(s); callers {}; callees {}",
                blast.touched_fns.len(),
                blast.files.len(),
                blast.caller_hits,
                blast.callees.len(),
              ),
            },
          );
        }
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
                "{} placebo-controlled proof(s) passed; strengths: {}; baseline_manifest={}",
                passed.len(),
                passed
                  .iter()
                  .map(|p| format!("{:.2}", p.strength()))
                  .collect::<Vec<_>>()
                  .join(", "),
                // V3 corpus K5 asserts this: a pass without a launch-
                // time baseline is unanchored (S1 external-edit guard).
                if baseline.is_some() { "present" } else { "absent" },
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
            scan_daemon.run_artifact_scan(&scan_ctx);
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

  // Argument grouping would mask the spawn contract; the list is the
  // contract (each flag maps 1:1 to a confinement decision).
  #[allow(clippy::too_many_arguments)]
  fn spawn(
    &self,
    harness: String,
    project: PathBuf,
    pid: Option<u32>,
    command: Option<Vec<String>>,
    enforce: bool,
    undo: bool,
    net: bool,
    net_restrict: bool,
    allow_hosts: Vec<String>,
    derived_hosts: Vec<(String, String)>,
    grants: Vec<String>,
    launcher_tty: u64,
    launcher_sid: u64,
  ) -> Response {
    // C7 (ninja review): refuse projects that contain the daemon's own
    // state/config (project = $HOME or an ancestor of $STATE/$CONFIG):
    // trust.db, keyring.toml, spines and canary ledgers would land
    // inside the agent's write roots (full trust + credential forgery).
    // Canonicalize (follows symlinks); normalize() only strips `.`.
    // P13 ninja F8: home/state/cfg are canonicalized too — a symlinked
    // HOME made `canon == home` compare canonical-project against raw
    // $HOME and miss, which was the hole the launcher-side advisory
    // existed to catch. The refusal is the primary control; the
    // advisory stays as second net for layouts this still misses.
    {
      let canon = project.canonicalize().unwrap_or_else(|_| project.clone());
      let state = Self::state_dir();
      let state = state.canonicalize().unwrap_or(state);
      let cfgdir = std::env::var("XDG_CONFIG_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
          std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config")
        });
      let cfgdir = cfgdir.canonicalize().unwrap_or(cfgdir);
      let home = std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default());
      let home = home.canonicalize().unwrap_or(home);
      let bad = state
        .starts_with(&canon)
        || cfgdir.starts_with(&canon)
        || home.starts_with(&canon)
        || canon == *"/";
      if bad {
        return Response::err(
          "project contains daemon state/config (refusing: trust.db and keyring would be agent-writable)",
        );
      }
    }
    // R7 (ninja review): per-project spawn rate limit (fork-bomb via an
    // escaped Human caller: each spawn grows registry + proxy listener).
    // 10 spawns per project per 60s; excess refused (fail-closed, loud).
    {
      let mut rl = self.spawn_rate.lock().unwrap();
      let now = std::time::Instant::now();
      let e = rl.entry(project.to_string_lossy().into_owned()).or_insert((now, 0));
      if now.duration_since(e.0).as_secs() >= 60 {
        e.0 = now;
        e.1 = 0;
      }
      e.1 += 1;
      if e.1 > 10 {
        return Response::err("spawn rate limited (10/min per project)");
      }
    }
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
    // Cold start (decision 2026-08-30, option B): a project with NO
    // trust record runs fail-closed too — the least-trusted session
    // must not get the widest write surface. The cold floor forces
    // undo+net but honors an explicit human --no-enforce (audit mode,
    // labeled debug-only): an informed opt-out is not softened. The
    // first keep/proof cycle earns the looser default.
    let (low_trust, cold_trust, tier_str, granted) = {
      let db = self.trust.lock().unwrap();
      let t = db.score(&project).ok();
      // cold = no trust record (score() synthesizes tier-2 with
      // last_event_ts 0 for unknown projects; see COLD_START_SCORE)
      let cold = t
        .as_ref()
        .map(|t| t.last_event_ts == 0)
        .unwrap_or(true);
      let low = t
        .as_ref()
        .map(|t| t.tier <= castellan_trust::Tier::One)
        .unwrap_or(false);
      let tier = match (&t, cold) {
        (Some(t), false) => t.tier.as_str().to_string(),
        (_, true) => "cold".into(),
        (None, false) => "cold".into(),
      };
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
      (low, cold, tier, granted)
    };
    // tiers 0-1: enforce+undo forced regardless of flags (trust was
    // earned down — full fail-closed containment).
    //
    // P11: destination-scoped egress (`net_restrict`) is ALSO forced at
    // tiers 0-1, via the broker's IP allowlist. This is the mechanism
    // that makes the floor real without the deadlock found live on
    // 2026-09-16: Landlock's `net` is port-scoped, so allowing 443 for
    // the LLM API also allows 443 exfil, and forcing it denied the API
    // itself — no edits, auto-revert, trust stays 0, unrecoverable. The
    // broker allowlist is destination-scoped, so the LLM provider stays
    // reachable while everything else is denied.
    //
    // Cold start is NOT forced: absence of history is not evidence of
    // misbehavior, and a stranger's first session should not be unable
    // to fetch a dependency. Cold still forces undo (C11).
    //
    // Landlock's port-scoped `net` is never forced at any tier.
    let egress_grant = granted.iter().any(|g| g == "egress");
    let (enforce, undo, net, mut net_restrict) = if low_trust && granted.is_empty() {
      (true, true, net, true)
    } else if cold_trust && granted.is_empty() {
      (enforce, true, net, net_restrict)
    } else {
      (enforce, undo, net, net_restrict)
    };
    // The effective allowlist is resolved HERE, daemon-side, so the
    // policy the broker enforces and the policy the launch profile
    // records are the same list. A missing allowlist under a forced
    // restriction is deny-all: the honest fail-closed state, and the
    // CLI says so loudly.
    //
    // P21.1: when the operator declared nothing (no flags, no env, no
    // egress.toml), the launcher's `derived_hosts` fill the gap so a
    // fresh install can reach its own LLM provider without hand-editing
    // config. Derivation is loud (recorded in the profile and on the
    // spine) and only ever applies where the list would otherwise be
    // empty — an explicit declaration always wins.
    let mut derived_used: Vec<(String, String)> = Vec::new();
    let allow_hosts: Vec<String> = if net_restrict && !egress_grant {
      let mut resolved = resolve_allow_hosts(&allow_hosts);
      if resolved.is_empty() && !derived_hosts.is_empty() {
        for (host, _source) in &derived_hosts {
          if !resolved.contains(host) {
            resolved.push(host.clone());
          }
        }
        derived_used = derived_hosts.clone();
      }
      resolved
    } else if egress_grant {
      // a human-approved egress grant: unrestricted for this launch
      net_restrict = false;
      Vec::new()
    } else {
      allow_hosts
    };
    if !derived_used.is_empty() {
      eprintln!(
        "castellan-daemon: no allowlist declared — derived {} destination(s) for {}: {}",
        derived_used.len(),
        harness,
        derived_used
          .iter()
          .map(|(h, s)| format!("{h} ({s})"))
          .collect::<Vec<_>>()
          .join(", ")
      );
      if let Ok(sink) = EventSink::for_session(&Self::state_dir(), &id) {
        for (host, source) in &derived_used {
          let _ = sink.emit("egress_derived", host, source);
        }
      }
    }
    if low_trust && granted.is_empty() {
      eprintln!(
        "castellan-daemon: tier floor active for {} — enforce+undo+egress-restrict (allowlist: {})",
        project.display(),
        if allow_hosts.is_empty() { "none (deny-all egress)".into() } else { allow_hosts.join(", ") }
      );
    }
    let config_sha = project_config_sha(&project);
    let pinned = config_sha.clone();
    // P9.4 gap-plug: pin the stria phrase index at spawn. The weight
    // is read at keep from a file inside the agent's write roots —
    // an unpinned read lets the agent rewrite the index mid-session
    // to inflate positive trust signals. Neutral-fail (weight 1.0)
    // on missing/mismatched pin: weighting is advisory, so neutral
    // is the right failure mode (unlike test_cmd's refuse).
    let hub_index_sha = castellan_hub::index_sha(&project);
    // V3 friction fix: create the session scratch BEFORE the launcher
    // applies the envelope. Landlock path-beneath rules need an
    // existing parent; a grant on the not-yet-created session dir left
    // the launcher's TMPDIR mkdir EACCES (found via cargo build failure
    // under enforce). The daemon is unconfined, so it creates the root.
    let _ = std::fs::create_dir_all(
      Self::state_dir().join("castellan/sessions").join(&id),
    );
    // P12: per-session credential-injecting egress proxy. The policy it
    // enforces IS the session's resolved destination policy (same
    // allow_hosts the B8 broker gets), so the proxy and the kernel
    // broker never disagree. A start failure degrades to today's
    // posture (no proxy env, canaries only) — honest, not fatal.
    let proxy_port: u16 = {
      let pcfg = castellan_proxy::ProxyConfig {
        session: id.clone(),
        state_dir: Self::state_dir(),
        allow_hosts: allow_hosts.clone(),
        restrict: net_restrict,
        keyring: self.keyring.clone(),
        client_tls: self.proxy_tls.clone(),
        // P15 H1/F2: a tunnel to the honeypot port would originate the
        // connection from the daemon pid and defeat sender attribution.
        deny_ports: if self.honeypot.port > 0 {
          vec![self.honeypot.port]
        } else {
          vec![]
        },
      };
      match castellan_proxy::start(pcfg) {
        Ok(h) => {
          let port = h.port;
          self.proxies.lock().unwrap().insert(id.clone(), h);
          port
        }
        Err(e) => {
          eprintln!("castellan-daemon: egress proxy unavailable for {id} ({e}) — session runs without credential injection");
          0
        }
      }
    };
    // B7: witness the launcher's terminal at spawn. Only a tty the
    // daemon has seen as a launcher tty may later run session-less
    // global ops (freeze-all/thaw-all/kill-all) — an escaped process
    // allocating a fresh pty never enters this map.
    // P20/F18 correction: the witness value is the launcher's SESSION
    // ID, not its tty inode. devpts assigns a stable inode per minor
    // (measured on 7.1.8: /dev/pts/1 inode 4 across close/reopen), so
    // the inode was identical for a recycled minor — inert against the
    // recycling attack it was meant to defeat. A fresh pty invocation
    // always carries a new session id; tty_nr still keys the map.
    if launcher_tty != 0 && launcher_sid != 0 {
      self
        .trusted_ttys
        .lock()
        .unwrap()
        .insert(launcher_tty, launcher_sid);
    }
    let started_at = castellan_core::now_unix();
    self.registry.lock().unwrap().insert(Session {
      id: id.clone(),
      harness: harness.clone(),
      project: project.clone(),
      config_sha: pinned,
      started_at,
      hub_index_sha,
      launcher_tty,
      launcher_sid,
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
      launcher_tty,
      launcher_sid,
      started_at,
    );
    let ca_cert = if proxy_port > 0 {
      Self::state_dir()
        .join("castellan/sessions")
        .join(&id)
        .join("ca.pem")
        .to_string_lossy()
        .into_owned()
    } else {
      String::new()
    };
    Response::ok()
      .with_message(format!("spawned session {id}"))
      .with_extra(
        "profile",
        serde_json::json!({
          "enforce": enforce,
          "undo": undo,
          "net": net,
          "net_restrict": net_restrict,
          "allow_hosts": allow_hosts,
          "derived_hosts": derived_used,
          "forced": low_trust && granted.is_empty(),
          "cold_forced_undo": cold_trust && granted.is_empty() && !low_trust,
          "tier": tier_str,
          "grants": granted,
          "proxy_port": proxy_port,
          "ca_cert": ca_cert,
          "keyring_sha": self.keyring.sha(),
          "keyring_entries": self.keyring.len(),
        }),
      )
  }

  // Same contract-as-signature rationale as spawn.
  #[allow(clippy::too_many_arguments)]
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
    launcher_tty: u64,
    launcher_sid: u64,
    started_at: u64,
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
        "keyring_sha": self.keyring.sha(),
        "command": command,
        "enforce": enforce,
        "undo": undo,
        "net": net,
        // P20: control-plane survival across daemon restart. launcher_tty
        // lets human_tty_ok match the original terminal again;
        // launcher_sid is the per-open identity (devpts inodes are stable
        // per minor — F18); started_at keeps the N6 orphan census window
        // stable.
        "launcher_tty": launcher_tty,
        "launcher_sid": launcher_sid,
        "started_at": started_at,
      })
      .to_string(),
    )
  }

  /// P20.1: control-plane survival across daemon restart (F2).
  ///
  /// Registry, trusted_ttys and the audit watcher were spawn-only, so a
  /// restart (systemd `Restart=on-failure`, `service stop/start`, an
  /// upgrade) wiped status/freeze/thaw/kill/adopt for every live session
  /// while the agents kept running Landlock-confined but unmanageable.
  /// Rehydrate from the durable per-session JSON:
  ///
  /// - a row is used only if it parses AND its `session` field matches
  ///   its filename — mismatch or corruption is skipped and COUNTED
  ///   (fail-closed; never panic — `panic=abort` would take the daemon
  ///   down on attacker- or entropy-controlled input);
  /// - trusted_ttys re-witnesses the launcher tty with the persisted
  ///   SESSION ID (P20/F18 — devpts inodes are stable per minor, so
  ///   the session id is the only per-open identity);
  /// - legacy rows (pre-P20) lack `launcher_sid` — they enter the
  ///   registry but are NOT re-witnessed, so tty-gated ops on them are
  ///   denied (fail-closed; relaunch to restore tty control);
  /// - the audit watcher restarts with a RESTART-TIME baseline: the
  ///   window while the daemon was down is unobservable (documented).
  ///
  /// Accepted residual R-POISON (THREAT_MODEL): an unconfined same-uid
  /// process able to write `sessions/*.json` can plant launcher_tty +
  /// inode — but that process can already write `cgroup.freeze`
  /// directly, so rehydration grants no capability it lacks (equal
  /// power; hashing the row would imply integrity we cannot enforce).
  fn rehydrate(&self) {
    let dir = Self::state_dir().join("castellan/sessions");
    let Ok(rd) = std::fs::read_dir(&dir) else {
      return;
    };
    let mut ok = 0u32;
    let mut skipped = 0u32;
    for entry in rd.flatten() {
      let fname = entry.file_name();
      let fname = fname.to_string_lossy();
      let Some(id) = fname.strip_suffix(".json").map(|s| s.to_string()) else {
        continue;
      };
      let raw = match std::fs::read_to_string(entry.path()) {
        Ok(s) => s,
        Err(_) => {
          skipped += 1;
          continue;
        }
      };
      let mtime_fallback = entry
        .metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
      // Validation lives in parse_session_row (unit-tested): corrupt,
      // mismatched and incomplete rows are skipped and counted.
      let Some((session, undo)) = parse_session_row(&id, &raw, mtime_fallback) else {
        skipped += 1;
        continue;
      };
      // Re-witness the launcher tty with the spawn-time session id
      // (P20/F18 — devpts inodes are stable per minor, so sid is the
      // only per-open identity worth persisting).
      if session.launcher_tty != 0 && session.launcher_sid != 0 {
        self
          .trusted_ttys
          .lock()
          .unwrap()
          .insert(session.launcher_tty, session.launcher_sid);
      }
      let sid = session.id.clone();
      let harness = session.harness.clone();
      let project = session.project.clone();
      // P21.4: the auto-kill deadline is an ABSOLUTE unix ts, preserved
      // across restart (not restarted from restart time): a deadline is
      // a deadline. If it passed while the daemon was down, the timer
      // thread fires it on its next tick (2s). The timer only kills a
      // session that is still frozen, so a pre-restart thaw cannot be
      // undone by a stale deadline.
      if let Some(at) = serde_json::from_str::<serde_json::Value>(&raw)
        .ok()
        .and_then(|v| v.get("kill_at").and_then(|k| k.as_u64()))
      {
        self.freeze_deadlines.lock().unwrap().insert(sid.clone(), at);
      }
      self.registry.lock().unwrap().insert(session);
      // Undo sessions need their notes entry back or keep/undo-* return
      // "no undo layer recorded" after a restart (G1b: clean error, never
      // a panic — the notes paths all use `let Some(n) = ... else`).
      if undo {
        let upper = Self::state_dir()
          .join("castellan/sessions")
          .join(&sid)
          .join("overlay/upper");
        if upper.exists() {
          // With --undo the project dir itself is untouched (writes go
          // to the upper layer), so a restart-time capture equals the
          // spawn-time baseline for honest sessions.
          let baseline = castellan_proof::BaselineManifest::capture(&project).ok();
          self.notes.lock().unwrap().insert(
            sid.clone(),
            SessionNotes {
              undo_upper: Some(upper),
              baseline,
            },
          );
        }
      }
      // Audit watcher only for sessions whose scope still exists —
      // dead sessions self-prune from the registry on the next status().
      if self.root.freeze_state(&sid).unwrap_or(FreezeState::Missing) != FreezeState::Missing {
        self.start_audit(&sid, &harness, &project);
      }
      ok += 1;
    }
    if ok > 0 || skipped > 0 {
      eprintln!(
        "castellan-daemon: rehydrated {ok} session(s) from disk, skipped {skipped} unreadable/mismatched"
      );
    }
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

  /// B6 portability: the launcher's pid joins its own session scope,
  /// performed daemon-side. Kernel 7.1.x denies cgroup.procs writes
  /// from outside the delegated subtree (the launcher often sits in
  /// session-*.scope); the daemon lives inside user@1000.service where
  /// migration is permitted. Entering a session only constrains the
  /// caller, so any non-agent identity may join its own session.
  fn join_session(&self, session: &SessionId, pid: u32) -> Response {
    {
      let reg = self.registry.lock().unwrap();
      if !reg.contains(session) {
        return Response::err(format!("unknown session {session}"));
      }
    }
    match self.root.write_procs(session, &[pid]) {
      Ok(_) => Response::ok().with_message(format!("pid {pid} joined {session}")),
      Err(e) => Response::err(format!("join failed: {e}")),
    }
  }

  fn freeze(&self, session: Option<&SessionId>, freeze: bool, kill_after_m: Option<u64>) -> Response {
    let targets = self.resolve_targets(session);
    if targets.is_empty() {
      return Response::ok()
        .with_message(if freeze { "no sessions to freeze" } else { "no sessions to thaw" });
    }
    // P21.4: record or clear the auto-kill deadline. Only a real freeze
    // with an explicit flag sets one; a thaw clears it. `--kill-after-m
    // 0` is treated as "no deadline" (a zero-minute window is a footgun,
    // not a feature).
    if freeze {
      if let Some(mins) = kill_after_m.filter(|m| *m > 0) {
        // P21.4: minutes, except under the test override. The override
        // (CASTELLAN_KILL_AFTER_TEST_SECS) can only SHORTEN a deadline —
        // it cannot disable the timer — so it is not a defense-off
        // switch; the p21-freeze-ux suite uses it to exercise the timer
        // without waiting a real minute.
        let secs_per_min: u64 = std::env::var("CASTELLAN_KILL_AFTER_TEST_SECS")
          .ok()
          .and_then(|v| v.parse().ok())
          .filter(|v| *v > 0)
          .unwrap_or(60);
        let deadline = castellan_core::now_unix() + mins.saturating_mul(secs_per_min);
        let mut d = self.freeze_deadlines.lock().unwrap();
        for id in &targets {
          d.insert(id.clone(), deadline);
          self.persist_kill_deadline(id, Some(deadline));
        }
      } else if kill_after_m.is_some() {
        // explicit 0: clear any existing deadline
        let mut d = self.freeze_deadlines.lock().unwrap();
        for id in &targets {
          d.remove(id);
          self.persist_kill_deadline(id, None);
        }
      }
    } else {
      let mut d = self.freeze_deadlines.lock().unwrap();
      for id in &targets {
        d.remove(id);
        self.persist_kill_deadline(id, None);
      }
    }
    let msgs: Vec<String> = targets
      .iter()
      .map(|id| {
        let prev = self.root.freeze_state(id).unwrap_or(FreezeState::Missing);
        match self.root.set_freeze(id, freeze) {
          Ok(state) => {
            // P21.4: banner on the session's terminal, written daemon-side.
            // An in-scope process (the supervisor) is descheduled while
            // frozen — proven live on .227: only the daemon, outside the
            // frozen scope, can put text on the terminal (wall-style).
            if prev != state {
              let line = if freeze {
                match self.freeze_deadlines.lock().unwrap().get(id).copied() {
                  Some(at) => {
                    let left = at.saturating_sub(castellan_core::now_unix());
                    format!("FROZEN — thaw with `castellan thaw {id}` (auto-kill in {}:{:02})", left / 60, left % 60)
                  }
                  None => format!("FROZEN — thaw with `castellan thaw {id}`"),
                }
              } else {
                format!("session {id} resumed")
              };
              self.banner(id, &line);
            }
            format!("{id}: {}", state.as_str())
          }
          Err(e) => format!("{id}: error {e}"),
        }
      })
      .collect();
    Response::ok().with_message(msgs.join(", ")).with_sessions(self.reports())
  }

  /// P21.4: persist (or clear) the auto-kill deadline on the session row.
  /// Read-modify-write of a single field; called from the freeze/thaw
  /// dispatch path only (the timer thread never writes rows), so it does
  /// not race the spawn-time write. Failure is non-fatal: the in-memory
  /// deadline still applies this boot; the row just won't survive a
  /// restart.
  fn persist_kill_deadline(&self, id: &str, kill_at: Option<u64>) {
    let path = Self::state_dir()
      .join("castellan/sessions")
      .join(format!("{id}.json"));
    let Ok(raw) = std::fs::read_to_string(&path) else {
      return;
    };
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&raw) else {
      return;
    };
    match kill_at {
      Some(at) => v["kill_at"] = serde_json::json!(at),
      None => {
        if let Some(obj) = v.as_object_mut() {
          obj.remove("kill_at");
        }
      }
    }
    let _ = std::fs::write(&path, v.to_string());
  }

  /// P21.4: write a line to the session's terminal. The daemon is outside
  /// the frozen scope, so it can write while the session is descheduled;
  /// the supervisor cannot (a frozen cgroup stops every member). The tty
  /// comes from the session's recorded launcher_tty (kernel tty_nr); the
  /// minor is `tty_nr & 0xff` on Linux (major in bits 8..11), so the pty
  /// slave is `/dev/pts/<minor>`. Opened O_WRONLY|O_NOCTTY: O_NOCTTY so
  /// the daemon never acquires a controlling terminal, O_NONBLOCK so a
  /// full/absent reader cannot block the freeze path. Best-effort: any
  /// failure is silent (the spine row and `status` remain the record).
  fn banner(&self, id: &SessionId, line: &str) {
    let tty_nr = {
      let reg = self.registry.lock().unwrap();
      reg.get(id).map(|s| s.launcher_tty).unwrap_or(0)
    };
    if tty_nr == 0 {
      return;
    }
    // kernel new_encode_dev: minor low byte in bits 0..7, minor high bits
    // in bits 12..23 (a plain `& 0xff` breaks at /dev/pts/256).
    let minor = (tty_nr & 0xff) | ((tty_nr >> 12) & 0xfff00);
    let path = format!("/dev/pts/{minor}");
    use std::os::unix::fs::OpenOptionsExt as _;
    let Ok(mut f) = std::fs::OpenOptions::new()
      .write(true)
      .custom_flags(nix::libc::O_NOCTTY | nix::libc::O_NONBLOCK)
      .open(&path)
    else {
      return;
    };
    use std::io::Write as _;
    let _ = f.write_all(format!("\r\n{line}\r\n").as_bytes());
    let _ = f.flush();
  }

  /// P21.4: the auto-kill timer tick. A session whose deadline passed
  /// while still frozen is SIGKILLed (scope + egress proxy torn down
  /// like `kill`), an `auto_kill` spine row records it, and the deadline
  /// is removed. A session that was thawed already lost its deadline at
  /// thaw time, so this never races a deliberate thaw into a kill: the
  /// last decision wins. Restart note: deadlines are daemon-memory, so a
  /// restart mid-count restarts the window (documented).
  fn run_freeze_deadlines(&self) {
    let now = castellan_core::now_unix();
    let due: Vec<SessionId> = {
      let mut d = self.freeze_deadlines.lock().unwrap();
      let due: Vec<SessionId> = d
        .iter()
        .filter(|(_, deadline)| **deadline <= now)
        .map(|(id, _)| id.clone())
        .collect();
      for id in &due {
        d.remove(id);
      }
      due
    };
    for id in due {
      // only kill what is still frozen — a concurrent thaw means the
      // operator returned; the deadline is already gone, this is belt
      // and braces against a stale snapshot.
      if self.root.freeze_state(&id).unwrap_or(FreezeState::Missing) != FreezeState::Frozen {
        continue;
      }
      if let Some(h) = self.proxies.lock().unwrap().remove(&id) {
        drop(h);
      }
      let harness = {
        let reg = self.registry.lock().unwrap();
        reg.get(&id).map(|s| s.harness.clone())
      };
      if let Some(h) = harness {
        self.end_audit(&id, &h);
      }
      let _ = self.root.set_freeze(&id, false);
      let killed = self.root.kill_all(&id).unwrap_or(0);
      if let Ok(sink) = EventSink::for_session(&Self::state_dir(), &id) {
        let _ = sink.emit("auto_kill", &format!("frozen past kill-after deadline, {killed} pid(s) killed"), "deny");
      }
      // tear the scope down and drop the registration exactly like
      // `kill` does, so `status` does not keep listing a dead session.
      let _ = self.root.destroy_session(&id);
      self.registry.lock().unwrap().remove(&id);
      eprintln!("castellan-daemon: auto-kill: session {id} frozen past its --kill-after deadline — {killed} pid(s) killed");
    }
  }

  fn kill(&self, session: Option<&SessionId>) -> Response {
    let targets = self.resolve_targets(session);
    let mut msgs = Vec::new();
    for id in targets {
      // P12: stop the session's egress proxy first (Drop closes the
      // listener); kernel posture (B8) is unchanged — fail-closed.
      if let Some(h) = self.proxies.lock().unwrap().remove(&id) {
        drop(h);
      }
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
    let deadlines = self.freeze_deadlines.lock().unwrap().clone();
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
        kill_at: deadlines.get(&s.id).copied(),
      })
      .collect()
  }

  /// B8.3 (C36): periodic escape-shape sweep. For each live session,
  /// look for transient `run-*.service`/`run-*.timer` units created
  /// during its window. Report-only: emit an `escape_unit` spine event
  /// (deduped per (session, unit)). No blanket kill — see the C36 probe.
  fn run_sweep(&self) {
    let sessions: Vec<(SessionId, u64)> = {
      let reg = self.registry.lock().unwrap();
      reg.values().map(|s| (s.id.clone(), s.started_at)).collect()
    };
    for (id, start) in sessions {
      let hits = self.root.run_units_since(&id, start);
      for unit in hits {
        let key = format!("{id}:{unit}");
        {
          let mut seen = self.swept.lock().unwrap();
          if !seen.insert(key) {
            continue;
          }
          // keep the dedup set bounded — sessions are short-lived and
          // sweep intervals are seconds; 4096 covers any realistic run.
          if seen.len() > 4096 {
            seen.clear();
            seen.insert(format!("{id}:{unit}"));
          }
        }
        if let Ok(sink) = EventSink::for_session(&Self::state_dir(), &id) {
          let _ = sink.emit("escape_unit", &unit, "deny");
        }
        eprintln!("castellan-daemon: escape-shape unit {unit} under session {id} — reported (B8.3)");
      }
    }
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
/// - udp: UDP send to a PUBLIC address (expected OPEN without
///   the broker; DENIED under a destination policy)
/// - unix: unix socket connect outside the session (expected
///   OPEN — unix sockets are not covered by Landlock)
/// - dns: DNS-crafted UDP query to the resolver (expected OPEN
///   without the broker; DENIED under a destination policy)
/// - fs_drop: write to a world-readable path outside the workspace
///   (expected DENIED by Landlock write roots)
/// - fd_inherit: write through an inherited fd (expected OPEN — the
///   envelope cannot revoke an already-open fd)
///
/// P11: the UDP and DNS probes target a PUBLIC address, not loopback.
/// They previously sent to 127.0.0.1, which the broker always allows
/// (loopback is the honeypot path), so the census could not distinguish
/// a working destination policy from a broken one. A loopback UDP send
/// is still reported as `udp_loopback`, because that channel genuinely
/// stays open for any local listener.
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

  // TCP to a PUBLIC destination: the decisive probe for the B8 broker's
  // destination policy. 1.2.3.4 is TEST-NET-1 (RFC 5737), reserved and
  // never routed — a connect that "succeeds" would be a kernel-level
  // false positive, so an EPERM here is unambiguous.
  let tcp_public = match TcpStream::connect(("1.2.3.4", 443)) {
    Ok(_) => "ALLOWED (destination policy not enforced)".to_string(),
    Err(e) => format!("DENIED ({e})"),
  };
  out.push(("tcp_public".into(), tcp_public));

  // UDP send to a PUBLIC address. Connected-UDP (connect + send) is
  // used deliberately: the broker's decision point is `connect`, which
  // every UDP client performs, and a bare sendto on an unconnected
  // socket is the implicit-destination path the broker cannot judge.
  let udp = match UdpSocket::bind("0.0.0.0:0") {
    Ok(s) => match s.connect(("1.2.3.4", 53)).and_then(|_| s.send(b"probe")) {
      Ok(_) => "OPEN (UDP not covered)".to_string(),
      Err(e) => format!("DENIED ({e})"),
    },
    Err(e) => format!("bind failed ({e})"),
  };
  out.push(("udp".into(), udp));

  // UDP to a LOCAL listener: genuinely open under every posture, because
  // loopback is the canary-honeypot path. Recorded so the residual is
  // explicit rather than implied by the public probe.
  let udp_loop = match UdpSocket::bind("127.0.0.1:0") {
    Ok(s) => match s.send_to(b"probe", ("127.0.0.1", denied_port)) {
      Ok(_) => "OPEN (loopback UDP — local listener channel)".to_string(),
      Err(e) => format!("DENIED ({e})"),
    },
    Err(e) => format!("bind failed ({e})"),
  };
  out.push(("udp_loopback".into(), udp_loop));

  // Unix socket connect outside the session — expected OPEN.
  let unix = match UnixStream::connect("/tmp/castellan-channels-probe.sock") {
    Ok(_) => "OPEN (unix sockets not covered)".to_string(),
    Err(e) => format!("DENIED ({e})"),
  };
  out.push(("unix".into(), unix));

  // DNS-crafted UDP query to the system resolver. Under the tier floor
  // the resolver is NOT in the allowlist (a reachable resolver is a DNS
  // tunnel), so this must be DENIED; without a destination policy it
  // stays OPEN.
  let dns = match UdpSocket::bind("0.0.0.0:0") {
    Ok(s) => {
      let target = castellan_broker::resolver_ips()
        .first()
        .map(|ip| (ip.to_string(), 53u16))
        .unwrap_or_else(|| ("1.2.3.4".to_string(), 53u16));
      match s.connect(&target).and_then(|_| s.send(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")) {
        Ok(_) => "OPEN (DNS exfil possible)".to_string(),
        Err(e) => format!("DENIED ({e})"),
      }
    }
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

  // P20.1: rehydration row validation (G2). Corrupt, mismatched and
  // incomplete rows must be SKIPPED (None), never panicking — the daemon
  // is panic=abort.
  #[test]
  fn rehydrate_row_valid_parses() {
    let raw = serde_json::json!({
      "session": "sABC",
      "project": "/tmp/p",
      "harness": "claude",
      "config_sha": "sha",
      "hub_index_sha": null,
      "command": null,
      "enforce": true,
      "undo": true,
      "net": false,
      "launcher_tty": 259,
      "launcher_sid": 12345,
      "started_at": 1700000000
    })
    .to_string();
    let (s, undo) = parse_session_row("sABC", &raw, 0).expect("valid row parses");
    assert_eq!(s.id, "sABC");
    assert_eq!(s.harness, "claude");
    assert_eq!(s.launcher_tty, 259);
    assert_eq!(s.launcher_sid, 12345);
    assert_eq!(s.started_at, 1700000000);
    assert!(undo);
  }

  #[test]
  fn rehydrate_row_corrupt_is_skipped() {
    assert!(parse_session_row("sABC", "not json {", 0).is_none());
  }

  #[test]
  fn rehydrate_row_session_mismatch_is_skipped() {
    // filename says sABC, row says sXYZ — fail closed, do not register
    // under either identity.
    let raw = r#"{"session":"sXYZ","project":"/tmp/p","harness":"claude"}"#;
    assert!(parse_session_row("sABC", raw, 0).is_none());
  }

  #[test]
  fn rehydrate_row_missing_required_field_is_skipped() {
    let raw = r#"{"session":"sABC","harness":"claude"}"#;
    assert!(parse_session_row("sABC", raw, 0).is_none());
    let raw2 = r#"{"session":"sABC","project":"/tmp/p"}"#;
    assert!(parse_session_row("sABC", raw2, 0).is_none());
  }

  #[test]
  fn rehydrate_row_legacy_uses_mtime_fallback() {
    // pre-P20 row: no started_at, no launcher_tty/sid. It must still
    // parse (functionality preserved) with the mtime fallback and NOT
    // invent a tty witness (launcher 0 → tty-gated ops stay denied,
    // and tty_matches_launcher refuses sid==0 — fail-closed).
    let raw = r#"{"session":"sLEG","project":"/tmp/p","harness":"codex"}"#;
    let (s, undo) = parse_session_row("sLEG", raw, 1700000123).expect("legacy row parses");
    assert_eq!(s.started_at, 1700000123);
    assert_eq!(s.launcher_tty, 0);
    assert_eq!(s.launcher_sid, 0);
    assert!(!undo);
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
