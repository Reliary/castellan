use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub type SessionId = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
  pub id: SessionId,
  pub harness: String,
  pub project: PathBuf,
  /// sha256 of the project's .reliary/castellan.toml at spawn time.
  /// None = no config at launch. The daemon refuses to execute a
  /// test_cmd whose config hash differs from this pin: the config
  /// lives inside the agent's write roots, so an unpinned read is an
  /// agent->daemon command-injection path.
  #[serde(default)]
  pub config_sha: Option<String>,
  /// unix timestamp of spawn; the orphan census (N6) uses it to find
  /// processes started during the session window that escaped the
  /// session cgroup via the user manager.
  #[serde(default)]
  pub started_at: u64,
  /// sha256 of the project's stria phrase index (.stria/phrases.sqlite)
  /// at spawn time. None = no index at launch. The P9.4 blast-radius
  /// weight is read at KEEP from this file, which lives inside the
  /// agent's write roots — an agent could rewrite the index mid-session
  /// to make its touched files look like hubs and inflate positive
  /// trust signals. On missing/mismatched pin the weight is 1.0
  /// (neutral, not refused — weighting is advisory).
  #[serde(default)]
  pub hub_index_sha: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeState {
  Thawed,
  Frozen,
  Missing,
}

impl FreezeState {
  pub fn as_str(self) -> &'static str {
    match self {
      FreezeState::Thawed => "thawed",
      FreezeState::Frozen => "frozen",
      FreezeState::Missing => "missing",
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReport {
  pub id: SessionId,
  pub harness: String,
  pub project: String,
  pub state: FreezeState,
  pub pids: usize,
}

/// N2: two-tier response routing. Low-confidence signals (radar drift,
/// would_deny in audit mode) log silently — freezing on them would
/// teach the attacker the detection rules (T2) and freeze legit
/// sessions on novel-but-benign behavior. High-confidence signals
/// (canary trip, hard-deny write, cgroup membership drift) freeze.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseTier {
  /// Log to the spine only. Never freezes.
  Silent,
  /// Freeze the session (kernel-enforced pause).
  Freeze,
}

/// The routing table. Add a signal here when wiring a new detector;
/// the default for anything not listed is Silent (fail-open on
/// detection, fail-closed on enforcement).
pub fn response_tier(signal: &str) -> ResponseTier {
  match signal {
    "canary_trip" | "hard_deny" | "membership_drift" => ResponseTier::Freeze,
    _ => ResponseTier::Silent,
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
  Spawn {
    harness: String,
    project: PathBuf,
    pid: Option<u32>,
    /// The exact command the launcher will exec (persisted for
    /// bless-broker relaunch orchestration).
    #[serde(default)]
    command: Option<Vec<String>>,
    /// Confinement flags, persisted so a relaunch reproduces the
    /// session's confinement.
    #[serde(default)]
    enforce: bool,
    #[serde(default)]
    undo: bool,
    #[serde(default)]
    net: bool,
    /// Expansion wants this launch wants to consume. The daemon
    /// consumes daemon-side one-shot grants (keyed project:want);
    /// a consumed grant overrides the tier floor (human decision).
    #[serde(default)]
    grants: Vec<String>,
  },
  Adopt {
    session: SessionId,
    pids: Vec<u32>,
  },
  Freeze {
    session: Option<SessionId>,
  },
  Thaw {
    session: Option<SessionId>,
  },
  Kill {
    session: Option<SessionId>,
  },
  Status,
  Note {
    session: SessionId,
    kind: String,
    detail: String,
  },
  UndoDiff {
    session: SessionId,
  },
  UndoDiscard {
    session: SessionId,
  },
  UndoCommit {
    session: SessionId,
  },
  /// Generate canary secrets for a session, register them with the
  /// honeypot, and return them (plus the honeypot port) to the launcher.
  CanaryRegister {
    session: SessionId,
    project: PathBuf,
    harness: String,
  },
  /// Return the daemon's honeypot port (0 if detached).
  HoneypotPort,
  /// Query the trust score/tier for a project.
  TrustScore {
    project: PathBuf,
  },
  /// Apply a trust signal to a project.
  TrustSignal {
    project: PathBuf,
    session: SessionId,
    signal: String,
    evidence: String,
  },
  /// Bless-broker: request an envelope expansion for a session.
  BlessRequest {
    session: SessionId,
    want: String,
    reason: String,
  },
  /// Bless-broker: approve a pending expansion by nonce. Killing the
  /// session's workers and re-forking the agent in a wider envelope is
  /// daemon-side (trust floor coupling); the caller just reports.
  BlessApprove {
    nonce: String,
  },
  /// Bless-broker: reject a pending expansion by nonce.
  BlessReject {
    nonce: String,
  },
  /// Assemble a ProofCertificate for a session (daemon-as-verifier).
  Cert {
    session: SessionId,
  },
  /// Forensic replay: re-classify a session's recorded events against a
  /// narrower envelope (permissive-case delta).
  Replay {
    session: SessionId,
    narrower_project: PathBuf,
  },
  /// HV radar (opt-in): encode a session's events, fold into the
  /// project prototype, report the cosine + anomaly flag.
  Radar {
    session: SessionId,
    project: PathBuf,
  },
  /// N5: sibling detector — report known harness processes running
  /// without the CASTELLAN_SESSION tag (advisory).
  Siblings,
  /// N1: campaign detector — cross-session slow-drip attack detection
  /// over the project's trust-event stream (advisory, silent tier).
  Campaign {
    project: PathBuf,
  },
  /// P8: run the live-fire drill suite now (manual trigger).
  DrillRun,
  /// P8: report the last drill results.
  DrillStatus,
  /// P8.1: immune memory — recall a response for a session's telemetry
  /// window (advisory; the memory never auto-enforces).
  MemoryRecall {
    session: SessionId,
  },
  /// P8.1: immune memory — status (writes, activations, self shapes).
  MemoryStatus,
  /// P8.3: acoustic channel — approve a pending bless request by
  /// spoken nonce. The utterance is the STT-transcribed human voice
  /// (or the typed fallback); the daemon matches it against the
  /// voice session's nonce under the constrained grammar.
  VoiceApprove {
    session: SessionId,
    utterance: String,
  },
  /// P9.1: exfil channel census — run the D6 drill now (manual
  /// trigger) and return the kernel-verified channel inventory.
  ChannelsRun,
  /// P9.1: report the last channel census results.
  ChannelsStatus,
  /// P9.3: cross-session contact tracing — sessions that wrote files
  /// the compromised session wrote AFTER it did (exposure scored,
  /// freeze offered, human decides).
  TraceExpose {
    compromised: SessionId,
  },
  /// P9.6: policy regression replay — replay kept-session spines
  /// through a CANDIDATE policy before it lands (false-NEW-denies
  /// only, advisory at release time).
  PolicyCheck {
    project: PathBuf,
    candidate_project: PathBuf,
  },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
  pub ok: bool,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub error: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub sessions: Option<Vec<SessionReport>>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub message: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  pub extra: Option<serde_json::Value>,
}

impl Response {
  pub fn ok() -> Self {
    Self { ok: true, error: None, sessions: None, message: None, extra: None }
  }

  pub fn err(msg: impl Into<String>) -> Self {
    Self { ok: false, error: Some(msg.into()), sessions: None, message: None, extra: None }
  }

  pub fn with_sessions(mut self, sessions: Vec<SessionReport>) -> Self {
    self.sessions = Some(sessions);
    self
  }

  pub fn with_message(mut self, msg: impl Into<String>) -> Self {
    self.message = Some(msg.into());
    self
  }

  pub fn with_extra(mut self, key: &str, value: serde_json::Value) -> Self {
    use serde_json::Value;
    match &mut self.extra {
      Some(Value::Object(map)) => {
        map.insert(key.to_string(), value);
      }
      _ => {
        let mut map = serde_json::Map::new();
        map.insert(key.to_string(), value);
        self.extra = Some(Value::Object(map));
      }
    }
    self
  }
}

#[derive(Default)]
pub struct Registry {
  sessions: FxHashMap<SessionId, Session>,
}

impl Registry {
  pub fn get(&self, id: &SessionId) -> Option<&Session> {
    self.sessions.get(id)
  }

  pub fn contains(&self, id: &SessionId) -> bool {
    self.sessions.contains_key(id)
  }

  pub fn insert(&mut self, session: Session) {
    self.sessions.insert(session.id.clone(), session);
  }

  pub fn remove(&mut self, id: &SessionId) -> Option<Session> {
    self.sessions.remove(id)
  }

  pub fn ids(&self) -> Vec<SessionId> {
    self.sessions.keys().cloned().collect()
  }

  pub fn values(&self) -> impl Iterator<Item = &Session> {
    self.sessions.values()
  }

  pub fn len(&self) -> usize {
    self.sessions.len()
  }

  pub fn is_empty(&self) -> bool {
    self.sessions.is_empty()
  }
}

pub fn now_unix() -> u64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
  pub ts: u64,
  pub session: SessionId,
  pub kind: String,
  pub path: String,
  pub verdict: String,
}

pub struct EventSink {
  path: PathBuf,
  session: SessionId,
}

impl EventSink {
  pub fn for_session(state_dir: &Path, session: &str) -> io::Result<Self> {
    let dir = state_dir.join("castellan/events");
    fs::create_dir_all(&dir)?;
    Ok(Self { path: dir.join(format!("{session}.jsonl")), session: session.to_owned() })
  }

  pub fn emit(&self, kind: &str, path: &str, verdict: &str) -> io::Result<()> {
    let ev = Event {
      ts: now_unix(),
      session: self.session.clone(),
      kind: kind.to_owned(),
      path: path.to_owned(),
      verdict: verdict.to_owned(),
    };
    // rotation: a chatty session must not grow the spine unbounded
    // (2MB+ jsonl observed). Rotate to .1 (previous .1 is dropped).
    if let Ok(meta) = fs::metadata(&self.path) {
      if meta.len() > SPINE_MAX_BYTES {
        let _ = fs::rename(&self.path, self.path.with_extension("jsonl.1"));
      }
    }
    let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
    serde_json::to_writer(&mut f, &ev)?;
    f.write_all(b"\n")
  }

  pub fn read_all(&self) -> io::Result<Vec<Event>> {
    let primary = match fs::read_to_string(&self.path) {
      Ok(c) => c,
      Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
      Err(e) => return Err(e),
    };
    // rotated segment first (older events), then the active spine
    let rotated = match fs::read_to_string(self.path.with_extension("jsonl.1")) {
      Ok(c) => c,
      Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
      Err(e) => return Err(e),
    };
    let mut events: Vec<Event> = rotated
      .lines()
      .chain(primary.lines())
      .filter_map(|l| serde_json::from_str(l).ok())
      .collect();
    events.sort_by_key(|e| e.ts);
    Ok(events)
  }
}

/// Spine rotation threshold: 4 MiB per session jsonl.
const SPINE_MAX_BYTES: u64 = 4 << 20;

pub fn new_session_id() -> SessionId {
  static SEQ: AtomicU64 = AtomicU64::new(0);
  let seq = SEQ.fetch_add(1, Ordering::Relaxed);
  let nanos = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_nanos() as u64)
    .unwrap_or(0);
  format!("s{nanos:x}{seq:04x}")
}

/// Bless-broker nonce: 16 random hex bytes. Generated by the daemon,
/// returned to the human's terminal — never to the agent's env.
/// No panics: with panic=abort a daemon must survive entropy failure,
/// so fall back to time+pid+counter hashed through a mixing function.
pub fn new_bless_nonce() -> String {
  let mut buf = [0u8; 16];
  let from_urandom = (|| {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").ok()?;
    f.read_exact(&mut buf).ok()?;
    Some(())
  })()
  .is_some();
  if !from_urandom {
    eprintln!("castellan-core: /dev/urandom unavailable — nonce entropy degraded");
    let nanos = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .map(|d| d.as_nanos() as u64)
      .unwrap_or(0);
    let pid = std::process::id() as u64;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mix = nanos ^ (pid << 32) ^ COUNTER.fetch_add(1, Ordering::Relaxed).wrapping_mul(0x9E3779B97F4A7C15);
    buf[..8].copy_from_slice(&mix.to_le_bytes());
    let mix2 = mix.rotate_left(31) ^ 0xBF58476D1CE4E5B9;
    buf[8..].copy_from_slice(&mix2.to_le_bytes());
  }
  buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// Stable per-project key (canonicalized path sha256). Single
/// implementation shared by trust/radar/certificate storage (S2
/// audit fix: three copies had drifted risk).
pub fn project_key(realpath: &Path) -> String {
  use sha2::{Digest, Sha256};
  let canon = realpath.canonicalize().unwrap_or_else(|_| realpath.to_path_buf());
  let digest = Sha256::digest(canon.to_string_lossy().as_bytes());
  digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn high_confidence_signals_freeze() {
    assert_eq!(response_tier("canary_trip"), ResponseTier::Freeze);
    assert_eq!(response_tier("hard_deny"), ResponseTier::Freeze);
    assert_eq!(response_tier("membership_drift"), ResponseTier::Freeze);
  }

  #[test]
  fn low_confidence_signals_are_silent() {
    assert_eq!(response_tier("radar_anomaly"), ResponseTier::Silent);
    assert_eq!(response_tier("would_deny"), ResponseTier::Silent);
    assert_eq!(response_tier("harness_drift"), ResponseTier::Silent);
  }

  #[test]
  fn unknown_signals_default_to_silent() {
    assert_eq!(response_tier("something_new"), ResponseTier::Silent);
  }
}
