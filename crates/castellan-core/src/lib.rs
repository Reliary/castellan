use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub type SessionId = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
  pub id: SessionId,
  pub harness: String,
  pub project: PathBuf,
  pub scope_path: PathBuf,
  #[serde(default)]
  pub frozen: bool,
  pub started_at: u64,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
  Spawn {
    harness: String,
    project: PathBuf,
    pid: Option<u32>,
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
}

impl Response {
  pub fn ok() -> Self {
    Self { ok: true, error: None, sessions: None, message: None }
  }

  pub fn err(msg: impl Into<String>) -> Self {
    Self { ok: false, error: Some(msg.into()), sessions: None, message: None }
  }

  pub fn with_sessions(mut self, sessions: Vec<SessionReport>) -> Self {
    self.sessions = Some(sessions);
    self
  }

  pub fn with_message(mut self, msg: impl Into<String>) -> Self {
    self.message = Some(msg.into());
    self
  }
}

#[derive(Default)]
pub struct Registry(pub FxHashMap<SessionId, Session>);

pub fn now_unix() -> u64 {
  std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_secs())
    .unwrap_or(0)
}

pub fn new_session_id() -> SessionId {
  let nanos = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.subsec_nanos() as u64 + d.as_secs())
    .unwrap_or(0);
  let pid = std::process::id();
  format!("s{:x}{:04x}", nanos, (pid & 0xffff) as u16)
}
