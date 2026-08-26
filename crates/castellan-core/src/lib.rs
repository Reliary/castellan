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
    let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
    serde_json::to_writer(&mut f, &ev)?;
    f.write_all(b"\n")
  }

  pub fn read_all(&self) -> io::Result<Vec<Event>> {
    let content = match fs::read_to_string(&self.path) {
      Ok(c) => c,
      Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
      Err(e) => return Err(e),
    };
    Ok(content.lines().filter_map(|l| serde_json::from_str(l).ok()).collect())
  }
}

pub fn new_session_id() -> SessionId {
  static SEQ: AtomicU64 = AtomicU64::new(0);
  let seq = SEQ.fetch_add(1, Ordering::Relaxed);
  let nanos = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.as_nanos() as u64)
    .unwrap_or(0);
  format!("s{nanos:x}{seq:04x}")
}
