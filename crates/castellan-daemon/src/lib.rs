use castellan_core::{
  now_unix, new_session_id, FreezeState, Registry, Request, Response, Session, SessionId,
  SessionReport,
};
use castellan_freezer::CgroupRoot;
use rustc_hash::FxHashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct DaemonHandle {
  root: Arc<CgroupRoot>,
  registry: Arc<Mutex<Registry>>,
  freezer_owner: Arc<Mutex<FxHashMap<SessionId, ()>>>,
}

impl DaemonHandle {
  fn new() -> std::io::Result<Self> {
    Ok(Self {
      root: Arc::new(CgroupRoot::detect()?),
      registry: Arc::new(Mutex::new(Registry::default())),
      freezer_owner: Arc::new(Mutex::new(FxHashMap::default())),
    })
  }

  fn serve(&self) -> std::io::Result<()> {
    let path = Daemon::socket_path();
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
          std::thread::spawn(move || {
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
      let n = reader.read_line(&mut line)?;
      if n == 0 {
        return Ok(());
      }
      let resp = match serde_json::from_str::<Request>(line.trim()) {
        Ok(req) => self.dispatch(req),
        Err(e) => Response::err(format!("bad request: {e}")),
      };
      let mut out = serde_json::to_string(&resp)?;
      out.push('\n');
      (&stream).write_all(out.as_bytes())?;
      if matches!(line.trim(), "quit" | "exit") {
        return Ok(());
      }
    }
  }

  fn dispatch(&self, req: Request) -> Response {
    match req {
      Request::Spawn { harness, project, pid } => self.spawn(harness, project, pid),
      Request::Adopt { session, pids } => self.adopt(session, pids),
      Request::Freeze { session } => self.freeze(session, true),
      Request::Thaw { session } => self.freeze(session, false),
      Request::Kill { session } => self.kill(session),
      Request::Status => self.status(),
    }
  }

  fn spawn(&self, harness: String, project: std::path::PathBuf, pid: Option<u32>) -> Response {
    let id = new_session_id();
    match self.root.create_session(&id) {
      Ok(_) => {}
      Err(e) => return Response::err(format!("cgroup create failed: {e}")),
    }
    if let Some(pid) = pid {
      if let Err(e) = self.root.write_procs(&id, &[pid]) {
        let _ = self.root.destroy_session(&id);
        return Response::err(format!("failed to move pid into scope: {e}"));
      }
    }
    let session = Session {
      id: id.clone(),
      harness,
      project,
      scope_path: self.root.session_dir(&id),
      frozen: false,
      started_at: now_unix(),
    };
    self.registry.lock().unwrap().0.insert(id.clone(), session);
    self.freezer_owner.lock().unwrap().insert(id.clone(), ());
    Response::ok().with_message(format!("spawned session {id}"))
  }

  fn adopt(&self, session: SessionId, pids: Vec<u32>) -> Response {
    let reg = self.registry.lock().unwrap();
    match reg.0.get(&session) {
      Some(_) => {}
      None => return Response::err(format!("unknown session {session}")),
    }
    drop(reg);
    match self.root.write_procs(&session, &pids) {
      Ok(n) => Response::ok().with_message(format!("adopted {n} pids into {session}")),
      Err(e) => Response::err(format!("adopt failed: {e}")),
    }
  }

  fn freeze(&self, session: Option<SessionId>, freeze: bool) -> Response {
    let targets = self.resolve_targets(session);
    if targets.is_empty() {
      return Response::ok()
        .with_message(if freeze { "no sessions to freeze" } else { "no sessions to thaw" })
        .with_sessions(self.reports());
    }
    let mut msgs = Vec::new();
    for id in targets {
      match self.root.set_freeze(&id, freeze) {
        Ok(state) => {
          if let Some(s) = self.registry.lock().unwrap().0.get_mut(&id) {
            s.frozen = state == FreezeState::Frozen;
          }
          msgs.push(format!("{id}: {}", state.as_str()));
        }
        Err(e) => msgs.push(format!("{id}: error {e}")),
      }
    }
    Response::ok().with_message(msgs.join(", ")).with_sessions(self.reports())
  }

  fn kill(&self, session: Option<SessionId>) -> Response {
    let targets = self.resolve_targets(session);
    let mut msgs = Vec::new();
    for id in targets {
      let _ = self.root.set_freeze(&id, false);
      match self.root.kill_all(&id) {
        Ok(n) => msgs.push(format!("{id}: killed {n}")),
        Err(e) => msgs.push(format!("{id}: error {e}")),
      }
      let _ = self.root.destroy_session(&id);
      self.registry.lock().unwrap().0.remove(&id);
      self.freezer_owner.lock().unwrap().remove(&id);
    }
    Response::ok().with_message(if msgs.is_empty() { "nothing to kill".into() } else { msgs.join(", ") }).with_sessions(self.reports())
  }

  fn status(&self) -> Response {
    let ids: Vec<SessionId> = {
      let reg = self.registry.lock().unwrap();
      reg.0.keys().cloned().collect()
    };
    for id in ids {
      let state = self.root.freeze_state(&id).unwrap_or(FreezeState::Missing);
      if state == FreezeState::Missing {
        self.registry.lock().unwrap().0.remove(&id);
        continue;
      }
      if let Some(s) = self.registry.lock().unwrap().0.get_mut(&id) {
        s.frozen = state == FreezeState::Frozen;
      }
    }
    let reports = self.reports();
    let frozen = reports.iter().filter(|r| r.state == FreezeState::Frozen).count();
    Response::ok()
      .with_message(format!(
        "{} session(s), {} frozen",
        reports.len(),
        frozen
      ))
      .with_sessions(reports)
  }

  fn resolve_targets(&self, session: Option<SessionId>) -> Vec<SessionId> {
    match session {
      Some(id) => vec![id],
      None => {
        let reg = self.registry.lock().unwrap();
        reg.0.keys().cloned().collect()
      }
    }
  }

  fn reports(&self) -> Vec<SessionReport> {
    let reg = self.registry.lock().unwrap();
    reg
      .0
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

pub struct Daemon {
  handle: DaemonHandle,
}

impl Daemon {
  pub fn new() -> std::io::Result<Self> {
    Ok(Self { handle: DaemonHandle::new()? })
  }

  pub fn socket_path() -> std::path::PathBuf {
    let runtime = std::env::var("XDG_RUNTIME_DIR")
      .unwrap_or_else(|_| format!("/run/user/{}", unsafe { libc::getuid() }));
    std::path::Path::new(&runtime).join("castellan.sock")
  }

  pub fn serve(&self) -> std::io::Result<()> {
    self.handle.serve()
  }
}

pub fn read_response(stream: &mut UnixStream) -> std::io::Result<String> {
  let mut buf = [0u8; 65536];
  let mut out = Vec::new();
  loop {
    let n = stream.read(&mut buf)?;
    if n == 0 {
      break;
    }
    out.extend_from_slice(&buf[..n]);
    if out.ends_with(b"\n") || out.iter().any(|&b| b == b'\n') {
      break;
    }
  }
  Ok(String::from_utf8_lossy(&out).trim().to_string())
}
