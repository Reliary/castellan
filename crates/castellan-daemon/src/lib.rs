use castellan_core::{
  new_session_id, FreezeState, Registry, Request, Response, Session, SessionId, SessionReport,
};
use castellan_freezer::CgroupRoot;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Daemon {
  root: Arc<CgroupRoot>,
  registry: Arc<Mutex<Registry>>,
}

impl Daemon {
  pub fn new() -> std::io::Result<Self> {
    Ok(Self {
      root: Arc::new(CgroupRoot::detect()?),
      registry: Arc::new(Mutex::new(Registry::default())),
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
    self.registry.lock().unwrap().insert(Session { id: id.clone(), harness, project });
    Response::ok().with_message(format!("spawned session {id}"))
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
