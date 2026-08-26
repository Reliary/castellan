use castellan_core::{FreezeState, SessionId};
use rustc_hash::FxHashMap;
use std::fs;
use std::io;
use std::path::PathBuf;

pub struct CgroupRoot {
  base: PathBuf,
}

fn user_slice_base() -> Option<PathBuf> {
  let uid = unsafe { libc::getuid() };
  let unified = PathBuf::from("/sys/fs/cgroup");
  let candidate = unified.join(format!("user.slice/user-{uid}.slice/user@{uid}.service"));
  if candidate.is_dir() { Some(candidate) } else { None }
}

impl CgroupRoot {
  pub fn detect() -> io::Result<Self> {
    let base = user_slice_base().ok_or_else(|| {
      io::Error::new(io::ErrorKind::NotFound, "cgroup v2 user slice not found")
    })?;
    Ok(Self { base })
  }

  pub fn session_dir(&self, session: &SessionId) -> PathBuf {
    self.base.join("castellan.slice").join(format!("{session}.scope"))
  }

  pub fn create_session(&self, session: &SessionId) -> io::Result<PathBuf> {
    let dir = self.session_dir(session);
    fs::create_dir_all(&dir)?;
    Ok(dir)
  }

  pub fn destroy_session(&self, session: &SessionId) -> io::Result<()> {
    let dir = self.session_dir(session);
    match fs::remove_dir(&dir) {
      Ok(()) => Ok(()),
      Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
      Err(e) => Err(e),
    }
  }

  pub fn write_procs(&self, session: &SessionId, pids: &[u32]) -> io::Result<usize> {
    let procs = self.session_dir(session).join("cgroup.procs");
    let mut moved = 0usize;
    for pid in pids {
      match fs::write(&procs, format!("{pid}\n")) {
        Ok(()) => moved += 1,
        Err(_) => continue,
      }
      let _ = descendants_of(*pid);
    }
    Ok(moved)
  }

  pub fn set_freeze(&self, session: &SessionId, freeze: bool) -> io::Result<FreezeState> {
    let dir = self.session_dir(session);
    let file = dir.join("cgroup.freeze");
    fs::write(&file, if freeze { b"1\n" } else { b"0\n" })?;
    for _ in 0..20 {
      let state = self.freeze_state(session)?;
      let settled = if freeze {
        state == FreezeState::Frozen
      } else {
        state == FreezeState::Thawed
      };
      if settled {
        return Ok(state);
      }
      std::thread::sleep(std::time::Duration::from_millis(10));
    }
    self.freeze_state(session)
  }

  pub fn kill_all(&self, session: &SessionId) -> io::Result<usize> {
    let dir = self.session_dir(session);
    let procs_path = dir.join("cgroup.procs");
    let content = fs::read_to_string(&procs_path)?;
    let mut killed = 0usize;
    for line in content.lines() {
      if let Ok(pid) = line.trim().parse::<i32>() {
        unsafe {
          if libc::kill(pid, libc::SIGKILL) == 0 {
            killed += 1;
          }
        }
      }
    }
    Ok(killed)
  }

  pub fn freeze_state(&self, session: &SessionId) -> io::Result<FreezeState> {
    let dir = self.session_dir(session);
    let events = match fs::read_to_string(dir.join("cgroup.events")) {
      Ok(e) => e,
      Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(FreezeState::Missing),
      Err(e) => return Err(e),
    };
    for line in events.lines() {
      if let Some(v) = line.strip_prefix("frozen ") {
        return Ok(if v.trim() == "1" { FreezeState::Frozen } else { FreezeState::Thawed });
      }
    }
    Ok(FreezeState::Thawed)
  }

  pub fn populate_count(&self, session: &SessionId) -> usize {
    fs::read_to_string(self.session_dir(session).join("cgroup.procs"))
      .map(|c| c.lines().filter(|l| !l.trim().is_empty()).count())
      .unwrap_or(0)
  }
}

fn descendants_of(root: u32) -> Vec<u32> {
  let mut out = Vec::new();
  let mut stack = vec![root];
  let mut seen: FxHashMap<u32, ()> = FxHashMap::default();
  while let Some(pid) = stack.pop() {
    if seen.contains_key(&pid) || out.len() > 4096 {
      continue;
    }
    seen.insert(pid, ());
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
      Ok(s) => s,
      Err(_) => continue,
    };
    let ppid: u32 = match parse_ppid(&stat) {
      Some(p) => p,
      None => continue,
    };
    if ppid == root && ppid != pid {
      out.push(pid);
      stack.push(pid);
    }
  }
  out
}

fn parse_ppid(stat: &str) -> Option<u32> {
  let close = stat.rfind(')')?;
  let mut rest = stat[close + 1..].split_whitespace();
  let _state = rest.next()?;
  rest.next().and_then(|p| p.parse().ok())
}
