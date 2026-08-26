use castellan_core::{FreezeState, SessionId};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

pub struct CgroupRoot {
  base: PathBuf,
}

fn user_slice_base() -> Option<PathBuf> {
  let uid = nix::unistd::Uid::current().as_raw();
  let unified = PathBuf::from("/sys/fs/cgroup");
  let candidate = unified.join(format!("user.slice/user-{uid}.slice/user@{uid}.service"));
  candidate.is_dir().then_some(candidate)
}

impl CgroupRoot {
  pub fn detect() -> io::Result<Self> {
    user_slice_base()
      .map(|base| Self { base })
      .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "cgroup v2 user slice not found"))
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
    match fs::remove_dir(self.session_dir(session)) {
      Ok(()) => Ok(()),
      Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
      Err(e) => Err(e),
    }
  }

  pub fn write_procs(&self, session: &SessionId, pids: &[u32]) -> io::Result<usize> {
    let procs = self.session_dir(session).join("cgroup.procs");
    let mut file = OpenOptions::new().append(true).open(&procs)?;
    let mut moved = 0usize;
    for pid in pids {
      if file.write_all(format!("{pid}\n").as_bytes()).is_ok() {
        moved += 1;
      }
    }
    file.flush()?;
    Ok(moved)
  }

  pub fn set_freeze(&self, session: &SessionId, freeze: bool) -> io::Result<FreezeState> {
    fs::write(
      self.session_dir(session).join("cgroup.freeze"),
      if freeze { b"1\n" as &[u8] } else { b"0\n" },
    )?;
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
    let content = fs::read_to_string(self.session_dir(session).join("cgroup.procs"))?;
    let killed = content
      .lines()
      .filter_map(|l| l.trim().parse::<i32>().ok())
      .filter(|&pid| {
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::Signal::SIGKILL)
          .is_ok()
      })
      .count();
    Ok(killed)
  }

  pub fn freeze_state(&self, session: &SessionId) -> io::Result<FreezeState> {
    let events = match fs::read_to_string(self.session_dir(session).join("cgroup.events")) {
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
