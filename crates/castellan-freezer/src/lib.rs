use castellan_core::{FreezeState, SessionId};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
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
    // P8 fault injection: the D5 drill must fail loudly when the
    // freezer is muted. Test-only, env-gated.
    if std::env::var("CASTELLAN_TEST_DISABLE_FREEZE").is_ok() {
      return Ok(FreezeState::Thawed);
    }
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

  /// Orphan census (N6): processes started during the session window
  /// whose direct parent is the user manager and whose cgroup is
  /// outside the session scope. These escaped the session cgroup via
  /// the user manager (systemd-run) and are invisible to freeze/kill.
  /// Bounds the blast radius to the session window; not a guarantee.
  pub fn orphan_census(&self, session: &SessionId, session_start_unix: u64) -> Vec<u32> {
    // fault injection (P8 drill suite): the census is disabled, so the
    // D1 drill must fail loudly. Env-gated, daemon-launcher-only.
    if std::env::var("CASTELLAN_TEST_DISABLE_CENSUS").is_ok() {
      return Vec::new();
    }
    let scope = self.session_dir(session);
    let scope_str = scope.to_string_lossy().to_string();
    // the user manager is the direct parent of escaped processes; scan
    // /proc for it rather than assuming the daemon's own parent is the
    // user manager (true only when the daemon runs as a user service)
    let user_mgr = user_manager_pid().unwrap_or_else(|| nix::unistd::getppid().as_raw() as u32);
    let btime = proc_btime();
    let hz = nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK)
      .ok()
      .flatten()
      .map(|h| h as u64)
      .unwrap_or(100);
    let mut orphans = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
      for entry in entries.flatten() {
        let name = entry.file_name();
        let pid: u32 = match name.to_string_lossy().parse() {
          Ok(p) => p,
          Err(_) => continue,
        };
        let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
          Ok(s) => s,
          Err(_) => continue,
        };
        // comm may contain spaces/parens; parse from the last ')'
        let Some(rest) = stat.rsplit_once(')') else { continue };
        let fields: Vec<&str> = rest.1.split_whitespace().collect();
        // after comm: state(1) ppid(2) ... starttime(20) -> index 19
        let (Some(ppid), Some(start_ticks)) = (
          fields.get(1).and_then(|f| f.parse::<i32>().ok()),
          fields.get(19).and_then(|f| f.parse::<u64>().ok()),
        ) else {
          continue;
        };
        if ppid as u32 != user_mgr {
          continue;
        }
        let start_unix = btime + start_ticks.div_ceil(hz);
        if start_unix < session_start_unix {
          continue;
        }
        let cg = match fs::read_to_string(format!("/proc/{pid}/cgroup")) {
          Ok(c) => c,
          Err(_) => continue,
        };
        if cg.contains(&scope_str) {
          continue;
        }
        orphans.push(pid);
      }
    }
    orphans
  }

  pub fn kill_pids(&self, pids: &[u32]) -> usize {
    pids
      .iter()
      .filter(|&&pid| {
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), nix::sys::signal::Signal::SIGKILL)
          .is_ok()
      })
      .count()
  }
}

fn proc_btime() -> u64 {
  fs::read_to_string("/proc/stat")
    .ok()
    .and_then(|s| {
      s.lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse().ok())
    })
    .unwrap_or(0)
}

/// Find the user manager (systemd --user) pid: the process whose
/// parent is pid 1, whose comm is "systemd", and whose uid matches
/// ours. Escaped processes (systemd-run) are direct children of it.
fn user_manager_pid() -> Option<u32> {
  let uid = nix::unistd::Uid::current().as_raw();
  let entries = fs::read_dir("/proc").ok()?;
  for entry in entries.flatten() {
    let name = entry.file_name();
    let pid: u32 = match name.to_string_lossy().parse() {
      Ok(p) => p,
      Err(_) => continue,
    };
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
      Ok(s) => s,
      Err(_) => continue,
    };
    let Some(rest) = stat.rsplit_once(')') else { continue };
    let fields: Vec<&str> = rest.1.split_whitespace().collect();
    let (Some(ppid), Some(state)) = (fields.get(1).and_then(|f| f.parse::<i32>().ok()), fields.get(0)) else {
      continue;
    };
    if ppid != 1 || *state != "S" {
      continue;
    }
    let comm = match fs::read_to_string(format!("/proc/{pid}/comm")) {
      Ok(c) => c,
      Err(_) => continue,
    };
    if comm.trim() != "systemd" {
      continue;
    }
    let uid_ok = fs::metadata(format!("/proc/{pid}")).map(|m| m.uid() == uid).unwrap_or(false);
    if uid_ok {
      return Some(pid);
    }
  }
  None
}
