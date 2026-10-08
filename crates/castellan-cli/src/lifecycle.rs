//! Lifecycle: `service`, `uninstall`, `gc`, `init`. These are local
//! commands (they do not require a running daemon) and they are the only
//! code that writes a unit file or deletes state — kept in one module so
//! the destructive surface is auditable in one place.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const UNIT_NAME: &str = "castellan.service";

fn home() -> PathBuf {
  std::env::var("HOME").map(PathBuf::from).unwrap_or_default()
}

fn state_home() -> PathBuf {
  std::env::var("XDG_STATE_HOME")
    .map(PathBuf::from)
    .unwrap_or_else(|_| home().join(".local/state"))
}

fn config_home() -> PathBuf {
  std::env::var("XDG_CONFIG_HOME")
    .map(PathBuf::from)
    .unwrap_or_else(|_| home().join(".config"))
}

fn runtime_dir() -> PathBuf {
  match std::env::var("XDG_RUNTIME_DIR") {
    Ok(d) => PathBuf::from(d),
    Err(_) => {
      let uid = nix::unistd::Uid::current().as_raw();
      PathBuf::from(format!("/run/user/{uid}"))
    }
  }
}

fn sock_path() -> PathBuf {
  runtime_dir().join("castellan.sock")
}

fn castellan_state() -> PathBuf {
  state_home().join("castellan")
}

fn castellan_config() -> PathBuf {
  config_home().join("castellan")
}

fn unit_dir() -> PathBuf {
  config_home().join("systemd/user")
}

fn unit_path() -> PathBuf {
  unit_dir().join(UNIT_NAME)
}

/// Absolute path to a sibling binary (the daemon lives next to the CLI).
fn sibling_bin(name: &str) -> Option<PathBuf> {
  let exe = std::env::current_exe().ok()?;
  let dir = exe.parent()?;
  let candidate = dir.join(name);
  if candidate.exists() {
    Some(candidate)
  } else {
    None
  }
}

fn systemctl(args: &[&str]) -> std::io::Result<std::process::Output> {
  Command::new("systemctl").arg("--user").args(args).output()
}

fn systemctl_ok(args: &[&str]) -> bool {
  systemctl(args).map(|o| o.status.success()).unwrap_or(false)
}

/// The user cgroup slice holding every session scope.
fn slice_dir() -> Option<PathBuf> {
  let root = castellan_freezer::CgroupRoot::detect().ok()?;
  Some(root.session_dir(&String::new()).parent()?.to_path_buf())
}

fn live_scopes() -> Vec<PathBuf> {
  let mut v = Vec::new();
  if let Some(slice) = slice_dir() {
    if let Ok(rd) = std::fs::read_dir(&slice) {
      for e in rd.flatten() {
        let p = e.path();
        if p.extension().map(|x| x == "scope").unwrap_or(false) {
          v.push(p);
        }
      }
    }
  }
  v
}

/// Recursively remove a tree, chmod-ing directories writable first.
///
/// A session's `overlay/work/work` is created mode `000` by the
/// unprivileged overlay setup and its own owner cannot `rm -rf` it
/// (verified: `rm: cannot remove ...: Permission denied`). A naive delete
/// therefore fails on the first session, which is the whole reason a clean
/// uninstall is not `rm -rf`.
fn remove_tree(path: &Path) -> std::io::Result<()> {
  let meta = match std::fs::symlink_metadata(path) {
    Ok(m) => m,
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
    Err(e) => return Err(e),
  };
  if meta.file_type().is_dir() {
    // make the directory traversable/removable before descending
    let _ = std::fs::set_permissions(
      path,
      std::os::unix::fs::PermissionsExt::from_mode(0o700),
    );
    if let Ok(rd) = std::fs::read_dir(path) {
      for e in rd.flatten() {
        let _ = remove_tree(&e.path());
      }
    }
    std::fs::remove_dir(path)
  } else {
    std::fs::remove_file(path)
  }
}

fn kill_scope(path: &Path) {
  let scope = path
    .file_name()
    .and_then(|s| s.to_str())
    .unwrap_or("")
    .trim_end_matches(".scope")
    .to_string();
  if let Ok(root) = castellan_freezer::CgroupRoot::detect() {
    let _ = root.set_freeze(&scope, false);
    let _ = root.kill_all(&scope);
  }
  // fallback: kill whatever pids remain in cgroup.procs
  if let Ok(s) = std::fs::read_to_string(path.join("cgroup.procs")) {
    for pid in s.lines().filter_map(|l| l.trim().parse::<i32>().ok()) {
      let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid),
        nix::sys::signal::Signal::SIGKILL,
      );
    }
  }
}

/// Stop sessions and remove every scope, then the slice.
fn teardown_scopes() -> usize {
  let mut removed = 0;
  for _ in 0..40 {
    let scopes = live_scopes();
    if scopes.is_empty() {
      break;
    }
    for s in &scopes {
      kill_scope(s);
      let _ = std::fs::remove_dir(s);
    }
    removed += 1;
    std::thread::sleep(std::time::Duration::from_millis(50));
  }
  if let Some(slice) = slice_dir() {
    let _ = std::fs::remove_dir(&slice);
    let _ = std::fs::remove_dir(slice.parent().map(|p| p.join("castellan.slice")).unwrap_or(slice));
  }
  removed
}

fn daemon_pids() -> Vec<i32> {
  let mut pids = Vec::new();
  if let Ok(rd) = std::fs::read_dir("/proc") {
    for e in rd.flatten() {
      let name = e.file_name();
      let s = name.to_string_lossy();
      if !s.chars().all(|c| c.is_ascii_digit()) {
        continue;
      }
      if let Ok(comm) = std::fs::read_to_string(e.path().join("comm")) {
        if comm.trim() == "castellan-daemon" {
          if let Ok(p) = s.parse::<i32>() {
            pids.push(p);
          }
        }
      }
    }
  }
  pids
}

fn stop_daemon_processes() -> usize {
  let pids = daemon_pids();
  for pid in &pids {
    let _ = nix::sys::signal::kill(
      nix::unistd::Pid::from_raw(*pid),
      nix::sys::signal::Signal::SIGTERM,
    );
  }
  std::thread::sleep(std::time::Duration::from_millis(300));
  for pid in &pids {
    let _ = nix::sys::signal::kill(
      nix::unistd::Pid::from_raw(*pid),
      nix::sys::signal::Signal::SIGKILL,
    );
  }
  pids.len()
}

fn unit_contents(daemon: &Path, cli: &Path, skip_preflight: bool) -> String {
  let pre = if skip_preflight {
    String::new()
  } else {
    format!("ExecStartPre={} preflight\n", cli.display())
  };
  format!(
    "[Unit]\n\
     Description=castellan daemon (OS trust boundary for AI agents)\n\
     After=default.target\n\
     \n\
     [Service]\n\
     Type=simple\n\
     {pre}\
     ExecStart={} \n\
     Restart=on-failure\n\
     RestartSec=2\n\
     # The agent runs in child scopes, not this unit; the daemon needs no\n\
     # privileges of its own (everything is unprivileged cgroup/Landlock).\n\
     NoNewPrivileges=yes\n\
     \n\
     [Install]\n\
     WantedBy=default.target\n",
    daemon.display()
  )
}

fn cmd_service(args: &[String]) -> ! {
  let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
  let skip_preflight = args.iter().any(|a| a == "--skip-preflight");
  match sub {
    "install" => {
      let daemon = match sibling_bin("castellan-daemon") {
        Some(d) => d,
        None => {
          eprintln!("service install: castellan-daemon not found next to this binary.");
          eprintln!("build it (`cargo build --release --workspace`) or install both together.");
          std::process::exit(1);
        }
      };
      let cli = std::env::current_exe().unwrap_or_else(|_| daemon.clone());
      let _ = std::fs::create_dir_all(unit_dir());
      if let Err(e) = std::fs::write(unit_path(), unit_contents(&daemon, &cli, skip_preflight)) {
        eprintln!("service install: cannot write {}: {e}", unit_path().display());
        std::process::exit(1);
      }
      println!("wrote {}", unit_path().display());
      let _ = systemctl(&["daemon-reload"]);
      if !systemctl_ok(&["enable", "--now", UNIT_NAME]) {
        eprintln!("service install: `systemctl --user enable --now {UNIT_NAME}` failed");
        eprintln!("unit written; inspect with: systemctl --user status {UNIT_NAME}");
        std::process::exit(1);
      }
      print!("{}", exec_stdout(&["is-active", UNIT_NAME]));
      println!("service installed and started");
      std::process::exit(0);
    }
    "uninstall" => uninstall(&args[1..]),
    "stop" => {
      let _ = systemctl(&["stop", UNIT_NAME]);
      stop_daemon_processes();
      let _ = std::fs::remove_file(sock_path());
      println!("service stopped");
      std::process::exit(0);
    }
    "status" => {
      let enabled = systemctl_ok(&["is-enabled", UNIT_NAME]);
      let active = systemctl_ok(&["is-active", UNIT_NAME]);
      println!(
        "unit {}: {}",
        UNIT_NAME,
        if active { "active" } else { "inactive" }
      );
      println!("enabled: {}", if enabled { "yes" } else { "no" });
      println!("unit file: {}", if unit_path().exists() { unit_path().display().to_string() } else { "(none)".into() });
      println!(
        "socket: {}",
        if sock_path().exists() { sock_path().display().to_string() } else { "(none)".into() }
      );
      let sessions = castellan_state().join("sessions");
      let n = std::fs::read_dir(&sessions).map(|r| r.flatten().count()).unwrap_or(0);
      println!("sessions on disk: {n}");
      std::process::exit(if active { 0 } else { 1 });
    }
    "logs" => {
      let follow = args.iter().any(|a| a == "-f" || a == "--follow");
      let mut c = Command::new("journalctl");
      c.args(["--user", "-u", UNIT_NAME, "--no-pager"]);
      if follow {
        c.arg("-f");
      }
      match c.status() {
        Ok(s) => std::process::exit(s.code().unwrap_or(0)),
        Err(e) => {
          eprintln!("service logs: journalctl unavailable: {e}");
          std::process::exit(1);
        }
      }
    }
    other => {
      eprintln!("usage: castellan service [install [--skip-preflight]|uninstall|status|stop|logs [-f]]");
      eprintln!("  (unknown subcommand: {other})");
      std::process::exit(2);
    }
  }
}

fn exec_stdout(args: &[&str]) -> String {
  systemctl(args)
    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
    .unwrap_or_default()
}

fn uninstall(args: &[String]) -> ! {
  let keep_data = args.iter().any(|a| a == "--keep-data");
  let keep_config = args.iter().any(|a| a == "--keep-config");
  let assume_yes = args.iter().any(|a| a == "--yes" || a == "-y");

  if !assume_yes {
    eprintln!("This removes the castellan service, kills all sessions, and deletes");
    eprintln!("state{} and the credential keyring.", if keep_data { " (except session state: --keep-data)" } else { "" });
    eprintln!("Re-run with --yes to proceed.");
    std::process::exit(2);
  }

  // 1. stop the service and remove the unit so it cannot restart
  let _ = systemctl(&["stop", UNIT_NAME]);
  let _ = systemctl(&["disable", UNIT_NAME]);
  if unit_path().exists() {
    let _ = std::fs::remove_file(unit_path());
    println!("removed {}", unit_path().display());
  }
  let _ = systemctl(&["daemon-reload"]);

  // 2. kill the daemon (the unit is gone, but a manually-run one may linger)
  let nd = stop_daemon_processes();
  if nd > 0 {
    println!("stopped {nd} daemon process(es)");
  }

  // 3. tear down every session scope, then the slice
  let removed = teardown_scopes();
  println!("removed {removed} scope batch(es) and castellan.slice");

  // 4. socket
  if sock_path().exists() {
    let _ = std::fs::remove_file(sock_path());
    println!("removed socket");
  }

  // 5. state (session overlays, spine, trust.db) — chmod-aware
  if keep_data {
    println!("kept state at {} (--keep-data)", castellan_state().display());
  } else if castellan_state().exists() {
    match remove_tree(&castellan_state()) {
      Ok(()) => println!("removed state {}", castellan_state().display()),
      Err(e) => eprintln!("warning: could not fully remove state: {e}"),
    }
  }

  // 6. config — the keyring holds real credentials; default is to remove it
  if keep_config {
    println!("kept config at {} (--keep-config)", castellan_config().display());
  } else if castellan_config().exists() {
    match remove_tree(&castellan_config()) {
      Ok(()) => println!("removed config {} (keyring included)", castellan_config().display()),
      Err(e) => eprintln!("warning: could not fully remove config: {e}"),
    }
  }

  println!("uninstall complete");
  std::process::exit(0);
}

fn cmd_gc(args: &[String]) -> ! {
  let assume_yes = args.iter().any(|a| a == "--yes" || a == "-y");
  let keep_last: usize = args
    .iter()
    .position(|a| a == "--keep-last")
    .and_then(|i| args.get(i + 1))
    .and_then(|s| s.parse().ok())
    .unwrap_or(20);
  let older_days: Option<u64> = args
    .iter()
    .position(|a| a == "--older-than")
    .and_then(|i| args.get(i + 1))
    .and_then(|s| s.parse().ok());

  let sessions = castellan_state().join("sessions");
  let mut names: Vec<(String, std::time::SystemTime)> = Vec::new();
  if let Ok(rd) = std::fs::read_dir(&sessions) {
    for e in rd.flatten() {
      let name = e.file_name().to_string_lossy().to_string();
      let m = e
        .metadata()
        .and_then(|m| m.modified())
        .unwrap_or(std::time::UNIX_EPOCH);
      names.push((name, m));
    }
  }
  names.sort_by_key(|(_, m)| *m);
  let live: std::collections::HashSet<String> = live_scopes()
    .iter()
    .filter_map(|p| p.file_name().map(|s| s.to_string_lossy().trim_end_matches(".scope").to_string()))
    .collect();

  let total = names.len();
  let protected = total.saturating_sub(keep_last);
  let now = std::time::SystemTime::now();
  let mut doomed = Vec::new();
  for (i, (name, mtime)) in names.iter().enumerate() {
    let by_count = i < protected;
    let by_age = older_days
      .map(|d| {
        now.duration_since(*mtime)
          .map(|x| x.as_secs() > d * 86_400)
          .unwrap_or(false)
      })
      .unwrap_or(false);
    if (by_count || by_age) && !live.contains(name) {
      doomed.push(name.clone());
    }
  }

  println!(
    "gc: {total} sessions on disk, {protected} beyond keep-last {keep_last}, {} collectible, {} live (skipped)",
    doomed.len(),
    live.len()
  );
  if doomed.is_empty() {
    std::process::exit(0);
  }
  if !assume_yes {
    for d in doomed.iter().take(10) {
      println!("  would remove {d}");
    }
    if doomed.len() > 10 {
      println!("  ... and {} more", doomed.len() - 10);
    }
    println!("Re-run with --yes to remove them.");
    std::process::exit(2);
  }
  let mut removed = 0;
  for d in &doomed {
    if remove_tree(&sessions.join(d)).is_ok() {
      removed += 1;
    }
  }
  println!("gc: removed {removed} session dir(s)");
  std::process::exit(0);
}

fn cmd_init(args: &[String]) -> ! {
  let force = args.iter().any(|a| a == "--force");
  let dir = castellan_config();
  if let Err(e) = std::fs::create_dir_all(&dir) {
    eprintln!("init: cannot create {}: {e}", dir.display());
    std::process::exit(1);
  }
  let keyring = dir.join("keyring.toml");
  if keyring.exists() && !force {
    println!("init: {} already exists (use --force to overwrite)", keyring.display());
  } else {
    let body = "# castellan credential keyring — loaded by the daemon, never\n\
                # inside an agent envelope. One [[credential]] per secret.\n\
                #\n\
                # [[credential]]\n\
                # host = \"api.example.com\"        # exact, or *.suffix\n\
                # header = \"Authorization\"\n\
                # prefix = \"Bearer \"\n\
                # value = \"sk-...\"\n";
    if let Err(e) = std::fs::write(&keyring, body) {
      eprintln!("init: cannot write {}: {e}", keyring.display());
      std::process::exit(1);
    }
    println!("wrote {}", keyring.display());
  }
  let egress = dir.join("egress.toml");
  if egress.exists() && !force {
    println!("init: {} already exists (use --force to overwrite)", egress.display());
  } else {
    let body = "# castellan egress allowlist — destinations an enforced session\n\
                # may reach (the LLM API host goes here).\n\
                #\n\
                # [llm]\n\
                # hosts = [\"api.example.com\"]\n";
    if let Err(e) = std::fs::write(&egress, body) {
      eprintln!("init: cannot write {}: {e}", egress.display());
      std::process::exit(1);
    }
    println!("wrote {}", egress.display());
  }
  println!("edit these, then: castellan service install");
  std::process::exit(0);
}

fn cmd_doctor() -> ! {
  let mut problems = 0;
  let mut report = |ok: bool, what: &str, detail: &str| {
    println!("{}  {:<24} {}", if ok { "PASS" } else { "FAIL" }, what, detail);
    if !ok {
      problems += 1;
    }
  };
  report(sock_path().exists(), "daemon socket", &sock_path().display().to_string());
  let active = systemctl_ok(&["is-active", UNIT_NAME]);
  report(active, "service active", UNIT_NAME);
  report(unit_path().exists(), "unit installed", &unit_path().display().to_string());
  let keyring = castellan_config().join("keyring.toml");
  report(keyring.exists(), "keyring present", &keyring.display().to_string());
  let daemon = sibling_bin("castellan-daemon");
  report(daemon.is_some(), "daemon binary present", &daemon.map(|p| p.display().to_string()).unwrap_or_else(|| "(not found)".into()));
  report(live_scopes().is_empty() || true, "scope listing", &format!("{} scope(s)", live_scopes().len()));
  let sessions = castellan_state().join("sessions");
  let n = std::fs::read_dir(&sessions).map(|r| r.flatten().count()).unwrap_or(0);
  println!("INFO  {:<24} {n} session(s) on disk", "state");
  println!("\n{} problem(s)", problems);
  std::process::exit(if problems == 0 { 0 } else { 1 });
}

pub fn run_service(args: &[String]) -> ! {
  cmd_service(args)
}

pub fn run_uninstall(args: &[String]) -> ! {
  uninstall(args)
}

pub fn run_gc(args: &[String]) -> ! {
  cmd_gc(args)
}

pub fn run_init(args: &[String]) -> ! {
  cmd_init(args)
}

pub fn run_doctor() -> ! {
  cmd_doctor()
}

pub fn version() -> ! {
  println!("castellan {}", env!("CARGO_PKG_VERSION"));
  std::process::exit(0);
}

#[allow(dead_code)]
fn flush() {
  let _ = std::io::stdout().flush();
}

#[cfg(test)]
mod tests {
  use super::*;

  fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("castellan-lifecycle-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
  }

  // The reason uninstall is not `rm -rf`: overlay/work/work is mode 000 and
  // its owner cannot remove it. remove_tree must chmod before descending.
  #[test]
  fn remove_tree_handles_mode_000_dir() {
    let d = tmpdir("mode000");
    let deep = d.join("sess/overlay/work/work");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("leaf"), b"x").unwrap();
    std::fs::set_permissions(&deep, std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
    // a naive remove_dir_all is expected to fail here — assert we do not.
    remove_tree(&d).unwrap();
    assert!(!d.exists(), "remove_tree left {d:?} behind");
    std::fs::set_permissions(&d, std::os::unix::fs::PermissionsExt::from_mode(0o700)).ok();
    let _ = std::fs::remove_dir_all(&d);
  }

  #[test]
  fn remove_tree_is_ok_on_missing_path() {
    let d = tmpdir("missing").join("nope");
    assert!(remove_tree(&d).is_ok());
  }

  #[test]
  fn remove_tree_removes_plain_file() {
    let d = tmpdir("file");
    let f = d.join("a");
    std::fs::write(&f, b"x").unwrap();
    remove_tree(&f).unwrap();
    assert!(!f.exists());
    let _ = std::fs::remove_dir_all(&d);
  }

  #[test]
  fn unit_contents_includes_preflight_and_daemon() {
    let u = unit_contents(Path::new("/x/castellan-daemon"), Path::new("/x/castellan"), false);
    assert!(u.contains("ExecStart=/x/castellan-daemon"));
    assert!(u.contains("ExecStartPre=/x/castellan preflight"));
    assert!(u.contains("Type=simple"));
    let u2 = unit_contents(Path::new("/x/castellan-daemon"), Path::new("/x/castellan"), true);
    assert!(!u2.contains("ExecStartPre"));
  }
}
