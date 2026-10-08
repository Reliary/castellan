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
     # P20/F11: give up visibly after a burst instead of thrashing the\n\
     # socket against a competing daemon every 2s forever.\n\
     StartLimitBurst=5\n\
     StartLimitIntervalSec=60\n\
     \n\
     [Service]\n\
     Type=simple\n\
     {pre}\
     ExecStart={} \n\
     # P20/C43: the daemon is gone when this runs (any exit — crash,\n\
     # SIGKILL, systemctl stop, restart). Freeze every session scope\n\
     # directly via cgroupfs: no daemon, no registry, no tty gate. Pairs\n\
     # with daemon-side rehydration so thaw works after the restart.\n\
     ExecStopPost={} freeze --daemonless\n\
     # A killed daemon leaves its socket file behind; a stale socket makes
     # `-S` checks lie and clients report ECONNREFUSED against a path
     # that exists. %t is the manager's XDG_RUNTIME_DIR (same dir the
     # daemon binds). `-` = ignore failure (already gone).
     ExecStopPost=-/bin/rm -f %t/castellan.sock\n\
     Restart=on-failure\n\
     RestartSec=2\n\
     # The agent runs in child scopes, not this unit; the daemon needs no\n\
     # privileges of its own (everything is unprivileged cgroup/Landlock).\n\
     NoNewPrivileges=yes\n\
     \n\
     [Install]\n\
     WantedBy=default.target\n",
    daemon.display(),
    cli.display()
  )
}

/// P20.2: freeze every session scope via cgroupfs — no daemon, no
/// registry, no tty gate. Invoked by the unit's ExecStopPost (the daemon
/// is already dead) and available to operators as
/// `castellan freeze --daemonless`.
///
/// F12 surface: an ENVELOPED agent running this cannot write
/// cgroup.freeze — the same Landlock /sys denial that stops a direct
/// write stops this binary it spawns (live-verified EPERM). An
/// UNCONFINED same-uid process can already write cgroup.freeze without
/// this verb. Equal power in both directions: no new capability.
pub fn freeze_all_local() -> ! {
  let scopes = live_scopes();
  if scopes.is_empty() {
    println!("no session scopes to freeze");
    std::process::exit(0);
  }
  let root = match castellan_freezer::CgroupRoot::detect() {
    Ok(r) => r,
    Err(e) => {
      eprintln!("freeze --daemonless: cgroup root unavailable: {e}");
      std::process::exit(1);
    }
  };
  let mut froze = 0u32;
  let mut failed = 0u32;
  for path in &scopes {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
      continue;
    };
    let scope = name.trim_end_matches(".scope").to_string();
    match root.set_freeze(&scope, true) {
      Ok(_) => froze += 1,
      Err(_) => failed += 1,
    }
  }
  println!("froze {froze} session scope(s), {failed} failed");
  std::process::exit(if failed > 0 { 1 } else { 0 });
}

fn cmd_service(args: &[String]) -> ! {
  let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
  let skip_preflight = args.iter().any(|a| a == "--skip-preflight");
  let no_start = args.iter().any(|a| a == "--no-start");
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
      // P20/F4: a manually-run daemon answering the socket would make the
      // unit's daemon exit 3 (singleton) and Restart=on-failure would
      // thrash it against the socket forever. Refuse instead.
      let unit_active = systemctl_ok(&["is-active", UNIT_NAME]);
      if !unit_active && std::os::unix::net::UnixStream::connect(sock_path()).is_ok() {
        eprintln!(
          "service install: a castellan-daemon is already serving {} but it is not",
          sock_path().display()
        );
        eprintln!("systemd-managed (manual run). Stop it first — `castellan service stop`");
        eprintln!("or `pkill -f castellan-daemon` — then re-run install.");
        std::process::exit(1);
      }
      let rollback = |reason: &str| -> ! {
        let _ = systemctl(&["disable", "--now", UNIT_NAME]);
        let _ = std::fs::remove_file(unit_path());
        let _ = systemctl(&["daemon-reload"]);
        eprintln!("service install: {reason}");
        std::process::exit(1);
      };
      let cli = std::env::current_exe().unwrap_or_else(|_| daemon.clone());
      let _ = std::fs::create_dir_all(unit_dir());
      if let Err(e) = std::fs::write(unit_path(), unit_contents(&daemon, &cli, skip_preflight)) {
        eprintln!("service install: cannot write {}: {e}", unit_path().display());
        std::process::exit(1);
      }
      println!("wrote {}", unit_path().display());
      let _ = systemctl(&["daemon-reload"]);
      // P20/F7: systemctl --user is a singleton bound to the MANAGER's
      // config env. A unit written under a shell-set XDG_CONFIG_HOME the
      // manager never saw is invisible (measured on .227). Verify, do not
      // assume — then either start or roll back so no half-state remains.
      let visible = systemctl(&["cat", UNIT_NAME])
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false);
      if !visible {
        rollback(
          "the unit file was written but the user manager cannot see it\n\
         (or the manager is unreachable) — XDG_RUNTIME_DIR/XDG_CONFIG_HOME\n\
         in this shell must match the manager's environment. Unit rolled back.",
        );
      }
      if no_start {
        println!("service installed (not started, --no-start)");
        std::process::exit(0);
      }
      if !systemctl_ok(&["enable", "--now", UNIT_NAME]) {
        rollback(
          "`systemctl --user enable --now` failed (preflight? see\n\
         `journalctl --user -u castellan.service`). Unit rolled back.",
        );
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
        Ok(s) => {
          // journalctl exits 4 for "no entries yet" — a fresh unit, not
          // an error (P20 polish).
          match s.code() {
            Some(0) | Some(4) => std::process::exit(0),
            other => std::process::exit(other.unwrap_or(1)),
          }
        }
        Err(e) => {
          eprintln!("service logs: journalctl unavailable: {e}");
          std::process::exit(1);
        }
      }
    }
    other => {
      eprintln!("usage: castellan service [install [--skip-preflight]|[--no-start]|uninstall|status|stop|logs [-f]]");
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
  // P20/F1: every check must be falsifiable — no `|| true`.
  let sock = sock_path();
  let sock_present = sock.exists();
  let sock_alive = sock_present && std::os::unix::net::UnixStream::connect(&sock).is_ok();
  report(
    sock_alive,
    "daemon socket",
    if sock_present { "present and answering" } else { "absent" },
  );
  let active = systemctl_ok(&["is-active", UNIT_NAME]);
  report(active, "service active", UNIT_NAME);
  let unit_exists = unit_path().exists();
  report(unit_exists, "unit installed", &unit_path().display().to_string());
  // P20/F17: a field unit predating the P20 directives (ExecStopPost
  // freeze, StartLimit) reports "active" while C43 is still open on this
  // box. Regenerate and diff (ExecStartPre ignored: --skip-preflight is a
  // legitimate install variant).
  if unit_exists {
    let installed = std::fs::read_to_string(unit_path()).unwrap_or_default();
    let normalized = |s: &str| -> String {
      s.lines()
        .filter(|l| !l.starts_with("ExecStartPre"))
        .collect::<Vec<_>>()
        .join("\n")
    };
    match sibling_bin("castellan-daemon") {
      Some(daemon) => {
        let cli = std::env::current_exe().unwrap_or_else(|_| daemon.clone());
        let fresh = unit_contents(&daemon, &cli, false);
        let stale = normalized(&installed) != normalized(&fresh);
        report(
          !stale,
          "unit up to date",
          if stale {
            "STALE — re-run `castellan service install`"
          } else {
            "matches generated"
          },
        );
      }
      None => println!("INFO  {:<24} daemon binary missing — cannot check unit freshness", "unit"),
    }
    let exec_start = installed
      .lines()
      .find(|l| l.starts_with("ExecStart="))
      .and_then(|l| l.strip_prefix("ExecStart="))
      .map(|s| s.trim().to_string());
    match exec_start {
      Some(p) => report(std::path::Path::new(&p).exists(), "ExecStart path", &p),
      None => report(false, "ExecStart path", "no ExecStart= line found"),
    }
  }
  let keyring = castellan_config().join("keyring.toml");
  report(keyring.exists(), "keyring present", &keyring.display().to_string());
  let daemon = sibling_bin("castellan-daemon");
  report(
    daemon.is_some(),
    "daemon binary present",
    &daemon.map(|p| p.display().to_string()).unwrap_or_else(|| "(not found)".into()),
  );
  // P20/F16: registry-vs-cgroupfs drift. Live scopes with a reachable
  // daemon but a registry that missed them = rehydration failure (the
  // freeze button would not reach them). Live scopes with NO daemon =
  // the C43 running-unmanaged state.
  let scopes = live_scopes();
  let scope_names: Vec<String> = scopes
    .iter()
    .filter_map(|p| {
      p.file_name()
        .map(|n| n.to_string_lossy().trim_end_matches(".scope").to_string())
    })
    .collect();
  let managed = sock_alive || active;
  report(
    scope_names.is_empty() || managed,
    "scopes managed",
    &format!(
      "{} live scope(s), daemon {}",
      scope_names.len(),
      if managed { "reachable" } else { "UNREACHABLE" }
    ),
  );
  if sock_alive && !scope_names.is_empty() {
    let resp = crate::rpc(&sock.to_string_lossy(), &serde_json::json!({ "op": "status" }));
    let registered: std::collections::HashSet<String> =
      serde_json::from_str::<serde_json::Value>(&resp)
        .ok()
        .and_then(|v| {
          v.get("sessions")
            .and_then(|s| s.as_array())
            .map(|a| {
              a.iter()
                .filter_map(|x| x.get("id").and_then(|i| i.as_str()).map(String::from))
                .collect()
            })
        })
        .unwrap_or_default();
    let missing = scope_names.iter().filter(|s| !registered.contains(*s)).count();
    let detail = if missing == 0 {
      "all live scopes registered".to_string()
    } else {
      format!("{missing} scope(s) NOT in registry — rehydration drift")
    };
    report(missing == 0, "registry vs scopes", &detail);
  }
  let sessions = castellan_state().join("sessions");
  let n = std::fs::read_dir(&sessions).map(|r| r.flatten().count()).unwrap_or(0);
  println!("INFO  {:<24} {n} session(s) on disk", "state");
  println!("INFO  {:<24} {} scope(s) live", "cgroup", scope_names.len());
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

  // P20/F11: the unit must fail visibly (start-limit) instead of
  // thrashing the socket against a competing daemon forever.
  #[test]
  fn unit_contents_has_start_limit() {
    let u = unit_contents(Path::new("/x/d"), Path::new("/x/c"), false);
    assert!(u.contains("StartLimitBurst=5"));
    assert!(u.contains("StartLimitIntervalSec=60"));
    assert!(u.contains("Restart=on-failure"));
  }

  // P20/C43: ExecStopPost must freeze the fleet on any stop, via the
  // daemonless path (the daemon is gone when it runs), and must clean
  // the stale socket so existence checks stay truthful.
  #[test]
  fn unit_contents_freezes_on_stop() {
    let u = unit_contents(Path::new("/x/d"), Path::new("/x/c"), false);
    assert!(u.contains("ExecStopPost=/x/c freeze --daemonless"));
    assert!(!u.contains("ExecStopPost=/x/d"), "freeze must not need the daemon");
    assert!(u.contains("ExecStopPost=-/bin/rm -f %t/castellan.sock"));
  }
}
