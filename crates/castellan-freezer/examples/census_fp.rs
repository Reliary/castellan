// B8.3 gate probe: is the time-window orphan census safe to run
// PERIODICALLY during a live session?
//
// The at-kill census claims any process whose:
//   - ppid == the user manager, AND
//   - cgroup is not under castellan.slice, AND
//   - starttime >= session_start
// At kill time the agent is the only thing running, so the blast radius
// is moot. Run the SAME predicate periodically during a live session and
// every legitimate user-manager-parented process started since spawn —
// a new terminal, a browser, a `systemd-run --scope` — matches.
//
// This probe runs a `systemd-run --user --scope sleep` (the shape of a
// legit user app scope, analogous to a terminal) then calls
// orphan_census with a session_start just before it and reports whether
// the legit process is claimed.
//
// Run: cargo run --release -p castellan-freezer --example census_fp

use castellan_freezer::CgroupRoot;

fn main() {
  let root = match CgroupRoot::detect() {
    Ok(r) => r,
    Err(e) => {
      eprintln!("census-fp: detect failed: {e}");
      std::process::exit(3);
    }
  };
  // Session start = now, before we launch the legit scope.
  let session_start = castellan_core::now_unix();
  let session = "probe-b83".to_string();
  let _ = root.create_session(&session);

  // A legitimate user-manager-parented process: the exact shape a new
  // terminal takes. NOT an escape — it does not touch castellan.
  // `systemd-run --scope` runs the command in the foreground, so spawn
  // it without waiting.
  let child = std::process::Command::new("systemd-run")
    .args(["--user", "--scope", "--quiet", "sleep", "60"])
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::piped())
    .spawn();
  let mut child = match child {
    Ok(c) => c,
    Err(e) => {
      eprintln!("census-fp: systemd-run unavailable: {e}");
      std::process::exit(3);
    }
  };
  // Give the scope a moment to land (and to fail, if it will).
  std::thread::sleep(std::time::Duration::from_millis(600));
  if let Ok(Some(st)) = child.try_wait() {
    eprintln!("census-fp: legit scope exited early ({st:?}); probe inconclusive");
    std::process::exit(3);
  }

  let orphans = root.orphan_census(&session, session_start);
  let _ = root.destroy_session(&session);
  let _ = child.kill();
  let _ = child.wait();

  // Find the sleep pid for the scope we launched.
  let mut legit_pids: Vec<u32> = Vec::new();
  if let Ok(entries) = std::fs::read_dir("/proc") {
    for e in entries.flatten() {
      let name = e.file_name();
      let Ok(pid) = name.to_string_lossy().parse::<u32>() else { continue };
      let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) else { continue };
      if comm.trim() == "sleep" {
        legit_pids.push(pid);
      }
    }
  }
  let claimed_legit: Vec<u32> = orphans.iter().copied().filter(|p| legit_pids.contains(p)).collect();

  println!("orphan_census returned {} pid(s): {:?}", orphans.len(), orphans);
  println!("legit sleep pids on box: {:?}", legit_pids);
  println!("legit processes WRONGLY claimed: {:?}", claimed_legit);
  if claimed_legit.is_empty() {
    println!("B8.3-CENSUS-SAFE (legit app scope not claimed)");
  } else {
    println!("B8.3-CENSUS-UNSAFE (legit app scope claimed -> periodic auto-kill would kill user apps)");
  }
}
