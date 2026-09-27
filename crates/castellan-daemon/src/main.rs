fn main() {
  // P8 D4 drill child: apply the envelope for a drill session, then
  // attempt a write to the denied path. Exit 0 = denied (defense
  // held); exit 1 = write succeeded (envelope broken).
  if std::env::args().nth(1).as_deref() == Some("--drill-envelope") {
    let denied = std::env::args().nth(2).unwrap_or_default();
    let session = std::env::var("CASTELLAN_DRILL_SESSION").unwrap_or_else(|_| "drill".into());
    let policy = castellan_policy::Policy::new(&session, "drill", std::path::PathBuf::from("/tmp"));
    match castellan_envelope::apply_envelope(&policy) {
      Ok(()) => {}
      Err(e) => {
        eprintln!("drill-envelope: apply failed: {e}");
        std::process::exit(1);
      }
    }
    let target = std::path::Path::new(&denied).join("drill-probe");
    // the probe must be meaningful regardless of HOME contents: create
    // the parent BEFORE the envelope so a missing dir (ENOENT) can
    // never masquerade as a denied write (EACCES)
    if let Some(parent) = target.parent() {
      let _ = std::fs::create_dir_all(parent);
    }
    match std::fs::write(&target, b"probe") {
      Ok(()) => {
        eprintln!("drill-envelope: WRITE SUCCEEDED — envelope broken");
        std::process::exit(1);
      }
      Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
        std::process::exit(0);
      }
      Err(e) => {
        eprintln!("drill-envelope: unexpected error: {e}");
        std::process::exit(1);
      }
    }
  }
  // P9 D6 drill child: apply the envelope (with net lockdown), then
  // probe every egress channel and print one verdict line per channel.
  // The daemon aggregates the lines into the channel inventory.
  if std::env::args().nth(1).as_deref() == Some("--drill-channels") {
    let honeypot_port: u16 = std::env::args().nth(2).unwrap_or_default().parse().unwrap_or(0);
    let session = std::env::var("CASTELLAN_DRILL_SESSION").unwrap_or_else(|_| "drill".into());
    // the inherited-fd probe needs the fd open BEFORE the envelope —
    // the envelope cannot revoke an already-open fd
    let fd_path = "/tmp/castellan-channels-fd";
    let _ = std::fs::OpenOptions::new().create(true).append(true).open(fd_path);
    let mut policy = castellan_policy::Policy::new(&session, "drill", std::path::PathBuf::from("/tmp"));
    if honeypot_port > 0 {
      policy.set_net(castellan_policy::NetMode::Loopback(vec![honeypot_port]));
    }
    match castellan_envelope::apply_envelope(&policy) {
      Ok(()) => {}
      Err(e) => {
        eprintln!("channels: apply failed: {e}");
        std::process::exit(1);
      }
    }
    let verdicts = castellan_daemon::probe_channels(honeypot_port);
    for (channel, verdict) in &verdicts {
      println!("{channel}: {verdict}");
    }
    std::process::exit(0);
  }
  // F3 follow-up 5 (2026-09-27, .227 breakout): daemon singleton.
  // Learned live: stale daemons accumulate on the same socket path
  // (every test restart binds it again; last-bind-wins per connection),
  // so "kill the daemon" never empties the socket and no socket-based
  // watchdog can observe death. Refuse to stack: if the socket already
  // answers, exit non-zero instead of binding over it. (Stale socket
  // file with no listener: connect fails -> we bind fresh. A
  // same-host operator who WANTS two daemons uses XDG_RUNTIME_DIR to
  // separate them — the socket path already honors it.)
  {
    let runtime = std::env::var("XDG_RUNTIME_DIR")
      .unwrap_or_else(|_| format!("/run/user/{}", nix::unistd::Uid::current().as_raw()));
    let sock = std::path::Path::new(&runtime).join("castellan.sock");
    if std::os::unix::net::UnixStream::connect(&sock).is_ok() {
      eprintln!("castellan-daemon: socket {} already served — refusing to stack (kill the old daemon first)", sock.display());
      std::process::exit(3);
    }
  }
  if let Err(e) = castellan_daemon::Daemon::new().and_then(|d| d.serve()) {
    eprintln!("castellan-daemon: {e}");
    std::process::exit(1);
  }
}
