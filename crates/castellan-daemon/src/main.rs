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
  if let Err(e) = castellan_daemon::Daemon::new().and_then(|d| d.serve()) {
    eprintln!("castellan-daemon: {e}");
    std::process::exit(1);
  }
}
