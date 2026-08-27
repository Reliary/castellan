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
  if let Err(e) = castellan_daemon::Daemon::new().and_then(|d| d.serve()) {
    eprintln!("castellan-daemon: {e}");
    std::process::exit(1);
  }
}
