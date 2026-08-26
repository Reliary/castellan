fn main() {
  if let Err(e) = castellan_daemon::Daemon::new().and_then(|d| d.serve()) {
    eprintln!("castellan-daemon: {e}");
    std::process::exit(1);
  }
}
