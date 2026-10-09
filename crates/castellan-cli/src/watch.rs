use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};

/// P21.3: human visibility. `castellan watch` polls the daemon for
/// session-freeze and bless-pending transitions and reports them to the
/// terminal, optionally via `notify-send` when present on PATH. Read-only:
/// it never issues freeze/thaw/policy ops, so it needs no tty witness and
/// is safe to run from a service or a phone-side ssh session.
///
/// A pending bless otherwise lives only in `castellan bless show` and the
/// daemon journal; a freeze only in `castellan status`. The watcher closes
/// that gap.
pub fn run_watch(sock: &str, args: &[String]) -> ! {
  let mut once = false;
  let mut user_unit = false;
  let mut interval_secs: u64 = 2;
  let mut no_notify = false;
  let mut i = 0;
  while i < args.len() {
    match args[i].as_str() {
      "--once" => once = true,
      "--user-unit" => user_unit = true,
      "--no-notify" => no_notify = true,
      "--interval" => {
        i += 1;
        interval_secs = args.get(i).and_then(|v| v.parse().ok()).unwrap_or(2).max(1);
      }
      "-h" | "--help" => {
        eprintln!("usage: castellan watch [--once] [--interval SECS] [--no-notify] [--user-unit]");
        eprintln!("  prints session-freeze and bless-pending transitions;");
        eprintln!("  sends desktop notifications via notify-send when it is installed.");
        eprintln!("  --user-unit writes a castellan-watch.service that runs this in the background.");
        std::process::exit(0);
      }
      other => {
        eprintln!("unexpected watch argument: {other}");
        std::process::exit(2);
      }
    }
    i += 1;
  }
  if user_unit {
    write_watch_unit();
  }

  let notifier = if no_notify { Notifier::Disabled } else { Notifier::detect() };
  let mut prev: Option<Snapshot> = None;
  loop {
    let snap = match poll(sock) {
      Ok(s) => s,
      Err(e) => {
        if prev.is_some() {
          println!("daemon unreachable: {e} (waiting)");
          prev = None;
        }
        if once {
          eprintln!("watch: daemon unreachable: {e}");
          std::process::exit(1);
        }
        std::thread::sleep(std::time::Duration::from_secs(interval_secs));
        continue;
      }
    };
    match &prev {
      None => {
        println!(
          "watching {} sessions{}",
          snap.sessions.len(),
          if snap.pending_bless.is_empty() {
            String::new()
          } else {
            format!(" — {} approval request(s) pending", snap.pending_bless.len())
          }
        );
      }
      Some(old) => {
        for line in diff(old, &snap) {
          println!("{line}");
          if let Some((urgency, summary, body)) = line_notification(&line) {
            notifier.send(urgency, &summary, &body);
          }
        }
      }
    }
    // bless transitions were folded into diff(); baseline them here
    for (line, urgency, summary, body) in bless_transitions(prev.as_ref(), &snap) {
      println!("{line}");
      notifier.send(urgency, &summary, &body);
    }
    prev = Some(snap);
    if once {
      std::process::exit(0);
    }
    std::thread::sleep(std::time::Duration::from_secs(interval_secs));
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionState {
  frozen: bool,
  project: String,
}

#[derive(Debug, Clone)]
struct Snapshot {
  sessions: BTreeMap<String, SessionState>,
  /// nonce_hint -> (want, session)
  pending_bless: BTreeMap<String, (String, String)>,
}

fn rpc_line(sock: &str, req: &str) -> Result<String, String> {
  let mut stream = std::os::unix::net::UnixStream::connect(sock)
    .map_err(|e| format!("connect {sock}: {e}"))?;
  stream
    .write_all(format!("{req}\n").as_bytes())
    .map_err(|e| format!("send: {e}"))?;
  let mut reader = BufReader::new(stream);
  let mut line = String::new();
  reader
    .read_line(&mut line)
    .map_err(|e| format!("read: {e}"))?;
  if line.is_empty() {
    return Err("daemon closed connection".into());
  }
  Ok(line)
}

fn poll(sock: &str) -> Result<Snapshot, String> {
  let status = rpc_line(sock, r#"{"op":"status"}"#)?;
  let v: serde_json::Value =
    serde_json::from_str(&status).map_err(|e| format!("status not JSON: {e}"))?;
  if !v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false) {
    return Err(format!(
      "status failed: {}",
      v.get("error").and_then(|e| e.as_str()).unwrap_or("unknown")
    ));
  }
  let mut sessions = BTreeMap::new();
  if let Some(arr) = v.get("sessions").and_then(|s| s.as_array()) {
    for s in arr {
      let id = s.get("id").and_then(|x| x.as_str()).unwrap_or("-").to_string();
      let state = s.get("state").and_then(|x| x.as_str()).unwrap_or("?");
      let project = s
        .get("project")
        .and_then(|x| x.as_str())
        .unwrap_or("-")
        .to_string();
      sessions.insert(
        id,
        SessionState { frozen: state == "frozen", project },
      );
    }
  }
  // bless pending (read-only op; agent-allowed)
  let mut pending_bless = BTreeMap::new();
  if let Ok(line) = rpc_line(sock, r#"{"op":"bless_show"}"#) {
    if let Ok(bv) = serde_json::from_str::<serde_json::Value>(&line) {
      if let Some(arr) = bv
        .get("extra")
        .and_then(|e| e.get("bless"))
        .and_then(|b| b.get("pending"))
        .and_then(|p| p.as_array())
      {
        for p in arr {
          let hint = p.get("nonce_hint").and_then(|x| x.as_str()).unwrap_or("?").to_string();
          let want = p.get("want").and_then(|x| x.as_str()).unwrap_or("?").to_string();
          let sess = p.get("session").and_then(|x| x.as_str()).unwrap_or("?").to_string();
          pending_bless.insert(hint, (want, sess));
        }
      }
    }
  }
  Ok(Snapshot { sessions, pending_bless })
}

/// Session freeze-state transitions between two snapshots.
fn diff(old: &Snapshot, new: &Snapshot) -> Vec<String> {
  let mut out = Vec::new();
  for (id, st) in &new.sessions {
    match old.sessions.get(id) {
      None => out.push(format!("+ session {id} ({}) — {}", st.project, if st.frozen { "frozen" } else { "thawed" })),
      Some(prev) if prev.frozen != st.frozen => {
        if st.frozen {
          out.push(format!("FROZEN  {id} ({}) — thaw with: castellan thaw {id}", st.project));
        } else {
          out.push(format!("thawed  {id} ({})", st.project));
        }
      }
      _ => {}
    }
  }
  for id in old.sessions.keys() {
    if !new.sessions.contains_key(id) {
      out.push(format!("- session {id} ended"));
    }
  }
  out
}

fn line_notification(line: &str) -> Option<(&'static str, String, String)> {
  if line.starts_with("FROZEN") {
    return Some(("critical", "castellan: session frozen".into(), line.to_string()));
  }
  if line.starts_with("- session") {
    return Some(("low", "castellan: session ended".into(), line.to_string()));
  }
  None
}

fn bless_transitions(
  old: Option<&Snapshot>,
  new: &Snapshot,
) -> Vec<(String, &'static str, String, String)> {
  let mut out = Vec::new();
  let old_set = old.map(|o| o.pending_bless.clone()).unwrap_or_default();
  for (hint, (want, sess)) in &new.pending_bless {
    if !old_set.contains_key(hint) {
      let line = format!(
        "BLESS  {want} requested for {sess} (hint {hint}) — approve: castellan bless approve {hint}"
      );
      out.push((
        line,
        "critical",
        "castellan: expansion request".into(),
        format!("{want} for {sess}"),
      ));
    }
  }
  for hint in old_set.keys() {
    if !new.pending_bless.contains_key(hint) {
      out.push((
        format!("bless request {hint} resolved"),
        "low",
        "castellan: bless resolved".into(),
        format!("request {hint} was approved or rejected"),
      ));
    }
  }
  out
}

enum Notifier {
  Command,
  Disabled,
}

impl Notifier {
  fn detect() -> Self {
    // presence-checked: no hard dependency on a desktop session.
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
      let p = std::path::Path::new(dir).join("notify-send");
      if p.is_file() {
        return Notifier::Command;
      }
    }
    Notifier::Disabled
  }

  fn send(&self, urgency: &str, summary: &str, body: &str) {
    if let Notifier::Command = self {
      // fire-and-forget; a missing DBus session (headless ssh) must not
      // kill the watcher. stdout fallback already printed the line.
      let _ = std::process::Command::new("notify-send")
        .args(["-u", urgency, "-a", "castellan", summary, body])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    }
  }
}

/// P21.3: a background watcher unit. Unlike castellan.service it is not
/// a security component — it just runs `castellan watch`. Removed by
/// `uninstall` like the daemon unit.
fn write_watch_unit() -> ! {
  let exe = match std::env::current_exe() {
    Ok(p) => p,
    Err(e) => {
      eprintln!("watch: cannot resolve own path: {e}");
      std::process::exit(1);
    }
  };
  let dir = std::env::var("XDG_CONFIG_HOME")
    .map(std::path::PathBuf::from)
    .unwrap_or_else(|_| {
      std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".config")
    })
    .join("systemd/user");
  if let Err(e) = std::fs::create_dir_all(&dir) {
    eprintln!("watch: cannot create {}: {e}", dir.display());
    std::process::exit(1);
  }
  let unit = dir.join("castellan-watch.service");
  let body = format!(
    "[Unit]\n\
     Description=castellan session watcher (freeze/bless notifications)\n\
     After=castellan.service\n\
     \n\
     [Service]\n\
     Type=simple\n\
     ExecStart={} watch\n\
     Restart=on-failure\n\
     RestartSec=5\n\
     NoNewPrivileges=yes\n\
     \n\
     [Install]\n\
     WantedBy=default.target\n",
    exe.display()
  );
  if let Err(e) = std::fs::write(&unit, body) {
    eprintln!("watch: cannot write {}: {e}", unit.display());
    std::process::exit(1);
  }
  let status = std::process::Command::new("systemctl")
    .args(["--user", "daemon-reload"])
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null())
    .status();
  println!("wrote {}", unit.display());
  println!("enable it with: systemctl --user enable --now castellan-watch.service");
  if status.map(|s| !s.success()).unwrap_or(true) {
    eprintln!("warning: systemctl --user daemon-reload did not succeed");
  }
  std::process::exit(0);
}

#[cfg(test)]
mod tests {
  use super::*;

  fn snap(sessions: &[(&str, bool, &str)], bless: &[(&str, &str, &str)]) -> Snapshot {
    Snapshot {
      sessions: sessions
        .iter()
        .map(|(id, frozen, project)| {
          (id.to_string(), SessionState { frozen: *frozen, project: project.to_string() })
        })
        .collect(),
      pending_bless: bless
        .iter()
        .map(|(hint, want, sess)| (hint.to_string(), (want.to_string(), sess.to_string())))
        .collect(),
    }
  }

  #[test]
  fn diff_reports_freeze_thaw_start_end() {
    let old = snap(&[("s1", false, "p1"), ("s2", false, "p2")], &[]);
    let new = snap(&[("s1", true, "p1"), ("s3", false, "p3")], &[]);
    let lines = diff(&old, &new);
    assert!(lines.iter().any(|l| l.starts_with("FROZEN  s1")), "{lines:?}");
    assert!(lines.iter().any(|l| l.starts_with("+ session s3")), "{lines:?}");
    assert!(lines.iter().any(|l| l.starts_with("- session s2")), "{lines:?}");
    assert!(!lines.iter().any(|l| l.contains("s1") && l.contains("+ ")), "{lines:?}");
  }

  #[test]
  fn diff_quiet_when_nothing_changes() {
    let a = snap(&[("s1", false, "p")], &[]);
    assert!(diff(&a, &a).is_empty());
  }

  #[test]
  fn blessing_and_resolution_are_transitions() {
    let old = snap(&[], &[]);
    let new = snap(&[], &[("abc12345", "egress", "s9")]);
    let t = bless_transitions(Some(&old), &new);
    assert_eq!(t.len(), 1);
    assert!(t[0].0.contains("BLESS"));
    assert!(t[0].0.contains("castellan bless approve abc12345"), "{}", t[0].0);
    assert_eq!(t[0].1, "critical");
    // resolution: request disappears
    let resolved = bless_transitions(Some(&new), &old);
    assert_eq!(resolved.len(), 1);
    assert!(resolved[0].0.contains("resolved"));
  }

  #[test]
  fn first_poll_has_no_spurious_transitions() {
    // With no previous snapshot, bless_transitions sees all pending as
    // new (baseline announcement); diff() is not called. This pins the
    // baseline behavior: a fresh watcher announces pending requests.
    let new = snap(&[], &[("h1", "config-dir", "s1")]);
    let t = bless_transitions(None, &new);
    assert_eq!(t.len(), 1, "a fresh watcher should announce pending requests");
  }

  #[test]
  fn frozen_line_maps_to_critical_notification() {
    let n = line_notification("FROZEN  s1 (p) — thaw with: castellan thaw s1");
    assert_eq!(n.map(|(u, _, _)| u), Some("critical"));
    assert!(line_notification("thawed  s1 (p)").is_none());
  }
}
