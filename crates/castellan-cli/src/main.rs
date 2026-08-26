use std::io::Write;

fn main() {
  let path = match std::env::var("XDG_RUNTIME_DIR") {
    Ok(dir) => format!("{dir}/castellan.sock"),
    Err(_) => {
      let uid = nix::unistd::Uid::current().as_raw();
      format!("/run/user/{uid}/castellan.sock")
    }
  };
  let args: Vec<String> = std::env::args().skip(1).collect();
  if args.is_empty() {
    print_usage_and_exit();
  }
  match args[0].as_str() {
    "launch" => launch(&args[1..], &path),
    "audit" => audit_report(&args[1..]),
    _ => {}
  }
  let request = match args[0].as_str() {
    "status" => serde_json::json!({"op": "status"}),
    "freeze" => freeze_req(&args[1..], "freeze"),
    "thaw" => freeze_req(&args[1..], "thaw"),
    "kill" => freeze_req(&args[1..], "kill"),
    "spawn" => spawn_req(&args[1..]),
    "adopt" => adopt_req(&args[1..]),
    "help" | "--help" | "-h" => print_usage_and_exit(),
    other => {
      eprintln!("unknown command: {other}");
      print_usage_and_exit();
    }
  };
  let mut stream = match std::os::unix::net::UnixStream::connect(&path) {
    Ok(s) => s,
    Err(e) => {
      eprintln!("castellan daemon not reachable at {path}: {e}");
      eprintln!("start it with: castellan daemon");
      std::process::exit(1);
    }
  };
  let mut req = request.to_string();
  req.push('\n');
  if let Err(e) = stream.write_all(req.as_bytes()) {
    eprintln!("send failed: {e}");
    std::process::exit(1);
  }
  let mut reader = std::io::BufReader::new(stream);
  let mut line = String::new();
  use std::io::BufRead;
  match reader.read_line(&mut line) {
    Ok(0) => eprintln!("daemon closed connection"),
    Ok(_) => print!("{}", render(&line)),
    Err(e) => eprintln!("read failed: {e}"),
  }
}

fn freeze_req(args: &[String], op: &str) -> serde_json::Value {
  match args.first() {
    Some(id) => serde_json::json!({"op": op, "session": id}),
    None => serde_json::json!({"op": op}),
  }
}

fn launch(args: &[String], sock: &str) -> ! {
  let mut harness = "unknown".to_string();
  let mut project = std::env::current_dir().unwrap_or_default();
  let mut enforce = false;
  let mut cmd: Option<Vec<String>> = None;
  let mut i = 0;
  while i < args.len() {
    match args[i].as_str() {
      "--harness" | "-H" if i + 1 < args.len() => {
        harness = args[i + 1].clone();
        i += 1;
      }
      "--project" | "-p" if i + 1 < args.len() => {
        project = std::path::PathBuf::from(&args[i + 1]);
        i += 1;
      }
      "--enforce" => enforce = true,
      "--" => {
        cmd = Some(args[i + 1..].to_vec());
        break;
      }
      other => {
        eprintln!("unexpected launch argument: {other}");
        std::process::exit(2);
      }
    }
    i += 1;
  }
  let cmd = match cmd {
    Some(c) if !c.is_empty() => c,
    _ => {
      eprintln!("usage: castellan launch [--harness H] [--project P] [--enforce] -- <command> [args...]");
      std::process::exit(2);
    }
  };
  let resp = rpc(sock, &serde_json::json!({
    "op": "spawn",
    "harness": harness,
    "project": project,
    "pid": null
  }));
  let session = extract_session(&resp).unwrap_or_else(|| {
    eprintln!("launch failed: {resp}");
    std::process::exit(1);
  });
  let procs = scope_procs(&session);
  if let Err(e) = std::fs::write(
    &procs,
    format!("{}\n", std::process::id()),
  ) {
    eprintln!("failed to join session cgroup: {e}");
    std::process::exit(1);
  }
  if enforce {
    let policy = castellan_policy::Policy::new(&session, &harness, project.clone());
    if let Err(e) = castellan_envelope::apply_envelope(&policy) {
      eprintln!("failed to apply envelope (fail-closed): {e}");
      std::process::exit(1);
    }
  }
  eprintln!("castellan session {session}{} launched", if enforce { ", enforced" } else { "" });
  let err = execvp(&cmd);
  eprintln!("exec failed: {err}");
  std::process::exit(127);
}

fn scope_procs(session: &str) -> std::path::PathBuf {
  castellan_freezer::CgroupRoot::detect()
    .expect("cgroup v2 user slice not found")
    .session_dir(&session.to_string())
    .join("cgroup.procs")
}

fn rpc(sock: &str, req: &serde_json::Value) -> String {
  use std::io::{BufRead, BufReader, Write};
  let mut stream =
    std::os::unix::net::UnixStream::connect(sock).unwrap_or_else(|e| {
      eprintln!("castellan daemon not reachable at {sock}: {e}");
      eprintln!("start it with: castellan-daemon");
      std::process::exit(1);
    });
  stream
    .write_all(format!("{req}\n").as_bytes())
    .unwrap_or_else(|e| {
      eprintln!("send failed: {e}");
      std::process::exit(1);
    });
  let mut reader = BufReader::new(stream);
  let mut line = String::new();
  match reader.read_line(&mut line) {
    Ok(0) | Err(_) => {
      eprintln!("daemon closed connection");
      std::process::exit(1);
    }
    Ok(_) => {}
  }
  line.trim().to_string()
}

fn extract_session(resp: &str) -> Option<String> {
  let v = serde_json::from_str::<serde_json::Value>(resp).ok()?;
  let msg = v.get("message")?.as_str()?;
  let idx = msg.find("session ")? + "session ".len();
  let rest = &msg[idx..];
  let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
  Some(rest[..end].to_string())
}

#[cfg(target_os = "linux")]
fn execvp(cmd: &[String]) -> nix::Error {
  use std::ffi::CString;
  let argv: Vec<CString> = cmd
    .iter()
    .map(|a| match CString::new(a.as_bytes()) {
      Ok(c) => c,
      Err(_) => {
        eprintln!("argument contains NUL byte");
        std::process::exit(2);
      }
    })
    .collect();
  nix::unistd::execvp(&argv[0], &argv).unwrap_err()
}

#[cfg(not(target_os = "linux"))]
fn execvp(_cmd: &[String]) -> nix::Error {
  unreachable!()
}

fn audit_report(args: &[String]) -> ! {
  let session = match args.first() {
    Some(s) => s,
    None => {
      eprintln!("usage: castellan audit <session>");
      std::process::exit(2);
    }
  };
  let state_dir = std::env::var("XDG_STATE_HOME")
    .map(std::path::PathBuf::from)
    .unwrap_or_else(|_| {
      let h = nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .ok()
        .flatten()
        .map(|u| u.dir)
        .unwrap_or_default();
      h.join(".local/state")
    });
  let sink_path = state_dir.join("castellan/events").join(format!("{session}.jsonl"));
  let content = std::fs::read_to_string(&sink_path).unwrap_or_default();
  let mut allow = 0usize;
  let mut deny = Vec::new();
  for line in content.lines() {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
    let verdict = v.get("verdict").and_then(|x| x.as_str()).unwrap_or("");
    match verdict {
      "allow" => allow += 1,
      "would_deny" => {
        let p = v.get("path").and_then(|x| x.as_str()).unwrap_or("?");
        deny.push(p.to_string());
      }
      _ => {}
    }
  }
  println!("{session}: {allow} write(s) inside envelope, {} outside:", deny.len());
  for d in deny.iter().take(20) {
    println!("  WOULD-DENY {d}");
  }
  if deny.len() > 20 {
    println!("  ... and {} more", deny.len() - 20);
  }
  std::process::exit(0)
}

fn spawn_req(args: &[String]) -> serde_json::Value {
  let mut harness = "unknown".to_string();
  let mut project = std::env::current_dir().unwrap_or_default();
  let mut pid = None;
  let mut i = 0;
  while i < args.len() {
    match args[i].as_str() {
      "--harness" | "-H" => {
        if i + 1 < args.len() {
          harness = args[i + 1].clone();
          i += 1;
        }
      }
      "--project" | "-p" => {
        if i + 1 < args.len() {
          project = std::path::PathBuf::from(&args[i + 1]);
          i += 1;
        }
      }
      "--pid" => {
        if let Some(p) = args.get(i + 1).and_then(|v| v.parse::<u32>().ok()) {
          pid = Some(p);
          i += 1;
        }
      }
      _ => {}
    }
    i += 1;
  }
  serde_json::json!({"op": "spawn", "harness": harness, "project": project, "pid": pid})
}

fn adopt_req(args: &[String]) -> serde_json::Value {
  if args.len() < 2 {
    eprintln!("usage: castellan adopt <session> <pid> [pid...]");
    std::process::exit(2);
  }
  let pids: Vec<u32> = args[1..].iter().filter_map(|p| p.parse().ok()).collect();
  serde_json::json!({"op": "adopt", "session": args[0], "pids": pids})
}

fn render(line: &str) -> String {
  match serde_json::from_str::<serde_json::Value>(line) {
    Ok(v) => {
      let ok = v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false);
      let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("");
      let err = v.get("error").and_then(|e| e.as_str());
      let mut out = String::new();
      if !ok {
        out.push_str(&format!("error: {}\n", err.unwrap_or("unknown")));
      }
      if !msg.is_empty() {
        out.push_str(msg);
        out.push('\n');
      }
      if let Some(sessions) = v.get("sessions").and_then(|s| s.as_array()) {
        for s in sessions {
          let id = s.get("id").and_then(|x| x.as_str()).unwrap_or("-");
          let harness = s.get("harness").and_then(|x| x.as_str()).unwrap_or("-");
          let state = s.get("state").and_then(|x| x.as_str()).unwrap_or("-");
          let pids = s.get("pids").and_then(|x| x.as_u64()).unwrap_or(0);
          let project = s.get("project").and_then(|x| x.as_str()).unwrap_or("-");
          out.push_str(&format!("{id:<24} {harness:<10} {state:<8} {pids:>3} pids  {project}\n"));
        }
      }
      out
    }
    Err(_) => format!("raw: {line}\n"),
  }
}

fn print_usage_and_exit() -> ! {
  eprintln!("castellan — the OS is the trust boundary for AI agents");
  eprintln!();
  eprintln!("usage:");
  eprintln!("  castellan status                 list sessions and freeze states");
  eprintln!("  castellan freeze [session]       freeze all sessions or one");
  eprintln!("  castellan thaw   [session]       thaw all sessions or one");
  eprintln!("  castellan kill   [session]       kill all sessions or one");
  eprintln!("  castellan spawn --harness H [--project P] [--pid PID]");
  eprintln!("  castellan launch [--harness H] [--project P] [--enforce] -- CMD [args...]");
  eprintln!("  castellan audit <session>     show envelope violations for a session");
  eprintln!("  castellan adopt <session> <pid> [pid...]   move running procs into a scope");
  eprintln!("  castellan daemon                 start the daemon (foreground)");
  std::process::exit(2);
}
