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
    "diff" | "undo" | "keep" => undo_req(&args[1..], args[0].as_str()),
    "canary" => canary_req(&args[1..]),
    "trust" => trust_req(&args[1..]),
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
fn undo_req(args: &[String], verb: &str) -> serde_json::Value {
  let Some(id) = args.first() else {
    eprintln!("usage: castellan {verb} <session>");
    std::process::exit(2);
  };
  match verb {
    "diff" => serde_json::json!({"op": "undo_diff", "session": id}),
    "undo" => serde_json::json!({"op": "undo_discard", "session": id}),
    _ => serde_json::json!({"op": "undo_commit", "session": id}),
  }
}

fn canary_req(args: &[String]) -> serde_json::Value {
  let Some(id) = args.first() else {
    eprintln!("usage: castellan canary <session>");
    std::process::exit(2);
  };
  serde_json::json!({"op": "canary_register", "session": id, "project": "", "harness": ""})
}

fn trust_req(args: &[String]) -> serde_json::Value {
  let project = match args.first() {
    Some(p) => std::path::PathBuf::from(p),
    None => std::env::current_dir().unwrap_or_default(),
  };
  serde_json::json!({"op": "trust_score", "project": project})
}

fn launch(args: &[String], sock: &str) -> ! {
  let mut harness: Option<String> = None;
  let mut project = std::env::current_dir().unwrap_or_default();
  let mut enforce = false;
  let mut undo = false;
  let mut net = false;
  let mut cmd: Option<Vec<String>> = None;
  let mut i = 0;
  while i < args.len() {
    match args[i].as_str() {
      "--harness" | "-H" if i + 1 < args.len() => {
        harness = Some(args[i + 1].clone());
        i += 1;
      }
      "--project" | "-p" if i + 1 < args.len() => {
        project = std::path::PathBuf::from(&args[i + 1]);
        i += 1;
      }
      "--enforce" => enforce = true,
      "--undo" => undo = true,
      "--net" => net = true,
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
      eprintln!("usage: castellan launch [--harness H] [--project P] [--enforce] [--undo] [--net] -- <command> [args...]");
      std::process::exit(2);
    }
  };
  let harness = harness.unwrap_or_else(|| {
    castellan_policy::detect_harness(&cmd[0]).unwrap_or("unknown").to_string()
  });
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
    let mut policy = castellan_policy::Policy::new(&session, &harness, project.clone());
    if net {
      let port = rpc(sock, &serde_json::json!({ "op": "honeypot_port" }));
      let port: u16 = serde_json::from_str(&port)
        .ok()
        .and_then(|v: serde_json::Value| v["port"].as_u64().map(|p| p as u16))
        .unwrap_or(0);
      if port == 0 {
        eprintln!("--net requested but daemon honeypot is detached; continuing WITHOUT net lockdown");
      } else {
        policy.set_net(castellan_policy::NetMode::Loopback(vec![port]));
      }
    }
    if let Err(e) = castellan_envelope::apply_envelope(&policy) {
      eprintln!("failed to apply envelope (fail-closed): {e}");
      std::process::exit(1);
    }
  }
  if undo {
    // overlay setup enters a user+mount namespace; every write the agent
    // makes lands in the session upper layer. undo/diff/commit operate
    // on that layer from outside after exit.
    let scratch = std::env::var("XDG_STATE_HOME")
      .map(std::path::PathBuf::from)
      .unwrap_or_else(|_| {
        std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".local/state")
      })
      .join("castellan/sessions")
      .join(&session);
    match castellan_ledger::setup(&project, &scratch) {
      Ok(o) => {
        if let Err(e) = std::env::set_current_dir(&o.merged) {
          eprintln!("failed to chdir into merged view: {e}");
          std::process::exit(1);
        }
        rpc(sock, &serde_json::json!({ "op": "note", "session": session, "kind": "undo", "detail": o.upper.display().to_string() }));
      }
      Err(e) => {
        eprintln!("failed to set up undo overlay (continuing WITHOUT undo): {e}");
        undo = false;
      }
    }
  }
  eprintln!(
    "castellan session {session}{}{} launched",
    if enforce { ", enforced" } else { "" },
    if undo { ", undoable" } else { "" }
  );
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
      if let Some(changes) =
        v.get("extra").and_then(|e| e.get("changes")).and_then(|c| c.as_array())
      {
        for c in changes {
          let kind = c.get("kind").and_then(|k| k.as_str()).unwrap_or("?");
          let path = c.get("path").and_then(|p| p.as_str()).unwrap_or("?");
          let size = c.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
          let marker = match kind {
            "deleted" => "-",
            "dir" => "d",
            _ => "+",
          };
          out.push_str(&format!("{marker} {path:<50} {size:>8}B\n"));
        }
      }
      if let Some(applied) =
        v.get("extra").and_then(|e| e.get("applied")).and_then(|a| a.as_array())
      {
        for a in applied {
          out.push_str(&format!("{}\n", a.as_str().unwrap_or("?")));
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
