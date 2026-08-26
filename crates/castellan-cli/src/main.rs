use std::io::Write;

fn main() {
  let path = match std::env::var("XDG_RUNTIME_DIR") {
    Ok(dir) => format!("{dir}/castellan.sock"),
    Err(_) => {
      let uid = unsafe { libc::getuid() };
      format!("/run/user/{uid}/castellan.sock")
    }
  };
  let args: Vec<String> = std::env::args().skip(1).collect();
  if args.is_empty() {
    print_usage_and_exit();
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
        if i + 1 < args.len() {
          pid = args[i + 1].parse::<u32>().ok();
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
  eprintln!("  castellan adopt <session> <pid> [pid...]   move running procs into a scope");
  eprintln!("  castellan daemon                 start the daemon (foreground)");
  std::process::exit(2);
}
