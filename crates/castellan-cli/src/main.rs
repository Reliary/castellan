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
    "bless" => bless_req(&args[1..]),
    "cert" => cert_req(&args[1..]),
    "replay" => replay_req(&args[1..]),
    "radar" => radar_req(&args[1..]),
    "siblings" => siblings_req(),
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
    Ok(0) => {
      eprintln!("daemon closed connection");
      std::process::exit(1);
    }
    Ok(_) => {
      print!("{}", render(&line));
      // scripts must be able to detect daemon-side failures
      let ok = serde_json::from_str::<serde_json::Value>(&line)
        .ok()
        .and_then(|v| v.get("ok").and_then(|b| b.as_bool()))
        .unwrap_or(false);
      if !ok {
        std::process::exit(1);
      }
    }
    Err(e) => {
      eprintln!("read failed: {e}");
      std::process::exit(1);
    }
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

fn radar_req(args: &[String]) -> serde_json::Value {
  let Some(session) = args.first() else {
    eprintln!("usage: castellan radar <session> [project]");
    std::process::exit(2);
  };
  let project = match args.get(1) {
    Some(p) => std::path::PathBuf::from(p),
    None => std::env::current_dir().unwrap_or_default(),
  };
  serde_json::json!({"op": "radar", "session": session, "project": project})
}

/// N5: sibling detector — scan for known harness processes running
/// WITHOUT the CASTELLAN_SESSION tag. Advisory: any process not
/// launched via castellan can read trust.db, the spine, and the
/// signing key; this detects the boundary violation, it cannot
/// prevent it.
fn siblings_req() -> serde_json::Value {
  let harnesses = ["claude", "codex", "pi", "opencode", "aider", "cursor-agent", "gemini", "crush"];
  let mut found: Vec<serde_json::Value> = Vec::new();
  if let Ok(entries) = std::fs::read_dir("/proc") {
    for entry in entries.flatten() {
      let name = entry.file_name();
      let pid: u32 = match name.to_string_lossy().parse() {
        Ok(p) => p,
        Err(_) => continue,
      };
      let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        continue;
      };
      let argv: Vec<&[u8]> = cmdline.split(|&b| b == 0).filter(|a| !a.is_empty()).collect();
      let Some(prog) = argv.first() else { continue };
      let prog = String::from_utf8_lossy(prog);
      let base = std::path::Path::new(prog.as_ref())
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
      if !harnesses.contains(&base.as_str()) {
        continue;
      }
      let Ok(environ) = std::fs::read(format!("/proc/{pid}/environ")) else {
        continue;
      };
      let tagged = environ
        .split(|&b| b == 0)
        .any(|kv| kv.starts_with(b"CASTELLAN_SESSION="));
      if !tagged {
        found.push(serde_json::json!({
          "pid": pid,
          "harness": base,
          "tagged": false,
        }));
      }
    }
  }
  serde_json::json!({"op": "siblings", "found": found})
}

fn replay_req(args: &[String]) -> serde_json::Value {
  let Some(session) = args.first() else {
    eprintln!("usage: castellan replay <session> [narrower-project]");
    std::process::exit(2);
  };
  let narrower = match args.get(1) {
    Some(p) => std::path::PathBuf::from(p),
    None => std::env::current_dir().unwrap_or_default(),
  };
  serde_json::json!({"op": "replay", "session": session, "narrower_project": narrower})
}

fn cert_req(args: &[String]) -> serde_json::Value {
  let Some(session) = args.first() else {
    eprintln!("usage: castellan cert <session>");
    std::process::exit(2);
  };
  serde_json::json!({"op": "cert", "session": session})
}

fn bless_req(args: &[String]) -> serde_json::Value {
  match args.first().map(|s| s.as_str()) {
    Some("request") => {
      let mut session = String::new();
      let mut want = String::new();
      let mut reason = String::new();
      let mut i = 1;
      while i < args.len() {
        match args[i].as_str() {
          "--session" | "-s" => {
            if i + 1 < args.len() {
              session = args[i + 1].clone();
              i += 1;
            }
          }
          "--want" | "-w" => {
            if i + 1 < args.len() {
              want = args[i + 1].clone();
              i += 1;
            }
          }
          "--reason" | "-r" => {
            if i + 1 < args.len() {
              reason = args[i + 1].clone();
              i += 1;
            }
          }
          other => {
            eprintln!("unexpected bless request argument: {other}");
            std::process::exit(2);
          }
        }
        i += 1;
      }
      if session.is_empty() || want.is_empty() {
        eprintln!("usage: castellan bless request --session <id> --want <egress|config-dir|system-config> [--reason ...]");
        std::process::exit(2);
      }
      serde_json::json!({"op": "bless_request", "session": session, "want": want, "reason": reason})
    }
    Some("approve") => {
      let Some(nonce) = args.get(1) else {
        eprintln!("usage: castellan bless approve <nonce>");
        std::process::exit(2);
      };
      serde_json::json!({"op": "bless_approve", "nonce": nonce})
    }
    Some("reject") => {
      let Some(nonce) = args.get(1) else {
        eprintln!("usage: castellan bless reject <nonce>");
        std::process::exit(2);
      };
      serde_json::json!({"op": "bless_reject", "nonce": nonce})
    }
    _ => {
      eprintln!("usage: castellan bless <request|approve|reject> ...");
      std::process::exit(2);
    }
  }
}

fn launch(args: &[String], sock: &str) -> ! {
  let mut harness: Option<String> = None;
  let mut project = std::env::current_dir().unwrap_or_default();
  let mut enforce = false;
  let mut undo = false;
  let mut net = false;
  let mut grants: Vec<String> = Vec::new();
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
      "--grant" if i + 1 < args.len() => {
        grants.push(args[i + 1].clone());
        i += 1;
      }
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
      eprintln!("usage: castellan launch [--harness H] [--project P] [--enforce] [--undo] [--net] [--grant WANT] -- <command> [args...]");
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
    "pid": null,
    "command": cmd,
    "enforce": enforce,
    "undo": undo,
    "net": net,
    "grants": grants
  }));
  let session = extract_session(&resp).unwrap_or_else(|| {
    eprintln!("launch failed: {resp}");
    std::process::exit(1);
  });
  // N5: tag the launched process so the sibling detector can tell
  // castellan-wrapped harnesses from unenrolled ones.
  unsafe {
    std::env::set_var("CASTELLAN_SESSION", &session);
  }
  // trust floor coupling: the daemon may have forced flags regardless
  // of what the launcher requested (tiers 0-1 run fail-closed unless a
  // human grant was consumed)
  let profile = serde_json::from_str::<serde_json::Value>(&resp)
    .ok()
    .and_then(|v| v.get("extra").and_then(|e| e.get("profile")).cloned());
  let forced = profile
    .as_ref()
    .and_then(|p| p.get("forced").and_then(|f| f.as_bool()))
    .unwrap_or(false);
  let consumed: Vec<String> = profile
    .as_ref()
    .and_then(|p| p.get("grants").and_then(|g| g.as_array()))
    .map(|a| a.iter().filter_map(|g| g.as_str().map(String::from)).collect())
    .unwrap_or_default();
  if forced {
    eprintln!("castellan: trust tier <= 1 — forcing enforce+undo+net (fail-closed)");
    enforce = true;
    undo = true;
    net = true;
  }
  if !consumed.is_empty() {
    eprintln!("castellan: consumed expansion grant(s): {}", consumed.join(", "));
  }
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
      if let Some(bless) = v.get("extra").and_then(|e| e.get("bless")) {
        if let Some(nonce) = bless.get("nonce").and_then(|n| n.as_str()) {
          out.push_str(&format!("nonce: {nonce}\n"));
        }
        if let Some(want) = bless.get("want").and_then(|w| w.as_str()) {
          out.push_str(&format!("want: {want}\n"));
        }
        if let Some(session) = bless.get("session").and_then(|s| s.as_str()) {
          out.push_str(&format!("session: {session}\n"));
        }
        if let Some(note) = bless.get("note").and_then(|n| n.as_str()) {
          out.push_str(&format!("note: {note}\n"));
        }
        if let Some(approved) = bless.get("approved").and_then(|a| a.as_bool()) {
          out.push_str(&format!("approved: {approved}\n"));
        }
      }      if let Some(cert) = v.get("extra").and_then(|e| e.get("cert")) {
        let label = cert.get("quality_label").and_then(|l| l.as_str()).unwrap_or("?");
        let bounds = cert.get("bounds").and_then(|b| b.get("verdict")).and_then(|x| x.as_str()).unwrap_or("?");
        let oob = cert.get("bounds").and_then(|b| b.get("out_of_bounds_attempts")).and_then(|x| x.as_u64()).unwrap_or(0);
        let placebo = cert.get("placebo").and_then(|p| p.get("verdict")).and_then(|x| x.as_str()).unwrap_or("?");
        let proofs = cert.get("placebo").and_then(|p| p.get("proofs_passed")).and_then(|x| x.as_u64()).unwrap_or(0);
        let tests = cert.get("placebo").and_then(|p| p.get("test_rerun_passed")).and_then(|x| x.as_bool()).unwrap_or(false);
        out.push_str(&format!("quality: {label}\n"));
        out.push_str(&format!("bounds: {bounds} ({} out-of-bounds)\n", oob));
        out.push_str(&format!("placebo: {placebo} ({} proofs, tests {})\n", proofs, if tests { "pass" } else { "n/a" }));
      }
      if let Some(rp) = v.get("extra").and_then(|e| e.get("replay")) {
        let verdict = rp.get("verdict").and_then(|x| x.as_str()).unwrap_or("?");
        let analyzed = rp.get("events_analyzed").and_then(|x| x.as_u64()).unwrap_or(0);
        let orig = rp.get("original_denies").and_then(|x| x.as_u64()).unwrap_or(0);
        let alt = rp.get("alternate_denies").and_then(|x| x.as_u64()).unwrap_or(0);
        out.push_str(&format!("replay: {verdict} ({analyzed} events, {orig} orig-denies, {alt} alt-denies)\n"));
        if let Some(nd) = rp.get("newly_denied").and_then(|x| x.as_array()) {
          for p in nd.iter().take(10) {
            out.push_str(&format!("  NEWLY-DENIED {}\n", p.as_str().unwrap_or("?")));
          }
          if nd.len() > 10 {
            out.push_str(&format!("  ... and {} more\n", nd.len() - 10));
          }
        }
      }
      if let Some(rd) = v.get("extra").and_then(|e| e.get("radar")) {
        let cosine = rd.get("cosine_to_prototype").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let anomaly = rd.get("anomaly").and_then(|x| x.as_bool()).unwrap_or(false);
        let events = rd.get("events_encoded").and_then(|x| x.as_u64()).unwrap_or(0);
        out.push_str(&format!(
          "radar: cosine {:.3} to prototype ({} events) — {}\n",
          cosine,
          events,
          if anomaly { "ANOMALY (advisory)" } else { "normal" }
        ));
      }
      if let Some(pf) = v.get("extra").and_then(|e| e.get("profile")) {
        let enforce = pf.get("enforce").and_then(|x| x.as_bool()).unwrap_or(false);
        let undo = pf.get("undo").and_then(|x| x.as_bool()).unwrap_or(false);
        let net = pf.get("net").and_then(|x| x.as_bool()).unwrap_or(false);
        let forced = pf.get("forced").and_then(|x| x.as_bool()).unwrap_or(false);
        let tier = pf.get("tier").and_then(|x| x.as_str()).unwrap_or("?");
        let grants: Vec<String> = pf
          .get("grants")
          .and_then(|g| g.as_array())
          .map(|a| a.iter().filter_map(|g| g.as_str().map(String::from)).collect())
          .unwrap_or_default();
        out.push_str(&format!(
          "profile: tier {tier}, enforce={enforce} undo={undo} net={net}{}{}\n",
          if forced { " (FORCED fail-closed)" } else { "" },
          if grants.is_empty() { String::new() } else { format!(" grants={}", grants.join(",")) }
        ));
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
  eprintln!("  castellan bless request --session S --want W [--reason R]");
  eprintln!("  castellan bless approve <nonce>   approve an expansion (human only)");
  eprintln!("  castellan bless reject <nonce>    reject an expansion");
  eprintln!("  castellan cert <session>          assemble a ProofCertificate");
  eprintln!("  castellan replay <session> [narrower-project]   permissive-case delta");
  eprintln!("  castellan radar <session> [project]   HV fingerprint + anomaly flag (opt-in)");
  eprintln!("  castellan daemon                 start the daemon (foreground)");
  std::process::exit(2);
}
