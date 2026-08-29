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
    "campaign" => campaign_req(&args[1..]),
    "siblings" => siblings_req(),
    "drill" => drill_req(&args[1..]),
    "channels" => channels_req(&args[1..]),
    "trace" => trace_req(&args[1..]),
    "policycheck" => policycheck_req(&args[1..]),
    "memory" => memory_req(&args[1..]),
    "voice" => voice_req(&args[1..]),
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

fn campaign_req(args: &[String]) -> serde_json::Value {
  let project = match args.first() {
    Some(p) => std::path::PathBuf::from(p),
    None => std::env::current_dir().unwrap_or_default(),
  };
  serde_json::json!({"op": "campaign", "project": project})
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

fn drill_req(args: &[String]) -> serde_json::Value {
  match args.first().map(|s| s.as_str()) {
    Some("run") => serde_json::json!({"op": "drill_run"}),
    Some("status") | None => serde_json::json!({"op": "drill_status"}),
    Some(other) => {
      eprintln!("usage: castellan drill [run|status]");
      std::process::exit(2);
    }
  }
}

fn channels_req(args: &[String]) -> serde_json::Value {
  match args.first().map(|s| s.as_str()) {
    Some("run") => serde_json::json!({"op": "channels_run"}),
    Some("status") | None => serde_json::json!({"op": "channels_status"}),
    Some(other) => {
      eprintln!("usage: castellan channels [run|status]");
      std::process::exit(2);
    }
  }
}

fn trace_req(args: &[String]) -> serde_json::Value {
  let Some(compromised) = args.first() else {
    eprintln!("usage: castellan trace <compromised-session>");
    std::process::exit(2);
  };
  serde_json::json!({"op": "trace_expose", "compromised": compromised})
}

fn policycheck_req(args: &[String]) -> serde_json::Value {
  let (Some(project), Some(candidate)) = (args.first(), args.get(1)) else {
    eprintln!("usage: castellan policycheck <project> <candidate-project>");
    std::process::exit(2);
  };
  serde_json::json!({
    "op": "policy_check",
    "project": project,
    "candidate_project": candidate,
  })
}

fn memory_req(args: &[String]) -> serde_json::Value {
  match args.first().map(|s| s.as_str()) {
    Some("recall") => {
      let Some(session) = args.get(1) else {
        eprintln!("usage: castellan memory recall <session>");
        std::process::exit(2);
      };
      serde_json::json!({"op": "memory_recall", "session": session})
    }
    Some("status") | None => serde_json::json!({"op": "memory_status"}),
    Some(other) => {
      eprintln!("usage: castellan memory [recall <session>|status]");
      std::process::exit(2);
    }
  }
}

fn voice_req(args: &[String]) -> serde_json::Value {
  let Some(sub) = args.first().map(|s| s.as_str()) else {
    eprintln!("usage: castellan voice approve <session> <utterance>");
    std::process::exit(2);
  };
  if sub != "approve" {
    eprintln!("usage: castellan voice approve <session> <utterance>");
    std::process::exit(2);
  }
  let Some(session) = args.get(1) else {
    eprintln!("usage: castellan voice approve <session> <utterance>");
    std::process::exit(2);
  };
  let Some(utterance) = args.get(2) else {
    eprintln!("usage: castellan voice approve <session> <utterance>");
    std::process::exit(2);
  };
  serde_json::json!({"op": "voice_approve", "session": session, "utterance": utterance})
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
    // B6 P3: the request nonce is delivered out-of-band (daemon
    // journal). `bless show` prints the pending nonces the human can
    // read from the journal, matching request-time hints.
    Some("show") => {
      serde_json::json!({"op": "bless_show"})
    }
    _ => {
      eprintln!("usage: castellan bless <request|approve|reject|show> ...");
      std::process::exit(2);
    }
  }
}

fn launch(args: &[String], sock: &str) -> ! {
  let mut harness: Option<String> = None;
  let mut project = std::env::current_dir().unwrap_or_default();
  let mut enforce = true;
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
      "--no-enforce" => enforce = false,
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
      eprintln!("usage: castellan launch [--harness H] [--project P] [--no-enforce] [--undo] [--net] [--grant WANT] -- <command> [args...]");
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
    "grants": grants,
    "launcher_tty": launcher_tty()
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
  // undo overlay FIRST: setup enters a user+mount namespace and mounts
  // the overlay. The envelope's seccomp filter blocks mount(2), so
  // applying the envelope before the overlay would break forced
  // fail-closed sessions (tiers 0-1 force undo regardless of flags).
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
        // B6 P3: the undo-layer record is populated daemon-side at
        // spawn (deterministic path) — the launcher's socket Note is
        // gone. The daemon classifies socket callers by cgroup
        // membership; joining happens right below, after which the
        // CLI is an agent and human-only ops are blocked.
        if let Err(e) = std::env::set_current_dir(&o.merged) {
          eprintln!("failed to chdir into merged view: {e}");
          std::process::exit(1);
        }
      }
      Err(e) => {
        eprintln!("failed to set up undo overlay (continuing WITHOUT undo): {e}");
        undo = false;
      }
    }
  }
  // join the session cgroup AFTER the note: the agent inherits the
  // cgroup at exec, and the daemon's caller classification must see
  // the launcher as the human until the agent actually starts.
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
  if !enforce {
    eprintln!("castellan: AUDIT MODE — observation only, no containment (--no-enforce)");
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

/// B6 phase 4: the launcher's kernel tty_nr, read from /proc/self/stat
/// (field index 4 after comm). 0 = headless (no tty requirement on
/// human-only ops for sessions launched from here).
fn launcher_tty() -> u64 {
  let stat = match std::fs::read_to_string("/proc/self/stat") {
    Ok(s) => s,
    Err(_) => return 0,
  };
  let Some(rest) = stat.rsplit_once(')') else { return 0 };
  rest
    .1
    .split_whitespace()
    .nth(4)
    .and_then(|f| f.parse().ok())
    .unwrap_or(0)
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
          if let Some(hint) = bless.get("nonce_hint").and_then(|n| n.as_str()) {
            out.push_str(&format!("nonce_hint: {hint}\n"));
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
          if let Some(channel) = bless.get("channel").and_then(|c| c.as_str()) {
            out.push_str(&format!("channel: {channel}\n"));
          }
          if let Some(attempts) = bless.get("attempts_left").and_then(|a| a.as_u64()) {
            out.push_str(&format!("attempts_left: {attempts}\n"));
          }
          if let Some(pending) = bless.get("pending").and_then(|p| p.as_array()) {
            for p in pending {
              let hint = p.get("nonce_hint").and_then(|x| x.as_str()).unwrap_or("?");
              let want = p.get("want").and_then(|x| x.as_str()).unwrap_or("?");
              let sess = p.get("session").and_then(|x| x.as_str()).unwrap_or("?");
              out.push_str(&format!("  pending {want} for {sess} (hint {hint}) — nonce in daemon journal\n"));
            }
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
        if let Some(scan) = cert.get("artifact_scan") {
          let scanner = scan.get("scanner").and_then(|x| x.as_str()).unwrap_or("?");
          let findings = scan.get("new_findings").and_then(|x| x.as_array()).cloned().unwrap_or_default();
          out.push_str(&format!("artifact: {} new finding(s) (scanner={})\n", findings.len(), scanner));
          for f in findings.iter().take(5) {
            out.push_str(&format!("  FINDING {}\n", f.as_str().unwrap_or("?")));
          }
          out.push_str("  scope: session-touched files only; absence of findings is NOT evidence of safety\n");
        }
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
      if let Some(pc) = v.get("extra").and_then(|e| e.get("policycheck")) {
        let verdict = pc.get("verdict").and_then(|x| x.as_str()).unwrap_or("?");
        let sessions = pc.get("sessions_checked").and_then(|x| x.as_u64()).unwrap_or(0);
        let with_delta = pc.get("sessions_with_delta").and_then(|x| x.as_u64()).unwrap_or(0);
        out.push_str(&format!(
          "policycheck: {verdict} ({sessions} kept sessions, {with_delta} with false-new-denies)\n"
        ));
        if let Some(nd) = pc.get("newly_denied").and_then(|x| x.as_array()) {
          for p in nd.iter().take(10) {
            out.push_str(&format!("  FALSE-NEW-DENY {}\n", p.as_str().unwrap_or("?")));
          }
          if nd.len() > 10 {
            out.push_str(&format!("  ... and {} more\n", nd.len() - 10));
          }
        }
        out.push_str("  advisory: false-NEW-denies only; runs on the developer's machine, not the agent's runtime\n");
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
      if let Some(cp) = v.get("extra").and_then(|e| e.get("campaign")) {
        let scanned = cp.get("sessions_scanned").and_then(|x| x.as_u64()).unwrap_or(0);
        let campaigns = cp.get("campaigns").and_then(|x| x.as_array()).cloned().unwrap_or_default();
        out.push_str(&format!("campaign: {} session(s) scanned, {} campaign(s)\n", scanned, campaigns.len()));
        for c in campaigns {
          let start = c.get("start_ts").and_then(|x| x.as_u64()).unwrap_or(0);
          let end = c.get("end_ts").and_then(|x| x.as_u64()).unwrap_or(0);
          let sessions = c.get("sessions").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0);
          let sig = c.get("dominant_signal").and_then(|x| x.as_str()).unwrap_or("?");
          let sev = c.get("severity").and_then(|x| x.as_str()).unwrap_or("?");
          out.push_str(&format!(
            "  campaign {start}..{end}: {sessions} session(s), dominant={sig}, severity={sev}\n"
          ));
        }
      }
      if let Some(dr) = v.get("extra").and_then(|e| e.get("drill")) {
        let results = dr.get("results").and_then(|r| r.as_array()).cloned().unwrap_or_default();
        for r in results {
          let id = r.get("id").and_then(|x| x.as_str()).unwrap_or("?");
          let pass = r.get("pass").and_then(|x| x.as_bool()).unwrap_or(false);
          let expected = r.get("expected").and_then(|x| x.as_str()).unwrap_or("?");
          let observed = r.get("observed").and_then(|x| x.as_str()).unwrap_or("?");
          let lat = r.get("latency_ms").and_then(|x| x.as_u64()).unwrap_or(0);
          out.push_str(&format!(
            "drill {id:<10} {}  expected: {expected}  observed: {observed}  ({lat}ms)\n",
            if pass { "PASS" } else { "FAIL" }
          ));
        }
      }
      if let Some(ch) = v.get("extra").and_then(|e| e.get("channels")) {
        let inventory = ch.get("inventory").and_then(|r| r.as_array()).cloned().unwrap_or_default();
        if inventory.is_empty() {
          out.push_str("channels: no census yet — run `castellan channels run`\n");
        } else {
          out.push_str("channel inventory (kernel-verified, dated):\n");
          for c in inventory {
            let name = c.get("channel").and_then(|x| x.as_str()).unwrap_or("?");
            let verdict = c.get("verdict").and_then(|x| x.as_str()).unwrap_or("?");
            out.push_str(&format!("  {name:<12} {verdict}\n"));
          }
        }
      }
      if let Some(mem) = v.get("extra").and_then(|e| e.get("memory")) {
        if let Some(recall) = mem.get("recall") {
          if recall.is_null() {
            out.push_str("memory: no recall (cold start, self, or below gate)\n");
          } else {
            let response = recall.get("response").and_then(|x| x.as_str()).unwrap_or("?");
            let confidence = recall.get("confidence").and_then(|x| x.as_f64()).unwrap_or(0.0);
            let self_match = recall.get("self_match").and_then(|x| x.as_bool()).unwrap_or(false);
            let activations = recall.get("activations").and_then(|x| x.as_u64()).unwrap_or(0);
            out.push_str(&format!(
              "memory: recall {} (confidence {:.2}, {} activations{})\n",
              response,
              confidence,
              activations,
              if self_match { ", SELF" } else { "" }
            ));
          }
        } else {
          let iw = mem.get("incident_writes").and_then(|x| x.as_u64()).unwrap_or(0);
          let sw = mem.get("self_writes").and_then(|x| x.as_u64()).unwrap_or(0);
          let ss = mem.get("self_shapes").and_then(|x| x.as_u64()).unwrap_or(0);
          out.push_str(&format!("memory: {iw} incident(s), {sw} self write(s), {ss} self shape(s)\n"));
        }
      }
      if let Some(tr) = v.get("extra").and_then(|e| e.get("trace")) {
        let compromised = tr.get("compromised").and_then(|x| x.as_str()).unwrap_or("?");
        let exposed = tr.get("exposed").and_then(|x| x.as_array()).cloned().unwrap_or_default();
        out.push_str(&format!("trace: compromised {compromised}\n"));
        if exposed.is_empty() {
          out.push_str("  no exposed sessions\n");
        } else {
          for e in exposed.iter().take(10) {
            let s = e.get("session").and_then(|x| x.as_str()).unwrap_or("?");
            let score = e.get("score").and_then(|x| x.as_f64()).unwrap_or(0.0);
            let files = e.get("exposed_files").and_then(|x| x.as_array()).cloned().unwrap_or_default();
            out.push_str(&format!(
              "  {s}: score {score:.2} — {} file(s): {}\n",
              files.len(),
              files
                .iter()
                .take(5)
                .map(|f| f.as_str().unwrap_or("?").to_string())
                .collect::<Vec<_>>()
                .join(", ")
            ));
          }
        }
        out.push_str("  note: exposure is a lower bound (reads are invisible); freeze is offered, not applied\n");
      }
      if let Some(tr) = v.get("extra").and_then(|e| e.get("trust")) {
        let score = tr.get("score").and_then(|x| x.as_f64()).unwrap_or(0.0);
        let tier = tr.get("tier").and_then(|x| x.as_str()).unwrap_or("?");
        out.push_str(&format!("trust: score {score:.1} (tier {tier})\n"));
      }
      if let Some(pf) = v.get("extra").and_then(|e| e.get("profile")) {        let enforce = pf.get("enforce").and_then(|x| x.as_bool()).unwrap_or(false);
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
  eprintln!("  castellan launch [--harness H] [--project P] [--no-enforce] [--undo] [--net] -- CMD [args...]");
  eprintln!("  castellan audit <session>     show envelope violations for a session");
  eprintln!("  castellan adopt <session> <pid> [pid...]   move running procs into a scope");
  eprintln!("  castellan bless request --session S --want W [--reason R]");
  eprintln!("  castellan bless approve <nonce>   approve an expansion (human only)");
  eprintln!("  castellan bless reject <nonce>    reject an expansion");
  eprintln!("  castellan cert <session>          assemble a ProofCertificate");
  eprintln!("  castellan replay <session> [narrower-project]   permissive-case delta");
  eprintln!("  castellan radar <session> [project]   HV fingerprint + anomaly flag (opt-in)");
  eprintln!("  castellan drill [run|status]           live-fire self-test suite (P8)");
  eprintln!("  castellan channels [run|status]        exfil channel census (P9.1, report-only)");
  eprintln!("  castellan trace <session>              contact tracing (P9.3, exposure scored)");
  eprintln!("  castellan policycheck <proj> <cand>    policy regression replay (P9.6, advisory)");
  eprintln!("  castellan memory [recall <session>|status]   immune memory (P8.1, advisory)");
  eprintln!("  castellan voice approve <session> <utterance>   acoustic channel (P8.3)");
  eprintln!("  castellan daemon                 start the daemon (foreground)");
  std::process::exit(2);
}
