use castellan_core::EventSink;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// A canary secret: random, unique per session, never a real credential.
#[derive(Debug, Clone)]
pub struct CanarySecret {
  pub value: String,
  pub session: String,
}

/// Called when a canary credential is used against the honeypot.
/// The daemon uses this to apply the canary_hit trust signal.
pub type TripCallback = Arc<dyn Fn(&str) + Send + Sync>;

/// Files planted into the session's canary dir. The agent can read them
/// (read roots are broad); using any value against the honeypot trips.
pub struct Planted {
  pub dir: PathBuf,
  pub secrets: Vec<CanarySecret>,
}

fn rand_hex(n: usize) -> String {
  let mut buf = vec![0u8; n];
  getrandom_fill(&mut buf);
  buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn getrandom_fill(buf: &mut [u8]) {
  // libc getrandom via /dev/urandom (no extra deps)
  use std::fs::File;
  let mut f = File::open("/dev/urandom").expect("urandom");
  f.read_exact(buf).expect("urandom read");
}

/// Plant realistic-looking fake credential files into `dir`.
/// NEVER overwrites an existing file (defensive: if this ever points at
/// real user state, we must not destroy it).
pub fn plant(session: &str, session_scratch: &Path) -> io::Result<Planted> {
  let dir = session_scratch.join("canary");
  std::fs::create_dir_all(&dir)?;

  let aws_key = format!("AKIA{}", rand_hex(10).to_uppercase());
  let aws_secret = rand_hex(20);
  let gh_token = format!("ghp_{}", rand_hex(18));
  let npm_token = format!("npm_{}", rand_hex(18));

  let credentials = format!(
    "[default]\naws_access_key_id = {aws_key}\naws_secret_access_key = {aws_secret}\n"
  );
  let hosts_yml = format!(
    "github.com:\n    oauth_token: {gh_token}\n    user: castellan-canary\n"
  );
  let npmrc = format!("//registry.npmjs.org/:_authToken={npm_token}\n");

  write_if_absent(&dir.join("credentials"), &credentials)?;
  write_if_absent(&dir.join("hosts.yml"), &hosts_yml)?;
  write_if_absent(&dir.join(".npmrc"), &npmrc)?;

  let secrets = vec![
    CanarySecret { value: aws_key, session: session.into() },
    CanarySecret { value: aws_secret, session: session.into() },
    CanarySecret { value: gh_token, session: session.into() },
    CanarySecret { value: npm_token, session: session.into() },
  ];
  Ok(Planted { dir, secrets })
}

fn write_if_absent(path: &Path, content: &str) -> io::Result<()> {
  if path.exists() {
    return Err(io::Error::new(
      io::ErrorKind::AlreadyExists,
      format!("refusing to overwrite existing file {}", path.display()),
    ));
  }
  std::fs::write(path, content)
}

type Registry = Arc<Mutex<HashMap<String, String>>>;

/// Honeypot listener on 127.0.0.1. Any connection whose bytes contain a
/// registered canary secret freezes that session and logs the event.
pub struct Honeypot {
  pub port: u16,
  secrets: Registry,
  ledger: Option<PathBuf>,
  #[allow(dead_code)]
  on_trip: TripCallback,
}

impl Honeypot {
  /// Bind on a kernel-assigned port and start the accept thread.
  /// Returns immediately; the thread runs for the daemon's lifetime.
  /// Previously-registered secrets are reloaded from
  /// `<state_home>/castellan/canary.jsonl` — a daemon restart must not
  /// silently disarm planted canaries (S0 audit fix).
  pub fn start(state_home: &Path) -> io::Result<Self> {
    Self::start_with_callback(state_home, Arc::new(|_| {}))
  }

  pub fn start_with_callback(state_home: &Path, on_trip: TripCallback) -> io::Result<Self> {
    // P8 fault injection: the D2 drill must fail loudly when the
    // honeypot is down. Test-only, env-gated.
    if std::env::var("CASTELLAN_TEST_DISABLE_HONEYPOT").is_ok() {
      return Self::detached_ok();
    }
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let secrets: Registry = Arc::new(Mutex::new(HashMap::new()));
    let sink_dir = state_home.to_path_buf();
    std::fs::create_dir_all(sink_dir.join("castellan"))?;
    let ledger = sink_dir.join("castellan/canary.jsonl");

    for (secret, session) in load_canary_ledger(&ledger) {
      secrets.lock().unwrap().insert(secret, session);
    }

    let reg = Arc::clone(&secrets);
    let sink_dir_thread = sink_dir.clone();
    let cb = Arc::clone(&on_trip);
    // connection cap: bounds thread count against a connect-flooding agent
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let active_thread = Arc::clone(&active);
    std::thread::Builder::new().name("honeypot".into()).spawn(move || {
      for stream in listener.incoming() {
        match stream {
          Ok(s) => {
            if active_thread.load(std::sync::atomic::Ordering::Relaxed) >= MAX_CONNS {
              continue; // drop: the stream closes when it leaves this scope
            }
            active_thread.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let reg = Arc::clone(&reg);
            let sink = sink_dir_thread.clone();
            let cb = Arc::clone(&cb);
            let active = Arc::clone(&active_thread);
            let _ = std::thread::Builder::new().name("honeypot-conn".into()).spawn(move || {
              handle_conn(s, &reg, &sink, &cb);
              active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            });
          }
          Err(_) => continue,
        }
      }
    })?;

    Ok(Self { port, secrets, ledger: Some(ledger), on_trip })
  }

  /// Fallback when binding fails: no port, registrations accepted but
  /// inert (no trip detection).
  pub fn detached() -> Self {
    Self {
      port: 0,
      secrets: Arc::new(Mutex::new(HashMap::new())),
      ledger: None,
      on_trip: Arc::new(|_| {}),
    }
  }

  /// P8 fault injection: a honeypot that is *successfully* detached
  /// (port 0, no listener) so the D2 drill can observe the failure.
  fn detached_ok() -> io::Result<Self> {
    Ok(Self::detached())
  }

  pub fn register(&self, secret: &CanarySecret) {
    // durable registration: survives daemon restarts. Append-only;
    // duplicates are harmless (reload is last-wins into a HashMap).
    if let Some(ledger) = &self.ledger {
      use std::io::Write as _;
      if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(ledger) {
        let _ = writeln!(
          f,
          "{}",
          serde_json::json!({"secret": secret.value, "session": secret.session})
        );
      }
    }
    self.secrets.lock().unwrap().insert(secret.value.clone(), secret.session.clone());
  }

  #[cfg(test)]
  pub fn secret_count(&self) -> usize {
    self.secrets.lock().unwrap().len()
  }
}

/// Max concurrent honeypot connections. With the 5s total deadline per
/// connection this bounds both thread count and trickle-DoS hold time.
const MAX_CONNS: usize = 16;

fn load_canary_ledger(ledger: &Path) -> Vec<(String, String)> {
  let Ok(content) = std::fs::read_to_string(ledger) else {
    return Vec::new();
  };
  let mut out = Vec::new();
  for line in content.lines() {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
      if let (Some(s), Some(sess)) = (
        v.get("secret").and_then(|x| x.as_str()),
        v.get("session").and_then(|x| x.as_str()),
      ) {
        out.push((s.to_string(), sess.to_string()));
      }
    }
  }
  out
}

fn handle_conn(mut stream: TcpStream, registry: &Registry, state_home: &Path, on_trip: &TripCallback) {
  let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
  // hard total deadline: a trickle-feeding client cannot hold this
  // connection (and its thread) beyond 5s regardless of read timing
  let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
  let mut buf = vec![0u8; 8192];
  let mut total = Vec::new();
  loop {
    if std::time::Instant::now() > deadline {
      break;
    }
    match stream.read(&mut buf) {
      Ok(0) | Err(_) => break,
      Ok(n) => {
        total.extend_from_slice(&buf[..n]);
        if total.len() > 1 << 20 {
          break;
        }
        // respond fast so the client doesn't stall
        let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
      }
    }
  }
  let haystack = String::from_utf8_lossy(&total);
  let hit: Option<(String, String)> = {
    let reg = registry.lock().unwrap();
    reg
      .iter()
      .find(|(secret, _)| haystack.contains(secret.as_str()))
      .map(|(s, sess)| (s.clone(), sess.clone()))
  };
  if let Some((secret, session)) = hit {
    eprintln!(
      "castellan-canary: TRIP — canary credential used by session {session}"
    );
    log_trip(state_home, &session, &secret);
    freeze_session(&session);
    on_trip(&session);
    let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
  }
}

fn log_trip(state_home: &Path, session: &str, secret: &str) {
  if let Ok(sink) = EventSink::for_session(state_home, session) {
    let _ = sink.emit("canary_trip", &format!("secret_prefix={}", &secret[..secret.len().min(8)]), "frozen");
  }
}

fn freeze_session(session: &str) {
  match castellan_freezer::CgroupRoot::detect() {
    Ok(root) => {
      if let Err(e) = root.set_freeze(&session.to_string(), true) {
        eprintln!("castellan-canary: auto-freeze failed: {e:?}");
      }
    }
    Err(e) => eprintln!("castellan-canary: no cgroup root, cannot freeze: {e}"),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn temp_state(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("castellan-canary-test-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    dir
  }

  #[test]
  fn secrets_survive_restart() {
    let state = temp_state("persist");
    let hp = Honeypot::start(&state).unwrap();
    hp.register(&CanarySecret { value: "AKIATESTSECRET".into(), session: "s1".into() });
    assert_eq!(hp.secret_count(), 1);
    drop(hp);
    // simulate a daemon restart: new honeypot on the same state dir
    let hp2 = Honeypot::start(&state).unwrap();
    assert_eq!(hp2.secret_count(), 1, "canary registration must survive restart");
    let _ = std::fs::remove_dir_all(&state);
  }

  #[test]
  fn ledger_reload_skips_malformed_lines() {
    let state = temp_state("malformed");
    std::fs::create_dir_all(state.join("castellan")).unwrap();
    let ledger = state.join("castellan/canary.jsonl");
    std::fs::write(
      &ledger,
      "{\"secret\":\"ghp_good\",\"session\":\"s1\"}\nnot json at all\n{\"secret\":\"npm_also_good\",\"session\":\"s2\"}\n",
    )
    .unwrap();
    let loaded = load_canary_ledger(&ledger);
    assert_eq!(loaded.len(), 2);
    let _ = std::fs::remove_dir_all(&state);
  }

  #[test]
  fn detached_registers_without_ledger() {
    let hp = Honeypot::detached();
    hp.register(&CanarySecret { value: "x".into(), session: "s".into() });
    assert_eq!(hp.secret_count(), 1);
  }
}
