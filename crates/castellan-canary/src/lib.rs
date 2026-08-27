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
}

impl Honeypot {
  /// Bind on a kernel-assigned port and start the accept thread.
  /// Returns immediately; the thread runs for the daemon's lifetime.
  pub fn start(state_home: &Path) -> io::Result<Self> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let secrets: Registry = Arc::new(Mutex::new(HashMap::new()));
    let sink_dir = state_home.to_path_buf();
    std::fs::create_dir_all(&sink_dir)?;

    let reg = Arc::clone(&secrets);
    let sink_dir_thread = sink_dir.clone();
    std::thread::Builder::new().name("honeypot".into()).spawn(move || {
      for stream in listener.incoming() {
        match stream {
          Ok(s) => handle_conn(s, &reg, &sink_dir_thread),
          Err(_) => continue,
        }
      }
    })?;

    Ok(Self { port, secrets })
  }

  /// Fallback when binding fails: no port, registrations accepted but
  /// inert (no trip detection).
  pub fn detached() -> Self {
    Self { port: 0, secrets: Arc::new(Mutex::new(HashMap::new())) }
  }

  pub fn register(&self, secret: &CanarySecret) {
    self.secrets.lock().unwrap().insert(secret.value.clone(), secret.session.clone());
  }

  #[cfg(test)]
  pub fn secret_count(&self) -> usize {
    self.secrets.lock().unwrap().len()
  }
}

fn handle_conn(mut stream: TcpStream, registry: &Registry, state_home: &Path) {
  let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
  let mut buf = vec![0u8; 8192];
  let mut total = Vec::new();
  loop {
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
