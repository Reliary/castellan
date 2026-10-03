use castellan_keyring::Keyring;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const MAX_HEAD: usize = 64 * 1024;

pub struct ProxyConfig {
  pub session: String,
  pub state_dir: PathBuf,
  pub allow_hosts: Vec<String>,
  pub restrict: bool,
  pub keyring: Arc<Keyring>,
  pub client_tls: Arc<rustls::ClientConfig>,
  /// P15 H1/F2: loopback destinations the tunnel must never reach —
  /// today that is the session honeypot port. A CONNECT tunnel to it
  /// makes the honeypot-side connection originate from the DAEMON pid
  /// (proxy threads live in the daemon), which would defeat sender
  /// attribution and re-frame the secret's owner. Checked before
  /// `allowed()`, so it holds in both proxy postures.
  pub deny_ports: Vec<u16>,
}

pub struct ProxyHandle {
  pub port: u16,
  pub ca_path: PathBuf,
  running: Arc<AtomicBool>,
}

impl Drop for ProxyHandle {
  fn drop(&mut self) {
    self.running.store(false, Ordering::SeqCst);
  }
}

/// System-trust upstream TLS. The daemon builds this once; tests build
/// their own config trusting a stub CA (no insecure switch is shipped).
pub fn native_tls_config() -> Arc<rustls::ClientConfig> {
  install_crypto();
  let mut roots = rustls::RootCertStore::empty();
  for c in rustls_native_certs::load_native_certs().certs {
    let _ = roots.add(c);
  }
  Arc::new(
    rustls::ClientConfig::builder()
      .with_root_certificates(roots)
      .with_no_client_auth(),
  )
}

struct Ca {
  cert: rcgen::Certificate,
  key: rcgen::KeyPair,
}

fn make_ca() -> Result<Ca, String> {
  let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
  let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
  params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
  // explicit CA key usage: python/OpenSSL3 refuses a CA without KU
  // keyCertSign ("CA cert does not include key usage extension").
  params.key_usages = vec![
    rcgen::KeyUsagePurpose::KeyCertSign,
    rcgen::KeyUsagePurpose::CrlSign,
    rcgen::KeyUsagePurpose::DigitalSignature,
  ];
  let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
  Ok(Ca { cert, key })
}

pub fn install_crypto() {
  static ONCE: std::sync::Once = std::sync::Once::new();
  ONCE.call_once(|| {
    let _ = rustls::crypto::ring::default_provider().install_default();
  });
}

pub fn start(cfg: ProxyConfig) -> std::io::Result<ProxyHandle> {
  install_crypto();
  let ca = make_ca().map_err(|e| std::io::Error::other(format!("ca: {e}")))?;
  let dir = cfg.state_dir.join("castellan/sessions").join(&cfg.session);
  std::fs::create_dir_all(&dir)?;
  let ca_path = dir.join("ca.pem");
  std::fs::write(&ca_path, ca.cert.pem())?;

  let listener = TcpListener::bind(("127.0.0.1", 0))?;
  let port = listener.local_addr()?.port();
  listener.set_nonblocking(true)?;
  let running = Arc::new(AtomicBool::new(true));

  let spine = Arc::new(Mutex::new(
    castellan_core::EventSink::for_session(&cfg.state_dir, &cfg.session)
      .map_err(|e| std::io::Error::other(format!("spine: {e}")))?,
  ));
  let cfg = Arc::new(cfg);
  let ca = Arc::new(ca);
  let flag = running.clone();

  std::thread::Builder::new().name(format!("proxy-{port}")).spawn(move || {
    while flag.load(Ordering::SeqCst) {
      match listener.accept() {
        Ok((sock, _)) => {
          let cfg = cfg.clone();
          let ca = ca.clone();
          let spine = spine.clone();
          let _ = std::thread::Builder::new()
            .name("proxy-conn".into())
            .spawn(move || {
              let _ = handle_conn(sock, &cfg, &ca, &spine);
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
          std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Err(_) => break,
      }
    }
  })?;

  Ok(ProxyHandle { port, ca_path, running })
}

fn emit(spine: &Mutex<castellan_core::EventSink>, kind: &str, path: &str, verdict: &str) {
  if let Ok(s) = spine.lock() {
    let _ = s.emit(kind, path, verdict);
  }
}

/// P15 F2 pure predicate: refuse to tunnel when the destination port is
/// deny-listed AND the host is loopback (the honeypot binds loopback
/// only). A public host on the same port is not the honeypot — that is
/// the broker's decision, not this one. Split out of `handle_conn` so
/// the table is unit-pinnable without sockets.
fn honeypot_tunnel_denied(deny_ports: &[u16], host: &str, port: u16) -> bool {
  if !deny_ports.contains(&port) {
    return false;
  }
  // parse_connect already strips brackets today; tolerate them here so a
  // future caller cannot fail open on "[::1]".
  let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
  if let Ok(ip) = host.parse::<std::net::IpAddr>() {
    return ip.is_loopback();
  }
  host.eq_ignore_ascii_case("localhost")
}

fn allowed(cfg: &ProxyConfig, host: &str) -> bool {
  if !cfg.restrict {
    return true;
  }
  cfg.allow_hosts.iter().any(|p| {
    if let Some(suffix) = p.strip_prefix("*.") {
      host.ends_with(suffix) && host.len() > suffix.len() && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
    } else {
      p == host
    }
  })
}

fn parse_connect(head: &[u8]) -> Option<(String, u16)> {
  let line_end = head.windows(2).position(|w| w == b"\r\n")?;
  let line = std::str::from_utf8(&head[..line_end]).ok()?;
  let mut parts = line.split_whitespace();
  if parts.next()? != "CONNECT" {
    return None;
  }
  let authority = parts.next()?;
  let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
    let close = rest.find(']')?;
    let h = &rest[..close];
    let p = rest[close + 1..].strip_prefix(':')?;
    (h.to_string(), p.parse().ok()?)
  } else {
    let (h, p) = authority.rsplit_once(':')?;
    (h.to_string(), p.parse().ok()?)
  };
  Some((host, port))
}

fn read_head<R: Read>(r: &mut R) -> std::io::Result<Vec<u8>> {
  let mut buf = Vec::with_capacity(512);
  let mut b = [0u8; 1];
  loop {
    let n = r.read(&mut b)?;
    if n == 0 {
      return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "head"));
    }
    buf.push(b[0]);
    if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
      return Ok(buf);
    }
    if buf.len() > MAX_HEAD {
      return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "head too large"));
    }
  }
}

fn raw_respond(sock: &mut TcpStream, status: &str) {
  let body = format!(
    "<html><body><h1>{}</h1></body></html>",
    status
  );
  let msg = format!(
    "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
    body.len(),
    body
  );
  let _ = sock.write_all(msg.as_bytes());
  let _ = sock.flush();
}

fn handle_conn(
  mut sock: TcpStream,
  cfg: &ProxyConfig,
  ca: &Ca,
  spine: &Mutex<castellan_core::EventSink>,
) -> std::io::Result<()> {
  let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(10)));
  let head = match read_head(&mut sock) {
    Ok(h) => h,
    Err(_) => return Ok(()),
  };
  let _ = sock.set_read_timeout(None);

  let Some((host, port)) = parse_connect(&head) else {
    raw_respond(&mut sock, "501 Not Implemented");
    return Ok(());
  };

  // P15 H1/F2: never tunnel to a deny-listed loopback port (the
  // honeypot). Before allowed(), so both proxy postures enforce it.
  if honeypot_tunnel_denied(&cfg.deny_ports, &host, port) {
    emit(spine, "egress_deny", &host, "honeypot-tunnel");
    raw_respond(&mut sock, "403 Forbidden");
    return Ok(());
  }

  if !allowed(cfg, &host) {
    emit(spine, "egress_deny", &host, "allowlist");
    raw_respond(&mut sock, "403 Forbidden");
    return Ok(());
  }

  let upstream = match TcpStream::connect(format_host_port(&host, port)) {
    Ok(u) => u,
    Err(_) => {
      emit(spine, "egress_deny", &host, "upstream-unreachable");
      raw_respond(&mut sock, "502 Bad Gateway");
      return Ok(());
    }
  };

  sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
  sock.flush()?;

  let server_cfg = leaf_server_config(&host, ca)?;
  let sock2 = sock.try_clone()?;
  let server_conn =
    rustls::ServerConnection::new(server_cfg).map_err(std::io::Error::other)?;
  let mut client_side = rustls::StreamOwned::new(server_conn, sock2);

  let server_name = rustls::pki_types::ServerName::try_from(host.clone())
    .map_err(|_| std::io::Error::other("bad server name"))?;
  let up_conn =
    rustls::ClientConnection::new(cfg.client_tls.clone(), server_name).map_err(std::io::Error::other)?;
  let mut up_side = rustls::StreamOwned::new(up_conn, upstream);

  exchange(&mut client_side, &mut up_side, &host, cfg, spine)
}

fn format_host_port(host: &str, port: u16) -> String {
  if host.contains(':') && !host.starts_with('[') {
    format!("[{host}]:{port}")
  } else {
    format!("{host}:{port}")
  }
}

fn leaf_server_config(host: &str, ca: &Ca) -> std::io::Result<Arc<rustls::ServerConfig>> {
  let leaf_key = rcgen::KeyPair::generate().map_err(|e| std::io::Error::other(e.to_string()))?;
  let mut params = rcgen::CertificateParams::new(vec![host.to_string()])
    .map_err(|e| std::io::Error::other(format!("leaf params: {e}")))?;
  // non-empty subject DN: with an empty subject, RFC5280 requires the
  // SAN extension be marked critical — python's ssl enforces this
  // ("Subject empty and Subject Alt Name extension not critical"),
  // rustls does not, so an empty DN broke exactly one client class.
  let mut dn = rcgen::DistinguishedName::new();
  dn.push(rcgen::DnType::CommonName, host);
  params.distinguished_name = dn;
  // AKI on the leaf: rcgen defaults it off, python/OpenSSL3 refuses a
  // leaf whose issuer has an SKI but the leaf no AKI ("Missing
  // Authority Key Identifier"). rustls accepts either.
  params.use_authority_key_identifier_extension = true;
  params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
  params.key_usages = vec![
    rcgen::KeyUsagePurpose::DigitalSignature,
    rcgen::KeyUsagePurpose::KeyEncipherment,
  ];
  let leaf = params
    .signed_by(&leaf_key, &ca.cert, &ca.key)
    .map_err(|e| std::io::Error::other(format!("leaf sign: {e}")))?;
  let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
  let mut scfg = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(vec![leaf.der().clone()], key_der.into())
    .map_err(|e| std::io::Error::other(format!("server cert: {e}")))?;
  scfg.alpn_protocols = vec![b"http/1.1".to_vec()];
  Ok(Arc::new(scfg))
}

const STRIP: [&str; 4] = ["authorization", "proxy-authorization", "x-api-key", "api-key"];

struct ReqHead {
  method: String,
  target: String,
  head: Vec<u8>,
  content_length: Option<usize>,
  chunked: bool,
}

/// R6: all trailers are dropped structurally (dechunk never forwards
/// them), so no STRIP-class header can smuggle past the head filter via
/// trailers. No allowlist needed — trailers carry no legitimate proxy
/// function.
fn rewrite_request(raw: &[u8], host: &str, cfg: &ProxyConfig) -> std::io::Result<ReqHead> {
  let mut headers = [httparse::EMPTY_HEADER; 64];
  let mut req = httparse::Request::new(&mut headers);
  let _len = match req.parse(raw) {
    Ok(httparse::Status::Complete(n)) => n,
    _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad request head")),
  };
  let method = req.method.unwrap_or("").to_string();
  let target = req.path.unwrap_or("/").to_string();
  let mut out = format!("{method} {target} HTTP/1.1\r\n");
  let mut seen_host = false;
  let mut content_length = None;
  let mut content_length_seen = 0u32;
  let mut was_chunked = false;
  // R6 (ninja review): normalize framing. Duplicate Content-Length is a
  // classic desync vector (first-vs-last); Transfer-Encoding + CL cohabit
  // is another; trailers can smuggle STRIP-class headers past the head
  // filter. Policy: reject duplicate CL (400-class InvalidData), drop TE
  // entirely (de-chunk to identity below), strip trailers.
  for h in req.headers.iter() {
    let name = h.name.to_ascii_lowercase();
    if STRIP.contains(&name.as_str()) {
      continue;
    }
    if name == "host" {
      seen_host = true;
    }
    if name == "content-length" {
      content_length_seen += 1;
      if content_length_seen > 1 {
        return Err(std::io::Error::new(
          std::io::ErrorKind::InvalidData,
          "duplicate content-length",
        ));
      }
      content_length = std::str::from_utf8(h.value).ok().and_then(|v| v.trim().parse().ok());
    }
    if name == "transfer-encoding" {
      if std::str::from_utf8(h.value).map(|v| v.to_ascii_lowercase().contains("chunked")).unwrap_or(false) {
        was_chunked = true;
      }
      continue;
    }
    if name == "trailer" {
      continue;
    }
    if name == "connection" {
      continue;
    }
    out.push_str(h.name);
    out.push_str(": ");
    out.push_str(std::str::from_utf8(h.value).unwrap_or(""));
    out.push_str("\r\n");
  }
  if !seen_host {
    out.push_str(&format!("Host: {host}\r\n"));
  }
  if let Some((name, value, _)) = cfg.keyring.inject_for(host) {
    out.push_str(&format!("{name}: {value}\r\n"));
  }
  out.push_str("Connection: close\r\n");
  // R6: when chunked, the head stays UNTERMINATED here — forward_body
  // appends the single Content-Length + blank line after de-chunking.
  // Identity bodies terminate the head normally.
  if !was_chunked {
    out.push_str("\r\n");
  }
  Ok(ReqHead {
    method,
    target,
    head: out.into_bytes(),
    content_length,
    chunked: was_chunked,
  })
}

fn forward_body<R: Read, W: Write>(
  client: &mut R,
  up: &mut W,
  req: &ReqHead,
  prefix: &[u8],
) -> std::io::Result<()> {
  if req.chunked {
    // R6: de-chunk to identity upstream. The head was already written
    // by exchange() — but with TE dropped and no CL. Reframe: decode
    // here and emit a single Content-Length BEFORE the body. Since the
    // head is already on the wire, de-chunking requires head buffering —
    // handled in exchange(): when chunked, exchange() buffers via this
    // path returning the body length first. Simpler honest shape: decode
    // the body, then write a fresh framing line + CL + body.
    let body = dechunk(client, prefix)?;
    up.write_all(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes())?;
    up.write_all(&body)?;
    up.flush()?;
    return Ok(());
  }
  if let Some(n) = req.content_length {
    let mut left = n;
    if !prefix.is_empty() {
      let take = left.min(prefix.len());
      up.write_all(&prefix[..take])?;
      left -= take;
    }
    let mut buf = [0u8; 8192];
    while left > 0 {
      let want = left.min(buf.len());
      let r = client.read(&mut buf[..want])?;
      if r == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "body"));
      }
      up.write_all(&buf[..r])?;
      left -= r;
    }
    up.flush()?;
    return Ok(());
  }
  if !prefix.is_empty() {
    return Err(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "body without length framing",
    ));
  }
  if req.method == "POST" || req.method == "PUT" || req.method == "PATCH" {
    return Err(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "POST without content-length",
    ));
  }
  Ok(())
}

/// R6: decode a chunked body into raw bytes. Trailers are parsed;
/// STRIP-class trailer headers are dropped (they never reach upstream);
/// anything else in trailers is dropped too (upstreams that merge
/// trailers are attacker-influenced). Caps total at 32MB.
fn dechunk<R: Read>(client: &mut R, prefix: &[u8]) -> std::io::Result<Vec<u8>> {
  const CAP: usize = 32 << 20;
  let mut pending = prefix.to_vec();
  let mut scratch = [0u8; 1];
  macro_rules! next_byte {
    () => {
      if !pending.is_empty() {
        let b = pending.remove(0);
        b
      } else {
        let n = client.read(&mut scratch)?;
        if n == 0 {
          return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "chunk"));
        }
        scratch[0]
      }
    };
  }
  let mut body = Vec::new();
  loop {
    let mut size_line = Vec::new();
    loop {
      let b = next_byte!();
      size_line.push(b);
      if size_line.len() >= 2 && &size_line[size_line.len() - 2..] == b"\r\n" {
        break;
      }
      if size_line.len() > 128 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk size"));
      }
    }
    let text = String::from_utf8_lossy(&size_line);
    let size = usize::from_str_radix(text.trim().split(';').next().unwrap_or("").trim(), 16)
      .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk size"))?;
    if size == 0 {
      // consume trailers to the blank line, dropping all of them: after
      // the 0-size line, trailers are 0+ lines ending in one blank line.
      // (Trailer contents are never forwarded, so no per-header scan is
      // needed — the drop is structural.)
      let mut line = Vec::new();
      loop {
        let b = next_byte!();
        line.push(b);
        if line.ends_with(b"\r\n") || line.ends_with(b"\n") {
          if line == b"\r\n" || line == b"\n" {
            break;
          }
          line.clear();
        }
        if line.len() > 8192 {
          return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "trailers"));
        }
      }
      return Ok(body);
    }
    if body.len() + size > CAP {
      return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk cap"));
    }
    let mut left = size + 2;
    let mut buf = [0u8; 8192];
    while left > 0 {
      let want = left.min(buf.len());
      let mut got = 0;
      if !pending.is_empty() {
        let take = pending.len().min(want);
        body.extend_from_slice(&pending[..take]);
        pending.drain(..take);
        got += take;
      } else {
        let r = client.read(&mut buf[..want])?;
        if r == 0 {
          return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "chunk"));
        }
        body.extend_from_slice(&buf[..r]);
        got += r;
      }
      left -= got;
    }
    // strip the trailing CRLF of the chunk data: we appended size+2
    // bytes, of which the last 2 are CRLF.
    let n = body.len();
    body.truncate(n.saturating_sub(2));
  }
}

fn exchange(
  client: &mut rustls::StreamOwned<rustls::ServerConnection, TcpStream>,
  up: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
  host: &str,
  cfg: &ProxyConfig,
  spine: &Mutex<castellan_core::EventSink>,
) -> std::io::Result<()> {
  let raw = read_head(client)?;
  let req = rewrite_request(&raw, host, cfg)?;
  let head_end = {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut r = httparse::Request::new(&mut headers);
    match r.parse(&raw) {
      Ok(httparse::Status::Complete(n)) => n,
      _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad head")),
    }
  };
  let prefix = &raw[head_end..];

  let cred = match cfg.keyring.inject_for(host) {
    Some((_, _, name)) => name.to_string(),
    None => "none".to_string(),
  };
  emit(
    spine,
    "egress_inject",
    &format!("{host} {} {}", req.method, req.target),
    &format!("cred={cred}"),
  );

  up.write_all(&req.head)?;
  forward_body(client, up, &req, prefix)?;
  up.flush()?;

  // R6 (ninja review): response-side secret redaction. The proxy injects
  // the real credential upstream; an echo/reflect endpoint would hand it
  // back to the untrusted agent. Buffer the response (cap 32MB), scan
  // for the injected secret bytes, and terminate with an error (the tunnel drops) rather than rather than
  // deliver a secret-bearing body downstream. No secret injected for
  // this host (cred=none) -> passthrough, nothing to redact.
  let secret: Option<Vec<u8>> = cfg.keyring.inject_for(host).map(|(_, v, _)| v.as_bytes().to_vec());
  let mut resp = Vec::new();
  let mut buf = [0u8; 8192];
  loop {
    match up.read(&mut buf) {
      Ok(0) => break,
      Ok(n) => {
        resp.extend_from_slice(&buf[..n]);
        if resp.len() > (32 << 20) {
          return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "response cap"));
        }
      }
      Err(e) if is_clean_eof(&e) => break,
      Err(e) => return Err(e),
    }
  }
  if let Some(sec) = secret.as_ref() {
    if !sec.is_empty() && resp.windows(sec.len()).any(|w| w == sec.as_slice()) {
      emit(spine, "egress_secret_reflect", host, "redacted");
      return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "upstream reflected credential"));
    }
  }
  client.write_all(&resp)?;
  up.conn.send_close_notify();
  client.conn.send_close_notify();
  client.flush()?;
  Ok(())
}

/// rustls reports a FIN with no pending partial record as
/// UnexpectedEof ("peer closed without close_notify"). Every complete
/// TLS record was already delivered, so it is a clean end-of-response:
/// pipe-until-EOF proxies treat it as Ok(0).
fn is_clean_eof(e: &std::io::Error) -> bool {
  e.kind() == std::io::ErrorKind::UnexpectedEof || e.to_string().contains("close_notify")
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::io::Cursor;

  fn cfg_with(hosts: &[&str], restrict: bool) -> ProxyConfig {
    ProxyConfig {
      session: "t".into(),
      state_dir: std::env::temp_dir(),
      allow_hosts: hosts.iter().map(|s| s.to_string()).collect(),
      restrict,
      keyring: Arc::new(Keyring::empty()),
      client_tls: native_tls_config(),
      deny_ports: vec![],
    }
  }

  #[test]
  fn allowlist_exact_and_wildcard() {
    let c = cfg_with(&["api.github.com", "*.npmjs.org"], true);
    assert!(allowed(&c, "api.github.com"));
    assert!(allowed(&c, "registry.npmjs.org"));
    assert!(!allowed(&c, "evil.com"));
    assert!(!allowed(&c, "npmjs.org"));
    let open = cfg_with(&[], false);
    assert!(allowed(&open, "anything"));
    let deny_all = cfg_with(&[], true);
    assert!(!allowed(&deny_all, "api.github.com"));
  }

  #[test]
  fn connect_line_parsing() {
    assert_eq!(
      parse_connect(b"CONNECT api.github.com:443 HTTP/1.1\r\n\r\n"),
      Some(("api.github.com".into(), 443))
    );
    assert_eq!(
      parse_connect(b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n"),
      Some(("2001:db8::1".into(), 8443))
    );
    assert_eq!(parse_connect(b"GET / HTTP/1.1\r\n\r\n"), None);
    assert_eq!(parse_connect(b"CONNECT noport HTTP/1.1\r\n\r\n"), None);
  }

  #[test]
  fn rewrite_strips_and_injects() {
    let k = Keyring::parse(
      b"[[credential]]\nname=\"gh\"\nscheme=\"bearer\"\ntoken=\"REAL\"\nhosts=[\"api.github.com\"]\n",
    )
    .unwrap();
    let c = ProxyConfig {
      session: "t".into(),
      state_dir: std::env::temp_dir(),
      allow_hosts: vec!["api.github.com".into()],
      restrict: true,
      keyring: Arc::new(k),
      client_tls: native_tls_config(),
      deny_ports: vec![],
    };
    let raw = b"POST /v1/chat HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: Bearer canary\r\nX-API-Key: canary2\r\nContent-Length: 2\r\n\r\n{}";
    let req = rewrite_request(raw, "api.github.com", &c).unwrap();
    let head = String::from_utf8_lossy(&req.head).to_string();
    assert!(!head.to_lowercase().contains("canary"), "canary must be stripped: {head}");
    assert!(head.contains("authorization: Bearer REAL"), "real cred must be injected: {head}");
    assert!(head.contains("Connection: close"));
    assert_eq!(req.content_length, Some(2));
  }

  #[test]
  fn rewrite_without_binding_injects_nothing() {
    let c = cfg_with(&["open.host"], true);
    let raw = b"GET / HTTP/1.1\r\nHost: open.host\r\nAuthorization: Bearer canary\r\n\r\n";
    let req = rewrite_request(raw, "open.host", &c).unwrap();
    let head = String::from_utf8_lossy(&req.head).to_string();
    assert!(!head.to_lowercase().contains("authorization"), "{head}");
    assert!(!head.contains("Bearer"), "{head}");
  }


  #[test]
  fn duplicate_cl_rejected() {
    let cfg = cfg_with(&[], false);
    let raw = b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc";
    assert!(rewrite_request(raw, "h", &cfg).is_err());
  }

  #[test]
  fn te_dropped_and_dechunked() {
    let cfg = cfg_with(&[], false);
    let raw = b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    let req = rewrite_request(raw, "h", &cfg).unwrap();
    assert!(req.chunked);
    assert!(!req.head.windows(17).any(|w| w == b"Transfer-Encoding"));
    // de-chunk "3\r\nabc\r\n0\r\n\r\n" -> body abc, single CL downstream
    let mut up = Vec::new();
    let mut client = std::io::Cursor::new(b"3\r\nabc\r\n0\r\n\r\n".to_vec());
    forward_body(&mut client, &mut up, &req, &[]).unwrap();
    assert!(up.starts_with(b"Content-Length: 3\r\n\r\n"));
    assert!(up.ends_with(b"abc"));
  }

  #[test]
  fn trailer_auth_dropped() {
    let cfg = cfg_with(&[], false);
    let raw = b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
    let req = rewrite_request(raw, "h", &cfg).unwrap();
    let mut up = Vec::new();
    let mut client = std::io::Cursor::new(b"1\r\na\r\n0\r\nAuthorization: smuggled\r\n\r\n".to_vec());
    forward_body(&mut client, &mut up, &req, &[]).unwrap();
    assert!(!up.windows(13).any(|w| w == b"Authorization"));
    assert!(up.ends_with(b"a"));
  }

  // P15 F2 unit pin: the deny table that keeps a tunnel from
  // laundering honeypot attribution through the daemon pid.
  #[test]
  fn honeypot_tunnel_denied_table() {
    let d = &[9077u16];
    assert!(honeypot_tunnel_denied(d, "127.0.0.1", 9077));
    assert!(honeypot_tunnel_denied(d, "127.0.0.2", 9077));
    assert!(honeypot_tunnel_denied(d, "::1", 9077));
    assert!(honeypot_tunnel_denied(d, "[::1]", 9077));
    assert!(honeypot_tunnel_denied(d, "localhost", 9077));
    assert!(honeypot_tunnel_denied(d, "LOCALHOST", 9077));
    assert!(!honeypot_tunnel_denied(d, "127.0.0.1", 443));
    assert!(!honeypot_tunnel_denied(d, "example.com", 9077));
    assert!(!honeypot_tunnel_denied(d, "192.168.1.5", 9077));
    assert!(!honeypot_tunnel_denied(&[], "127.0.0.1", 9077));
  }
}

#[cfg(feature = "fuzz")]
pub mod fuzz_api {
  use super::{native_tls_config, Keyring, ProxyConfig};
  use std::sync::OnceLock;

  pub fn parse_connect(head: &[u8]) -> Option<(String, u16)> {
    super::parse_connect(head)
  }

  fn fuzz_cfg() -> &'static ProxyConfig {
    static CFG: OnceLock<ProxyConfig> = OnceLock::new();
    CFG.get_or_init(|| ProxyConfig {
      session: "fuzz".into(),
      state_dir: std::env::temp_dir(),
      allow_hosts: vec![],
      restrict: false,
      keyring: std::sync::Arc::new(
        Keyring::parse(
          b"[[credential]]\nname=\"gh\"\nscheme=\"bearer\"\ntoken=\"REAL\"\nhosts=[\"api.github.com\"]\n",
        )
        .expect("fixed keyring blob is valid (covered by unit test)"),
      ),
      client_tls: native_tls_config(),
      deny_ports: vec![],
    })
  }

  pub fn rewrite_request(raw: &[u8], host: &str) {
    let _ = super::rewrite_request(raw, host, fuzz_cfg());
  }
}
