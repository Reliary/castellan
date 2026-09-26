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
  let mut chunked = false;
  for h in req.headers.iter() {
    let name = h.name.to_ascii_lowercase();
    if STRIP.contains(&name.as_str()) {
      continue;
    }
    if name == "host" {
      seen_host = true;
    }
    if name == "content-length" {
      content_length = std::str::from_utf8(h.value).ok().and_then(|v| v.trim().parse().ok());
    }
    if name == "transfer-encoding" {
      chunked = std::str::from_utf8(h.value).map(|v| v.to_ascii_lowercase().contains("chunked")).unwrap_or(false);
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
  out.push_str("Connection: close\r\n\r\n");
  Ok(ReqHead {
    method,
    target,
    head: out.into_bytes(),
    content_length,
    chunked,
  })
}

fn forward_body<R: Read, W: Write>(
  client: &mut R,
  up: &mut W,
  req: &ReqHead,
  prefix: &[u8],
) -> std::io::Result<()> {
  if req.chunked {
    return forward_chunked(client, up, prefix);
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

fn forward_chunked<R: Read, W: Write>(client: &mut R, up: &mut W, prefix: &[u8]) -> std::io::Result<()> {
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
    up.write_all(&size_line)?;
    let text = String::from_utf8_lossy(&size_line);
    let size = usize::from_str_radix(text.trim().split(';').next().unwrap_or("").trim(), 16)
      .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "chunk size"))?;
    if size == 0 {
      loop {
        let b = next_byte!();
        up.write_all(&[b])?;
        if b == b'\n' && size_line.last() == Some(&b'\n') {
          break;
        }
        size_line.push(b);
        if size_line.ends_with(b"\r\n\r\n") || size_line.ends_with(b"\n\n") {
          break;
        }
      }
      up.flush()?;
      return Ok(());
    }
    let mut left = size + 2;
    let mut buf = [0u8; 8192];
    while left > 0 {
      let want = left.min(buf.len());
      let mut got = 0;
      if !pending.is_empty() {
        let take = pending.len().min(want);
        up.write_all(&pending[..take])?;
        pending.drain(..take);
        got += take;
      } else {
        let r = client.read(&mut buf[..want])?;
        if r == 0 {
          return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "chunk"));
        }
        up.write_all(&buf[..r])?;
        got += r;
      }
      left -= got;
    }
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

  let mut buf = [0u8; 8192];
  loop {
    match up.read(&mut buf) {
      Ok(0) => break,
      Ok(n) => client.write_all(&buf[..n])?,
      Err(e) if is_clean_eof(&e) => break,
      Err(e) => return Err(e),
    }
  }
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

  fn cfg_with(hosts: &[&str], restrict: bool) -> ProxyConfig {
    ProxyConfig {
      session: "t".into(),
      state_dir: std::env::temp_dir(),
      allow_hosts: hosts.iter().map(|s| s.to_string()).collect(),
      restrict,
      keyring: Arc::new(Keyring::empty()),
      client_tls: native_tls_config(),
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
}
