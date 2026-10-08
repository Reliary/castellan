use castellan_keyring::Keyring;
use castellan_proxy::{install_crypto, native_tls_config, start, ProxyConfig};
use rustls::pki_types::pem::PemObject;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, LazyLock, Mutex};

struct StubId {
  pem: String,
  server_cfg: Arc<rustls::ServerConfig>,
}

static STUB: LazyLock<StubId> = LazyLock::new(|| {
  install_crypto();
  let key = rcgen::KeyPair::generate().unwrap();
  let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
  let cert = params.self_signed(&key).unwrap();
  let server_cfg = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(
      vec![cert.der().clone()],
      rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
  StubId { pem: cert.pem(), server_cfg: Arc::new(server_cfg) }
});

static STUB_CLIENT_TLS: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
  install_crypto();
  let mut roots = rustls::RootCertStore::empty();
  roots
    .add(rustls::pki_types::CertificateDer::from_pem_slice(STUB.pem.as_bytes()).expect("stub pem"))
    .expect("stub root");
  Arc::new(
    rustls::ClientConfig::builder()
      .with_root_certificates(roots)
      .with_no_client_auth(),
  )
});

struct StubHit {
  headers: String,
  body: String,
}

fn stub_tls_server() -> (u16, Arc<Mutex<Vec<StubHit>>>) {
  let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
  let port = listener.local_addr().unwrap().port();
  let hits: Arc<Mutex<Vec<StubHit>>> = Arc::new(Mutex::new(Vec::new()));
  let hits2 = hits.clone();
  std::thread::spawn(move || {
    for s in listener.incoming() {
      let Ok(sock) = s else { continue };
      let cfg = STUB.server_cfg.clone();
      let hits = hits2.clone();
      std::thread::spawn(move || {
        let conn = rustls::ServerConnection::new(cfg).unwrap();
        let mut tls = rustls::StreamOwned::new(conn, sock);
        let mut buf = Vec::new();
        let mut b = [0u8; 1];
        loop {
          match tls.read(&mut b) {
            Ok(0) | Err(_) => return,
            Ok(_) => {
              buf.push(b[0]);
              if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
                break;
              }
              if buf.len() > 65536 {
                return;
              }
            }
          }
        }
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);
        let n = match req.parse(&buf) {
          Ok(httparse::Status::Complete(n)) => n,
          _ => return,
        };
        let mut body = buf[n..].to_vec();
        let cl = req
          .headers
          .iter()
          .find(|h| h.name.eq_ignore_ascii_case("content-length"))
          .and_then(|h| std::str::from_utf8(h.value).ok())
          .and_then(|v| v.trim().parse::<usize>().ok())
          .unwrap_or(0);
        while body.len() < cl {
          let mut tmp = [0u8; 4096];
          match tls.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(r) => body.extend_from_slice(&tmp[..r]),
          }
        }
        hits.lock().unwrap().push(StubHit {
          headers: String::from_utf8_lossy(&buf[..n]).to_string(),
          body: String::from_utf8_lossy(&body).to_string(),
        });
        let _ =
          tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        let _ = tls.flush();
      });
    }
  });
  (port, hits)
}

fn read_head_from<R: Read>(r: &mut R) -> Result<Vec<u8>, String> {
  let mut out = Vec::new();
  let mut b = [0u8; 1];
  loop {
    match r.read(&mut b) {
      Ok(0) => return Err("eof in head".into()),
      Ok(_) => {
        out.push(b[0]);
        if out.len() >= 4 && &out[out.len() - 4..] == b"\r\n\r\n" {
          return Ok(out);
        }
        if out.len() > 65536 {
          return Err("head too large".into());
        }
      }
      Err(e) => return Err(format!("read: {e}")),
    }
  }
}

fn tunnel_request(
  ca_pem: &str,
  proxy_port: u16,
  upstream_port: u16,
  request: &str,
) -> Result<String, String> {
  install_crypto();
  let mut roots = rustls::RootCertStore::empty();
  roots
    .add(
      rustls::pki_types::CertificateDer::from_pem_slice(ca_pem.as_bytes()).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
  let client_cfg = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();

  let sock = TcpStream::connect(("127.0.0.1", proxy_port)).map_err(|e| e.to_string())?;
  let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(10)));
  let mut sock = sock;
  sock
    .write_all(format!("CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\n\r\n").as_bytes())
    .map_err(|e| e.to_string())?;
  let conn_head = read_head_from(&mut sock)?;
  let head = String::from_utf8_lossy(&conn_head).to_string();
  if !head.starts_with("HTTP/1.1 200") {
    return Err(format!("connect refused: {head}"));
  }
  let server_name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string())
    .map_err(|e| e.to_string())?;
  let conn = rustls::ClientConnection::new(Arc::new(client_cfg), server_name)
    .map_err(|e| e.to_string())?;
  let mut tls = rustls::StreamOwned::new(conn, sock);
  tls.write_all(request.as_bytes()).map_err(|e| e.to_string())?;
  tls.flush().map_err(|e| e.to_string())?;
  let mut out = Vec::new();
  loop {
    let mut buf = [0u8; 4096];
    match tls.read(&mut buf) {
      Ok(0) => break,
      Ok(r) => out.extend_from_slice(&buf[..r]),
      Err(e) => return Err(format!("read: {e}")),
    }
  }
  Ok(String::from_utf8_lossy(&out).to_string())
}

fn fresh_state(tag: &str) -> std::path::PathBuf {
  let w = std::env::temp_dir().join(format!("castellan-p12-{tag}-{}", std::process::id()));
  let _ = std::fs::remove_dir_all(&w);
  std::fs::create_dir_all(&w).unwrap();
  w
}

#[test]
fn k2_injects_real_rejects_canary() {
  let (port, hits) = stub_tls_server();
  let keyring = r#"
[[credential]]
name = "stub"
scheme = "bearer"
token = "REAL-SECRET"
hosts = ["127.0.0.1"]
"#;
  let cfg = ProxyConfig {
    session: "k2".into(),
    state_dir: fresh_state("k2"),
    allow_hosts: vec!["127.0.0.1".into()],
    restrict: true,
    keyring: Arc::new(Keyring::parse(keyring.as_bytes()).unwrap()),
    client_tls: STUB_CLIENT_TLS.clone(),
    deny_ports: vec![],
  };
  let h = start(cfg).unwrap();
  let ca_pem = std::fs::read_to_string(&h.ca_path).unwrap();

  let resp = tunnel_request(
    &ca_pem,
    h.port,
    port,
    "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer canary-value\r\nContent-Length: 5\r\n\r\nhello",
  )
  .expect("tunnel");
  assert!(resp.starts_with("HTTP/1.1 200"), "client must see 200: {resp}");
  assert!(resp.ends_with("ok"));

  let hit = hits.lock().unwrap().pop().expect("stub must be hit");
  assert!(
    hit.headers.to_lowercase().contains("authorization: bearer real-secret"),
    "upstream must see the real cred: {}",
    hit.headers
  );
  assert!(
    !hit.headers.to_lowercase().contains("canary"),
    "canary must not leak upstream: {}",
    hit.headers
  );
  assert_eq!(hit.body, "hello");
}

#[test]
fn k6_unbound_host_gets_no_injection() {
  let (port, hits) = stub_tls_server();
  let cfg = ProxyConfig {
    session: "k6".into(),
    state_dir: fresh_state("k6"),
    allow_hosts: vec!["127.0.0.1".into()],
    restrict: true,
    keyring: Arc::new(Keyring::empty()),
    client_tls: STUB_CLIENT_TLS.clone(),
    deny_ports: vec![],
  };
  let h = start(cfg).unwrap();
  let ca_pem = std::fs::read_to_string(&h.ca_path).unwrap();

  // P21.1 K3b: no binding -> the agent's own auth passes through intact
  // (an OAuth-first agent would otherwise 401 on every call).
  let resp = tunnel_request(
    &ca_pem,
    h.port,
    port,
    "GET /open HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer user-oauth-token\r\n\r\n",
  )
  .expect("tunnel");
  assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
  let hit = hits.lock().unwrap().pop().expect("stub hit");
  assert!(
    hit.headers.to_lowercase().contains("authorization: bearer user-oauth-token"),
    "unbound host must pass the agent's auth through: {}",
    hit.headers
  );
}

#[test]
fn k3c_non_allowlisted_host_is_denied() {
  let cfg = ProxyConfig {
    session: "k3".into(),
    state_dir: fresh_state("k3"),
    allow_hosts: vec!["other.host".into()],
    restrict: true,
    keyring: Arc::new(Keyring::empty()),
    client_tls: native_tls_config(),
    deny_ports: vec![],
  };
  let h = start(cfg).unwrap();

  let mut sock = TcpStream::connect(("127.0.0.1", h.port)).unwrap();
  let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(5)));
  sock.write_all(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n").unwrap();
  let out = read_head_from(&mut sock).unwrap_or_default();
  let head = String::from_utf8_lossy(&out).to_string();
  assert!(head.contains("403"), "expected 403, got: {head}");
}

#[test]
fn k5_workspace_poisoned_keyring_never_reaches_load_path() {
  let w = fresh_state("k5");
  let project = w.join("project");
  std::fs::create_dir_all(&project).unwrap();
  std::fs::write(
    project.join("keyring.toml"),
    "[[credential]]\nname=\"evil\"\ntoken=\"POISON\"\nhosts=[\"127.0.0.1\"]\n",
  )
  .unwrap();
  let cfg = ProxyConfig {
    session: "k5".into(),
    state_dir: w.clone(),
    allow_hosts: vec!["127.0.0.1".into()],
    restrict: true,
    keyring: Arc::new(Keyring::load(&w.join("nonexistent/keyring.toml"))),
    client_tls: native_tls_config(),
    deny_ports: vec![],
  };
  assert!(cfg.keyring.is_empty());
  let h = start(cfg).unwrap();
  let ca_pem = std::fs::read_to_string(&h.ca_path).unwrap();
  assert!(!ca_pem.contains("POISON"));
  assert!(!ca_pem.contains("evil"));
}
