//! B8.1 — the syscall broker.
//!
//! The kernel's seccomp user-notification mechanism lets a supervisor
//! process outside a filter decide `connect(2)` / `sendto(2)` /
//! `sendmsg(2)` calls made inside it. Two structural holes close here:
//!
//! - **Egress (C10a):** Landlock ABI4 net rules are TCP-only and
//!   port-scoped. The broker reads the actual `sockaddr` and decides
//!   per destination — UDP and destination-scoped 443 included.
//! - **T4 escape:** `systemd-run` reaches the user manager over a unix
//!   socket no filesystem rule covers. The broker reads
//!   `sockaddr_un` paths and denies the manager sockets.
//!
//! Safety shape (validated in B8.0, revised in B8.2):
//! - **deny** — `-errno`, the kernel never executes the syscall. Robust:
//!   a racing thread cannot turn a deny into an execution.
//! - **allow** — `CONTINUE`. The kernel re-reads the syscall arguments
//!   from tracee memory, so a racing thread that rewrites the sockaddr
//!   after our check can redirect an allowed connect to a denied
//!   destination. This is the kernel's documented limitation and it is
//!   honest to state it: **the broker is a best-effort detection and
//!   denial layer against a non-racing agent, not a hard boundary
//!   against a malicious actor with a racing-thread exploit.** The hard
//!   boundary remains Landlock + classic seccomp; the broker closes the
//!   holes those cannot see (unix `sockaddr_un` paths, UDP, DNS) for
//!   the realistic LLM-agent threat model.
//!
//! Why not the supervisor-performs-connect + ADDFD pattern (the B8.0
//! plan)? Empirically falsified in B8.2: `ADDFD_FLAG_SEND` returns the
//! injected fd *number* as connect's return value and leaves the
//! tracee's original socket fd unconnected. Every program that ignores
//! connect's return and keeps writing to its own fd then gets
//! `ENOTCONN` — see examples/broker_fd_identity.rs. ADDFD suits
//! open-style syscalls that return a new fd; `connect` is not one.
//!
//! Residual: an fd connected *before* the filter was installed cannot
//! be revoked (documented C10a). The broker never sees it.

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::os::fd::RawFd;
use std::sync::mpsc::{Receiver, Sender};

pub const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 8;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
pub const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xC050_2100;
pub const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xC018_2101;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SeccompData {
  pub nr: i32,
  pub arch: u32,
  pub instruction_pointer: u64,
  pub args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SeccompNotif {
  pub id: u64,
  pub pid: u32,
  pub flags: u32,
  pub data: SeccompData,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SeccompNotifResp {
  pub id: u64,
  pub val: i64,
  pub error: i32,
  pub flags: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
  Allow,
  Deny,
}

/// Per-session egress policy. Destination-based, not port-based.
#[derive(Debug, Clone, Default)]
pub struct EgressPolicy {
  /// Extra hosts/IPs allowed beyond loopback (bless grants, provider).
  /// Hostnames are resolved ONCE at construction (before the filter is
  /// installed) — the supervisor must never perform DNS itself, because
  /// its own connect/sendto would notify itself and deadlock.
  pub extra_ips: Vec<IpAddr>,
  /// Resolver IPs parsed from /etc/resolv.conf — DNS must survive.
  pub resolver_ips: Vec<IpAddr>,
  /// Specific (ip, port) pairs denied even though they are loopback.
  /// Used for the systemd-resolved stub (127.0.0.53:53), which is a
  /// relay to the real upstream: allowing it is an unmonitored egress
  /// path and a DNS-tunnel channel. Empty by default (audit posture).
  pub denied_loopback: Vec<(IpAddr, u16)>,
  /// Deny the systemd user-manager sockets (T4). Default true.
  pub deny_systemd_sockets: bool,
  /// Deny the session bus (`$XDG_RUNTIME_DIR/bus`). Default true.
  ///
  /// The private manager socket is NOT the only route to systemd's
  /// manager: `org.freedesktop.systemd1` is also exported on the session
  /// bus, and `StartTransientUnit` over the bus launches an arbitrary
  /// command as a transient unit — outside the session cgroup and the
  /// envelope. Verified live 2026-09-15: a busctl StartTransientUnit
  /// call from inside an enforced session wrote a marker file on the
  /// host. `systemd-run` falls back to the bus when the private socket
  /// is denied, so denying the private socket alone closes nothing.
  /// The bus must be denied too.
  pub deny_user_bus: bool,
  /// When false (default), non-loopback IPs are allowed — the broker
  /// only closes the unix/systemd-socket hole and leaves egress alone.
  /// When true, only loopback + extra_ips + resolver_ips are allowed, and
  /// a destination argument the broker cannot read from tracee memory is
  /// DENIED (fail-closed: no proof of destination, no packet).
  pub restrict_ip: bool,
}

impl EgressPolicy {
  pub fn new() -> Self {
    Self {
      deny_systemd_sockets: true,
      deny_user_bus: true,
      resolver_ips: resolver_ips(),
      ..Default::default()
    }
  }

  /// Resolve hostnames into extra_ips now, before any filter exists.
  pub fn with_hosts(mut self, hosts: &[String]) -> Self {
    for h in hosts {
      if let Ok(addrs) = (h.as_str(), 0u16).to_socket_addrs() {
        for a in addrs {
          if !self.extra_ips.contains(&a.ip()) {
            self.extra_ips.push(a.ip());
          }
        }
      }
    }
    self
  }

  /// Tier floor: loopback + declared hosts only. The resolver is NOT
  /// allowed: a low-trust agent that can resolve names can tunnel data
  /// out in DNS queries. The provider is already resolved before the
  /// filter is installed, so the agent does not need runtime DNS to
  /// reach it.
  ///
  /// This does NOT by itself close DNS exfiltration on a
  /// systemd-resolved host, where /etc/resolv.conf points at the LOCAL
  /// stub 127.0.0.53. The stub is loopback, so the blanket loopback
  /// allowance passes it, and the stub forwards to the real upstream.
  /// `deny_resolver_stub` closes that; it is applied automatically.
  pub fn with_llm_only(mut self, hosts: &[String]) -> Self {
    self.restrict_ip = true;
    self.resolver_ips.clear();
    self.deny_resolver_stub();
    self.with_hosts(hosts)
  }

  /// Under a destination policy, DENY the systemd-resolved stub even
  /// though it is loopback. The stub is a RELAY: anything an agent sends
  /// to it is forwarded to the real upstream, so an allowed
  /// 127.0.0.53:53 is an unmonitored egress path and a DNS-tunnel
  /// channel. The canary honeypot (an arbitrary loopback port) is
  /// unaffected — this denies a specific (ip, port) pair, not loopback.
  ///
  /// Verified live 2026-09-17: before this, the D6 census read DNS
  /// OPEN under the tier floor on a host whose resolver is
  /// 127.0.0.53 (systemd-resolved stub). The 53 is the stub's port; the
  /// upstream is reached by the stub, not by the agent.
  pub fn deny_resolver_stub(&mut self) {
    for octet in [53u8, 54] {
      let entry = (IpAddr::V4(Ipv4Addr::new(127, 0, 0, octet)), 53u16);
      if !self.denied_loopback.contains(&entry) {
        self.denied_loopback.push(entry);
      }
    }
  }

  /// Is this specific (ip, port) pair explicitly denied even though it
  /// is loopback? Used for the resolver stub.
  fn loopback_denied(&self, ip: &IpAddr, port: u16) -> bool {
    self.denied_loopback.contains(&(*ip, port))
  }

  fn ip_allowed(&self, ip: &IpAddr) -> bool {
    if ip.is_loopback() {
      return true;
    }
    if !self.restrict_ip {
      return true;
    }
    if self.extra_ips.contains(ip) || self.resolver_ips.contains(ip) {
      return true;
    }
    false
  }
}

/// Parse nameserver lines from /etc/resolv.conf. The file is readable
/// in the envelope (read roots are `/`), but this runs in the
/// supervisor which is outside the notif filter anyway.
pub fn resolver_ips() -> Vec<IpAddr> {
  let mut out = Vec::new();
  if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
    for line in text.lines() {
      let line = line.trim();
      if let Some(rest) = line.strip_prefix("nameserver") {
        if let Ok(ip) = rest.trim().parse::<IpAddr>() {
          out.push(ip);
        }
      }
    }
  }
  out
}

/// The unix paths that let a process escape the session scope by asking
/// the user manager to act. C25/T4: `systemd-run` needs no cgroup write
/// and no unit-file write — it talks to the manager over these sockets.
///
/// Scope note (B8.2): only the manager's private control socket and the
/// cgroup socket are denied by default. The general session bus
/// (`/run/user/N/bus`) is deliberately NOT denied — it carries ordinary
/// desktop/harness traffic and denying it is a high false-block risk;
/// `systemd-run --user` reaches the manager directly, not via the bus.
pub fn is_manager_socket(path: &[u8]) -> bool {
  let s = String::from_utf8_lossy(path);
  s.starts_with("/run/systemd/private")
    || s.contains("/systemd/private")
    || s.contains("/systemd/cgroup")
}

/// The session bus path class, kept separate for opt-in denial.
pub fn is_user_bus(path: &[u8]) -> bool {
  let s = String::from_utf8_lossy(path);
  s.ends_with("/bus") && s.contains("/run/user/")
}

pub fn evaluate_v4(ip: Ipv4Addr, policy: &EgressPolicy) -> Verdict {
  if policy.ip_allowed(&IpAddr::V4(ip)) {
    Verdict::Allow
  } else {
    Verdict::Deny
  }
}

pub fn evaluate_v6(ip: Ipv6Addr, policy: &EgressPolicy) -> Verdict {
  if policy.ip_allowed(&IpAddr::V6(ip)) {
    Verdict::Allow
  } else {
    Verdict::Deny
  }
}

pub enum Sockaddr {
  V4(Ipv4Addr, u16),
  V6(Ipv6Addr, u16),
  Unix(Vec<u8>),
  Other(i32),
}

impl Sockaddr {
  pub fn detail(&self) -> String {
    match self {
      Sockaddr::V4(ip, port) => format!("{ip}:{port}"),
      Sockaddr::V6(ip, port) => format!("[{ip}]:{port}"),
      Sockaddr::Unix(p) => format!("unix:{}", String::from_utf8_lossy(p)),
      Sockaddr::Other(f) => format!("family={f}"),
    }
  }
}

pub fn parse_sockaddr(buf: &[u8]) -> Option<Sockaddr> {
  if buf.len() < 2 {
    return None;
  }
  let family = u16::from_ne_bytes([buf[0], buf[1]]) as i32;
  match family {
    libc::AF_INET => {
      if buf.len() < 8 {
        return None;
      }
      let port = u16::from_be_bytes([buf[2], buf[3]]);
      Some(Sockaddr::V4(Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]), port))
    }
    libc::AF_INET6 => {
      if buf.len() < 24 {
        return None;
      }
      let port = u16::from_be_bytes([buf[2], buf[3]]);
      let mut octets = [0u8; 16];
      octets.copy_from_slice(&buf[8..24]);
      Some(Sockaddr::V6(Ipv6Addr::from(octets), port))
    }
    libc::AF_UNIX => {
      let path = &buf[2..];
      let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
      Some(Sockaddr::Unix(path[..end].to_vec()))
    }
    other => Some(Sockaddr::Other(other)),
  }
}

/// Decide a destination. `deny_systemd` is the T4 structural close;
/// when false, manager sockets are allowed (audit posture).
pub fn decide(sa: &Sockaddr, policy: &EgressPolicy) -> (Verdict, &'static str) {
  match sa {
    Sockaddr::V4(ip, port) => {
      if policy.loopback_denied(&IpAddr::V4(*ip), *port) {
        return (Verdict::Deny, "resolver-stub");
      }
      (evaluate_v4(*ip, policy), "ipv4")
    }
    Sockaddr::V6(ip, port) => {
      if policy.loopback_denied(&IpAddr::V6(*ip), *port) {
        return (Verdict::Deny, "resolver-stub");
      }
      (evaluate_v6(*ip, policy), "ipv6")
    }
    Sockaddr::Unix(path) => {
      if policy.deny_systemd_sockets && is_manager_socket(path) {
        (Verdict::Deny, "systemd-socket")
      } else if policy.deny_user_bus && is_user_bus(path) {
        (Verdict::Deny, "session-bus")
      } else {
        (Verdict::Allow, "unix")
      }
    }
    Sockaddr::Other(_) => (Verdict::Allow, "other-family"),
  }
}

#[derive(Debug, Clone)]
pub struct BrokerEvent {
  pub pid: u32,
  pub verdict: Verdict,
  pub reason: &'static str,
  pub detail: String,
}

impl BrokerEvent {
  /// A deny is an attempted escape, not a note. The supervisor (which
  /// runs outside the agent's envelope) records it to the session spine
  /// so the ProofCertificate's bounds proof can count it.
  pub fn as_spine_row(&self) -> Option<(String, String, &'static str)> {
    if self.verdict == Verdict::Deny {
      Some((
        "broker_deny".to_string(),
        format!("{} {} pid={}", self.reason, self.detail, self.pid),
        "deny",
      ))
    } else {
      None
    }
  }
}

pub type BrokerLog = (Sender<BrokerEvent>, Receiver<BrokerEvent>);
pub fn broker_log() -> BrokerLog {
  std::sync::mpsc::channel()
}

fn read_tracee(pid: u32, ptr: u64, len: usize) -> Option<Vec<u8>> {
  if ptr == 0 || len == 0 {
    return None;
  }
  let len = len.min(256);
  let mut buf = vec![0u8; len];
  let local = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: len };
  let remote = libc::iovec { iov_base: ptr as *mut _, iov_len: len };
  let n = unsafe { libc::process_vm_readv(pid as i32, &local, 1, &remote, 1, 0) };
  if n <= 0 {
    None
  } else {
    buf.truncate(n as usize);
    Some(buf)
  }
}

/// Extract the destination sockaddr from a notification, if the syscall
/// carries one. Returns None when the destination is implicit (connected
/// socket) or unreadable; `read_dest` distinguishes those two cases.
#[allow(dead_code)]
fn notification_dest(req: &SeccompNotif) -> Option<Sockaddr> {
  match req.data.nr as i64 {
    libc::SYS_connect => {
      let buf = read_tracee(req.pid, req.data.args[1], req.data.args[2] as usize)?;
      parse_sockaddr(&buf)
    }
    libc::SYS_sendto => {
      // sendto(fd, buf, len, flags, dest_addr, addrlen)
      if req.data.args[4] == 0 {
        return None;
      }
      let buf = read_tracee(req.pid, req.data.args[4], req.data.args[5] as usize)?;
      parse_sockaddr(&buf)
    }
    libc::SYS_sendmsg => {
      // sendmsg(fd, msg, flags): msghdr.msg_name at offset 0,
      // msg_namelen at offset 8 on x86_64.
      let hdr = read_tracee(req.pid, req.data.args[1], 16)?;
      if hdr.len() < 16 {
        return None;
      }
      let name_ptr = u64::from_ne_bytes(hdr[0..8].try_into().ok()?);
      let name_len = u32::from_ne_bytes(hdr[8..12].try_into().ok()?) as usize;
      if name_ptr == 0 || name_len == 0 {
        return None;
      }
      let buf = read_tracee(req.pid, name_ptr, name_len)?;
      parse_sockaddr(&buf)
    }
    _ => None,
  }
}

/// The outcome of reading a syscall's destination argument out of
/// tracee memory. `Unreadable` is NOT the same as `None` (no
/// destination argument at all): a failed read means we cannot prove
/// where the packet is going, and under a destination policy that must
/// be denied rather than allowed.
pub enum DestRead {
  Parsed(Sockaddr),
  /// The syscall carries no destination (sendto on an already-connected
  /// socket, or a connect form we do not parse) — vetted at connect time.
  None,
  /// The destination was not readable from the tracee.
  Unreadable,
}

pub fn read_dest(req: &SeccompNotif) -> DestRead {
  let nr = req.data.nr as i64;
  let read = |ptr: u64, len: u64| read_tracee(req.pid, ptr, len as usize);
  match nr {
    libc::SYS_connect => match read(req.data.args[1], req.data.args[2]) {
      Some(buf) => match parse_sockaddr(&buf) {
        Some(sa) => DestRead::Parsed(sa),
        None => DestRead::Unreadable,
      },
      None => DestRead::Unreadable,
    },
    libc::SYS_sendto => {
      // sendto(fd, buf, len, flags, dest_addr, addrlen). glibc implements
      // send() as sendto with a NULL destination on a connected socket,
      // so a NULL here is the normal implicit case, not a failure.
      if req.data.args[4] == 0 {
        return DestRead::None;
      }
      match read(req.data.args[4], req.data.args[5]) {
        Some(buf) => match parse_sockaddr(&buf) {
          Some(sa) => DestRead::Parsed(sa),
          None => DestRead::Unreadable,
        },
        None => DestRead::Unreadable,
      }
    }
    libc::SYS_sendmsg => {
      // sendmsg(fd, msg, flags): msghdr.msg_name at offset 0,
      // msg_namelen at offset 8 on x86_64.
      let hdr = match read(req.data.args[1], 16) {
        Some(h) if h.len() >= 16 => h,
        _ => return DestRead::Unreadable,
      };
      let name_ptr = u64::from_ne_bytes(hdr[0..8].try_into().unwrap());
      let name_len = u32::from_ne_bytes(hdr[8..12].try_into().unwrap()) as usize;
      if name_ptr == 0 || name_len == 0 {
        return DestRead::None;
      }
      match read(name_ptr, name_len as u64) {
        Some(buf) => match parse_sockaddr(&buf) {
          Some(sa) => DestRead::Parsed(sa),
          None => DestRead::Unreadable,
        },
        None => DestRead::Unreadable,
      }
    }
    _ => DestRead::None,
  }
}

pub fn decide_dest(
  dest: &DestRead,
  policy: &EgressPolicy,
) -> (Verdict, &'static str, String) {
  match dest {
    DestRead::Parsed(sa) => {
      let (v, r) = decide(sa, policy);
      (v, r, sa.detail())
    }
    // An implicit destination means the socket was vetted when it was
    // connected, and `connect` is intercepted. This MUST stay allowed:
    // glibc's send() is a sendto with a NULL destination and most TLS
    // stacks use sendmsg on connected sockets, so denying here would
    // block every program that sends anything. The inherited-fd case
    // (connected before the filter) is a documented residual (C10a),
    // not something a deny here can fix.
    DestRead::None => (Verdict::Allow, "implicit-dest", String::new()),
    DestRead::Unreadable => {
      // A destination argument was present but could not be read. We
      // cannot prove where this goes, so under a destination policy it
      // does not go.
      if policy.restrict_ip {
        (Verdict::Deny, "dest-unreadable", String::new())
      } else {
        (Verdict::Allow, "dest-unreadable", String::new())
      }
    }
  }
}

fn send_response(listener: RawFd, id: u64, error: i32, flags: u32) -> io::Result<()> {
  let mut resp = SeccompNotifResp { id, val: 0, error, flags };
  let rc = unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &mut resp) };
  if rc < 0 {
    let e = io::Error::last_os_error();
    if e.raw_os_error() != Some(libc::ENOENT) {
      return Err(e);
    }
  }
  Ok(())
}

fn respond(listener: RawFd, req: &SeccompNotif, verdict: Verdict) -> io::Result<()> {
  if verdict == Verdict::Deny {
    return send_response(listener, req.id, -libc::EPERM, 0);
  }
  // Allow: CONTINUE re-reads arguments from tracee memory. The kernel
  // documents this as TOCTOU-soft; see the crate-level note.
  send_response(listener, req.id, 0, SECCOMP_USER_NOTIF_FLAG_CONTINUE)
}

/// Install the notification filter on the current process and return
/// the listener fd. The filter intercepts only connect/sendto/sendmsg;
/// everything else falls through to ALLOW.
///
/// Callers use `spawn_broker`, which installs this in the SUPERVISOR
/// and forks the agent — the filter is inherited across fork/exec, so
/// no fd handoff is needed. (A handoff via SCM_RIGHTS deadlocks: the
/// handoff's own sendmsg is intercepted before the supervisor has the
/// listener. Found live, 2026-09-05.)
pub fn install_listener() -> io::Result<RawFd> {
  let prog = vec![
    bpf(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
    // Jump table: connect -> 4, sendto -> 4, sendmsg -> 4, else -> 5.
    bpf(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 2, 0, libc::SYS_connect as u32),
    bpf(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 1, 0, libc::SYS_sendto as u32),
    bpf(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 1, libc::SYS_sendmsg as u32),
    bpf(libc::BPF_RET | libc::BPF_K, 0, 0, SECCOMP_RET_USER_NOTIF),
    bpf(libc::BPF_RET | libc::BPF_K, 0, 0, SECCOMP_RET_ALLOW),
  ];
  unsafe {
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
      return Err(io::Error::last_os_error());
    }
    let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_ptr() as *mut _ };
    let fd = libc::syscall(
      libc::SYS_seccomp,
      SECCOMP_SET_MODE_FILTER,
      SECCOMP_FILTER_FLAG_NEW_LISTENER,
      &fprog as *const _,
    );
    if fd < 0 {
      Err(io::Error::last_os_error())
    } else {
      Ok(fd as RawFd)
    }
  }
}

fn bpf(code: u32, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
  libc::sock_filter { code: code as u16, jt, jf, k }
}

/// The supervisor/agent fork result. The supervisor installs the
/// notif filter FIRST, then forks: the agent inherits the filter at
/// exec; the supervisor keeps the listener.
pub enum Spawn {
  /// Child: apply the envelope, then exec the agent command.
  Agent,
  /// Parent: run `broker.run()`, reap the agent, exit its code.
  Supervisor(Broker),
}

pub struct Broker {
  pub listener: RawFd,
  pub agent_pid: libc::pid_t,
  agent_status: Option<i32>,
}

/// Run `exe args` under the broker and capture its stdout.
///
/// The filter is installed in a short-lived grandchild supervisor, never
/// in the calling process: installing a seccomp notif filter is
/// irreversible, and every later connect/sendto/sendmsg in the caller
/// would then notify a listener that dies with the supervisor. The first
/// version installed it in the long-lived daemon and hung the daemon
/// permanently (found live, 2026-09-17).
///
/// Shape:
///   caller  --fork--> supervisor (installs filter, forks) --fork-->
///           agent (execs `exe args`; its connects notify supervisor)
///   supervisor --exit--> caller reads the agent's stdout
pub fn supervise_capture(
  exe: &std::path::Path,
  args: &[String],
  env: &[(&str, String)],
  policy: &EgressPolicy,
) -> String {
  // stdout of the agent must reach a pipe the caller owns.
  let (out_r, out_w) = {
    let mut fds: [libc::c_int; 2] = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
      return format!("broker: pipe failed ({})\n", std::io::Error::last_os_error());
    }
    (fds[0], fds[1])
  };
  // Hand the write end to the supervisor through the fork: the caller
  // keeps the read end only.
  let pid = unsafe { libc::fork() };
  if pid < 0 {
    return format!("broker: fork failed ({})\n", std::io::Error::last_os_error());
  }
  if pid > 0 {
    // Caller: close the write end, read the agent's output to EOF, then
    // reap the supervisor. Reading to EOF before reaping is required:
    // the agent holds the write end until it exits.
    unsafe { libc::close(out_w) };
    let mut out = String::new();
    let mut f = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(out_r) };
    {
      use std::io::Read as _;
      let _ = f.read_to_string(&mut out);
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    return out;
  }
  // Supervisor (short-lived): its stdout is irrelevant; only the agent's
  // captured output matters, so point our own stdout at the pipe too in
  // case anything in the supervision path prints.
  unsafe {
    libc::close(out_r);
    libc::dup2(out_w, 1);
    libc::close(out_w);
    for (k, v) in env {
      std::env::set_var(k, v);
    }
  }
  let out = supervise_capture_inner(exe, args, policy);
  let bytes = out.as_bytes();
  unsafe {
    libc::write(1, bytes.as_ptr() as *const libc::c_void, bytes.len());
    libc::_exit(0)
  }
}

fn supervise_capture_inner(
  exe: &std::path::Path,
  args: &[String],
  policy: &EgressPolicy,
) -> String {
  use std::io::Read as _;
  let listener = match install_listener() {
    Ok(l) => l,
    Err(e) => return format!("broker: filter install failed ({e})\n"),
  };
  // The agent's stdout goes through a pipe the supervisor drains.
  let (r, w) = {
    let mut fds: [libc::c_int; 2] = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
      return format!("broker: pipe failed ({})\n", std::io::Error::last_os_error());
    }
    (fds[0], fds[1])
  };
  let pid = unsafe { libc::fork() };
  if pid < 0 {
    return format!("broker: fork failed ({})\n", std::io::Error::last_os_error());
  }
  if pid == 0 {
    // Agent: the filter is inherited. Drop the listener, the read end,
    // and every fd above 2 (the daemon's own socket must not leak into
    // the agent — a leaked socket makes the agent's own writes re-enter
    // this process's dispatch and deadlock). Then exec.
    unsafe {
      libc::close(listener);
      libc::close(r);
      libc::dup2(w, 1);
      libc::close(w);
      let max = libc::sysconf(libc::_SC_OPEN_MAX);
      let max = if max > 0 { max as i32 } else { 4096 };
      for fd in 3..max.min(1024) {
        libc::close(fd);
      }
    }
    let c = std::process::Command::new(exe);
    let err = execve(c, args);
    eprintln!("broker: exec failed: {err}");
    unsafe { libc::_exit(127) }
  }
  unsafe { libc::close(w) };
  // Drain the agent's stdout on a thread WHILE the decision loop runs:
  // the agent blocks once the pipe buffer fills, so reading only after
  // the loop deadlocks whenever its output exceeds the pipe capacity.
  let reader = std::thread::spawn(move || {
    let mut f = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(r) };
    let mut out = String::new();
    let _ = f.read_to_string(&mut out);
    out
  });
  let mut policy = policy.clone();
  let mut sup = Broker { listener, agent_pid: pid, agent_status: None };
  let (btx, _brx) = broker_log();
  let _ = sup.run(&mut policy, &btx);
  reader.join().unwrap_or_default()
}

fn execve(mut c: std::process::Command, args: &[String]) -> std::io::Error {
  use std::os::unix::process::CommandExt as _;
  c.args(args);
  c.exec()
}

impl Broker {
  /// Run the decision loop until the agent tree exits.
  ///
  /// NOTIF_RECV never returns ENOENT while the supervisor (itself a
  /// tracee) holds the listener open, even after the agent is gone.
  /// Exit detection is therefore poll(200ms) + waitpid(WNOHANG).
  pub fn run(&mut self, policy: &mut EgressPolicy, log: &Sender<BrokerEvent>) -> io::Result<u64> {
    let mut count = 0u64;
    loop {
      let mut pfd = libc::pollfd { fd: self.listener, events: libc::POLLIN, revents: 0 };
      let pr = unsafe { libc::poll(&mut pfd, 1, 200) };
      if pr < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EINTR) {
          continue;
        }
        return Err(e);
      }
      if pr == 0 || pfd.revents & libc::POLLIN == 0 {
        if let Some(status) = try_reap(self.agent_pid) {
          self.agent_status = Some(status);
          return Ok(count);
        }
        continue;
      }
      let mut req: SeccompNotif = unsafe { mem::zeroed() };
      let rc = unsafe { libc::ioctl(self.listener, SECCOMP_IOCTL_NOTIF_RECV, &mut req) };
      if rc < 0 {
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
          Some(libc::ENOENT) => continue,
          Some(libc::EINTR) => continue,
          _ => return Err(e),
        }
      }
      count += 1;
      let dest = read_dest(&req);
      let (verdict, reason, detail) = decide_dest(&dest, policy);
      let _ = log.send(BrokerEvent { pid: req.pid, verdict, reason, detail });
      respond(self.listener, &req, verdict)?;
    }
  }

  /// Reap the agent; returns its exit code.
  pub fn finish(self) -> i32 {
    match self.agent_status {
      Some(c) => c,
      None => reap(self.agent_pid),
    }
  }
}

/// Non-blocking wait: Some(exit code) if the child already exited.
fn try_reap(child: libc::pid_t) -> Option<i32> {
  let mut status = 0;
  let rc = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
  if rc == child {
    Some(if libc::WIFEXITED(status) {
      libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
      128 + libc::WTERMSIG(status)
    } else {
      1
    })
  } else {
    None
  }
}

/// Install the filter in the supervisor, then fork the agent. The
/// caller must branch immediately: `Spawn::Agent` -> apply envelope +
/// exec; `Spawn::Supervisor` -> run.
///
/// No helper process is needed: the supervisor performs no network I/O
/// (hostnames are resolved before the filter is installed), so it never
/// notifies itself.
pub fn spawn_broker() -> io::Result<Spawn> {
  let listener = install_listener()?;
  let agent_pid = unsafe { libc::fork() };
  if agent_pid < 0 {
    return Err(io::Error::last_os_error());
  }
  if agent_pid == 0 {
    // Agent: inherits the filter. Drop the listener.
    unsafe { libc::close(listener) };
    return Ok(Spawn::Agent);
  }
  Ok(Spawn::Supervisor(Broker { listener, agent_pid, agent_status: None }))
}

/// Wait for the agent child and return its exit code (128+sig on signal).
pub fn reap(child: libc::pid_t) -> i32 {
  let mut status = 0;
  unsafe { libc::waitpid(child, &mut status, 0) };
  if libc::WIFEXITED(status) {
    libc::WEXITSTATUS(status)
  } else if libc::WIFSIGNALED(status) {
    128 + libc::WTERMSIG(status)
  } else {
    1
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn loopback_allowed_public_denied() {
    let p = EgressPolicy { restrict_ip: true, ..EgressPolicy::new() };
    assert_eq!(evaluate_v4(Ipv4Addr::new(127, 0, 0, 1), &p), Verdict::Allow);
    assert_eq!(evaluate_v4(Ipv4Addr::new(8, 8, 8, 8), &p), Verdict::Deny);
    assert_eq!(evaluate_v4(Ipv4Addr::new(192, 168, 1, 227), &p), Verdict::Deny);
  }

  #[test]
  fn open_egress_allows_public_by_default() {
    // Default posture: the broker only closes the systemd-socket hole;
    // IP egress is unrestricted unless restrict_ip is set.
    let p = EgressPolicy::new();
    assert_eq!(evaluate_v4(Ipv4Addr::new(8, 8, 8, 8), &p), Verdict::Allow);
  }

  #[test]
  fn resolver_allowed() {
    let mut p = EgressPolicy { restrict_ip: true, ..EgressPolicy::new() };
    p.resolver_ips.push(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
    assert_eq!(evaluate_v4(Ipv4Addr::new(9, 9, 9, 9), &p), Verdict::Allow);
  }

  #[test]
  fn extra_ip_allowed() {
    let mut p = EgressPolicy { restrict_ip: true, ..EgressPolicy::new() };
    p.extra_ips.push(IpAddr::V4(Ipv4Addr::new(140, 82, 112, 5)));
    assert_eq!(evaluate_v4(Ipv4Addr::new(140, 82, 112, 5), &p), Verdict::Allow);
  }

  #[test]
  fn unparseable_destination_fails_closed_under_restriction() {
    let p = EgressPolicy { restrict_ip: true, ..EgressPolicy::new() };
    let (v, r, _) = decide_dest(&DestRead::Unreadable, &p);
    assert_eq!(v, Verdict::Deny);
    assert_eq!(r, "dest-unreadable");
  }

  #[test]
  fn unparseable_destination_is_allowed_under_audit_posture() {
    let p = EgressPolicy::new();
    assert!(!p.restrict_ip);
    let (v, _, _) = decide_dest(&DestRead::Unreadable, &p);
    assert_eq!(v, Verdict::Allow);
  }

  #[test]
  fn implicit_destination_is_allowed_under_restriction() {
    // The send() path. Denying here would break every TLS stack, because
    // most send via sendto/sendmsg with a NULL destination on a socket
    // whose connect() was already vetted by the broker.
    let p = EgressPolicy { restrict_ip: true, ..EgressPolicy::new() };
    let (v, r, _) = decide_dest(&DestRead::None, &p);
    assert_eq!(v, Verdict::Allow);
    assert_eq!(r, "implicit-dest");
  }

  #[test]
  fn llm_only_allows_loopback_and_denies_public() {
    // A host that cannot resolve leaves the policy with no extra IPs,
    // which is the honest "provider unreachable" case: loopback (the
    // honeypot) survives, every public destination is denied.
    let p = EgressPolicy::new().with_llm_only(&["provider.invalid.".to_string()]);
    assert!(p.restrict_ip);
    assert_eq!(evaluate_v4(Ipv4Addr::new(127, 0, 0, 1), &p), Verdict::Allow);
    assert_eq!(evaluate_v4(Ipv4Addr::new(1, 2, 3, 4), &p), Verdict::Deny);
  }

  #[test]
  fn llm_only_denies_the_resolver() {
    // DNS is an exfil channel. The provider is resolved BEFORE the
    // filter, so the agent never needs the resolver to reach it.
    let mut p = EgressPolicy::new();
    p.resolver_ips.push(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
    assert_eq!(evaluate_v4(Ipv4Addr::new(9, 9, 9, 9), &p), Verdict::Allow);
    let p = p.with_llm_only(&[]);
    assert_eq!(evaluate_v4(Ipv4Addr::new(9, 9, 9, 9), &p), Verdict::Deny);
  }

  #[test]
  fn llm_only_denies_the_resolved_stub_on_loopback() {
    // The real finding: /etc/resolv.conf points at 127.0.0.53 on a
    // systemd-resolved host. The stub is loopback, so the blanket
    // loopback allowance passed it, and the stub relays to the upstream
    // — an unmonitored DNS tunnel. Found by the D6 census 2026-09-17.
    let p = EgressPolicy::new().with_llm_only(&[]);
    let sa = Sockaddr::V4(Ipv4Addr::new(127, 0, 0, 53), 53);
    assert_eq!(decide(&sa, &p).0, Verdict::Deny);
    // A different loopback port (the canary honeypot) is unaffected.
    let sa = Sockaddr::V4(Ipv4Addr::new(127, 0, 0, 53), 44407);
    assert_eq!(decide(&sa, &p).0, Verdict::Allow);
    // The honeypot's own loopback address and port still works.
    let sa = Sockaddr::V4(Ipv4Addr::new(127, 0, 0, 1), 44407);
    assert_eq!(decide(&sa, &p).0, Verdict::Allow);
  }

  #[test]
  fn the_stub_is_allowed_under_the_audit_posture() {
    // The denial is a destination-policy behavior, not a blanket one:
    // audit mode leaves DNS exactly as the system configures it.
    let p = EgressPolicy::new();
    let sa = Sockaddr::V4(Ipv4Addr::new(127, 0, 0, 53), 53);
    assert_eq!(decide(&sa, &p).0, Verdict::Allow);
  }

  #[test]
  fn systemd_socket_denied_by_default() {
    let p = EgressPolicy::new();
    let sa = Sockaddr::Unix(b"/run/user/1000/systemd/private".to_vec());
    assert_eq!(decide(&sa, &p).0, Verdict::Deny);
    // B8.2: the session bus is ALSO denied by default — systemd1 is
    // exported there and StartTransientUnit over the bus escapes.
    let sa = Sockaddr::Unix(b"/run/user/1000/bus".to_vec());
    assert_eq!(decide(&sa, &p).0, Verdict::Deny);
    let sa = Sockaddr::Unix(b"/run/user/1000/wayland-0".to_vec());
    assert_eq!(decide(&sa, &p).0, Verdict::Allow);
  }

  #[test]
  fn session_bus_allowed_when_disabled() {
    let p = EgressPolicy { deny_user_bus: false, ..EgressPolicy::new() };
    let sa = Sockaddr::Unix(b"/run/user/1000/bus".to_vec());
    assert_eq!(decide(&sa, &p).0, Verdict::Allow);
  }

  #[test]
  fn systemd_socket_allowed_when_disabled() {
    let p = EgressPolicy { deny_systemd_sockets: false, ..EgressPolicy::new() };
    let sa = Sockaddr::Unix(b"/run/user/1000/systemd/private".to_vec());
    assert_eq!(decide(&sa, &p).0, Verdict::Allow);
  }

  #[test]
  fn parse_v4_sockaddr() {
    let buf = [2u8, 0, 0x01, 0xbb, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0];
    match parse_sockaddr(&buf).unwrap() {
      Sockaddr::V4(ip, port) => {
        assert_eq!(ip, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(port, 443);
      }
      _ => panic!("expected v4"),
    }
  }

  #[test]
  fn parse_unix_sockaddr() {
    let mut buf = vec![1u8, 0];
    buf.extend_from_slice(b"/run/systemd/private\0");
    match parse_sockaddr(&buf).unwrap() {
      Sockaddr::Unix(p) => assert_eq!(p, b"/run/systemd/private"),
      _ => panic!("expected unix"),
    }
  }
}
