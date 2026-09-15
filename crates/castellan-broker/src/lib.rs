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
//! Safety shape (validated in B8.0):
//! - **connect allow** — the broker performs the connect itself and
//!   injects the connected fd with `ADDFD_FLAG_SEND`. No argument
//!   forwarding, no TOCTOU.
//! - **connect deny** — `-errno`, no fd.
//! - **sendto/sendmsg with an explicit destination** — the kernel has
//!   no fd-injection equivalent (the send happens on an existing fd),
//!   so the allow path uses `CONTINUE`. That is TOCTOU-soft by kernel
//!   design and documented as such: a racing thread can rewrite the
//!   destination between the check and the syscall. Deny is hard.
//! - **sendto/sendmsg with no destination** (connected socket) — the
//!   destination was already vetted at connect time; allow.
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
pub const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0x4018_2103;
pub const SECCOMP_ADDFD_FLAG_SEND: u32 = 2;

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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SeccompNotifAddfd {
  pub id: u64,
  pub flags: u32,
  pub srcfd: u32,
  pub newfd: u32,
  pub newfd_flags: u32,
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
  pub extra_ips: Vec<IpAddr>,
  /// Hostnames re-resolved by the supervisor when an unknown IP is
  /// denied (rate-limited). Keeps CDN-rotated providers reachable.
  pub allow_hosts: Vec<String>,
  /// Resolver IPs parsed from /etc/resolv.conf — DNS must survive.
  pub resolver_ips: Vec<IpAddr>,
  /// Deny the systemd user-manager sockets (T4). Default true.
  pub deny_systemd_sockets: bool,
}

impl EgressPolicy {
  pub fn new() -> Self {
    Self { deny_systemd_sockets: true, resolver_ips: resolver_ips(), ..Default::default() }
  }

  fn ip_allowed(&self, ip: &IpAddr) -> bool {
    if ip.is_loopback() {
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
pub fn is_manager_socket(path: &[u8]) -> bool {
  let s = String::from_utf8_lossy(path);
  s.starts_with("/run/systemd/private")
    || s.contains("/systemd/private")
    || s.ends_with("/bus")
    || s.contains("/systemd/cgroup")
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
    Sockaddr::V4(ip, _) => (evaluate_v4(*ip, policy), "ipv4"),
    Sockaddr::V6(ip, _) => (evaluate_v6(*ip, policy), "ipv6"),
    Sockaddr::Unix(path) => {
      if policy.deny_systemd_sockets && is_manager_socket(path) {
        (Verdict::Deny, "systemd-socket")
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

pub type BrokerLog = (Sender<BrokerEvent>, Receiver<BrokerEvent>);
pub fn broker_log() -> BrokerLog {
  std::sync::mpsc::channel()
}

fn refresh_hosts(policy: &mut EgressPolicy) {
  let hosts = policy.allow_hosts.clone();
  for h in hosts {
    if let Ok(addrs) = (h.as_str(), 0u16).to_socket_addrs() {
      for a in addrs {
        if !policy.extra_ips.contains(&a.ip()) {
          policy.extra_ips.push(a.ip());
        }
      }
    }
  }
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
/// socket) or unreadable.
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

fn decide_notification(
  req: &SeccompNotif,
  policy: &EgressPolicy,
) -> (Verdict, &'static str, String) {
  match notification_dest(req) {
    Some(sa) => {
      let (v, r) = decide(&sa, policy);
      (v, r, sa.detail())
    }
    None => {
      // Implicit destination: the socket was vetted at connect time.
      (Verdict::Allow, "implicit-dest", String::new())
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

fn respond(listener: RawFd, helper_sock: RawFd, req: &SeccompNotif, verdict: Verdict) -> io::Result<()> {
  if verdict == Verdict::Deny {
    return send_response(listener, req.id, -libc::EPERM, 0);
  }
  if req.data.nr as i64 != libc::SYS_connect {
    // sendto/sendmsg allow: CONTINUE is the only mechanism (no fd to
    // inject). TOCTOU-soft, documented at the crate level.
    return send_response(listener, req.id, 0, SECCOMP_USER_NOTIF_FLAG_CONTINUE);
  }
  // connect allow: an unfiltered helper performs the syscall and we
  // inject the connected fd — no argument forwarding, no TOCTOU, and
  // the supervisor itself never calls connect (it is filtered too).
  let Some(sa) = notification_dest(req) else {
    return send_response(listener, req.id, -libc::EPERM, 0);
  };
  let (family, buf) = sockaddr_bytes(&sa);
  let sfd = match helper_connect(helper_sock, family, &buf) {
    Ok(fd) => fd,
    Err(err) => return send_response(listener, req.id, -err, 0),
  };
  let mut add = SeccompNotifAddfd {
    id: req.id,
    flags: SECCOMP_ADDFD_FLAG_SEND,
    srcfd: sfd as u32,
    newfd: 0,
    newfd_flags: libc::O_CLOEXEC as u32,
  };
  let injected = unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &mut add) };
  unsafe { libc::close(sfd) };
  if injected < 0 {
    let err = io::Error::last_os_error().raw_os_error().unwrap_or(libc::EPERM);
    return send_response(listener, req.id, -err, 0);
  }
  Ok(())
}

fn sockaddr_bytes(sa: &Sockaddr) -> (i32, Vec<u8>) {
  match sa {
    Sockaddr::V4(ip, port) => {
      let mut b = vec![0u8; 16];
      b[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
      b[2..4].copy_from_slice(&port.to_be_bytes());
      b[4..8].copy_from_slice(&ip.octets());
      (libc::AF_INET, b)
    }
    Sockaddr::V6(ip, port) => {
      let mut b = vec![0u8; 28];
      b[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
      b[2..4].copy_from_slice(&port.to_be_bytes());
      b[8..24].copy_from_slice(&ip.octets());
      (libc::AF_INET6, b)
    }
    Sockaddr::Unix(path) => {
      let mut b = vec![0u8; 2 + path.len() + 1];
      b[0..2].copy_from_slice(&(libc::AF_UNIX as u16).to_ne_bytes());
      b[2..2 + path.len()].copy_from_slice(path);
      (libc::AF_UNIX, b)
    }
    Sockaddr::Other(f) => {
      let mut b = vec![0u8; 2];
      b[0..2].copy_from_slice(&(*f as u16).to_ne_bytes());
      (*f, b)
    }
  }
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
/// exec; the supervisor keeps the listener and the unfiltered helper.
pub enum Spawn {
  /// Child: apply the envelope, then exec the agent command.
  Agent,
  /// Parent: run `broker.supervise()`, reap the agent, exit its code.
  Supervisor(Broker),
}

pub struct Broker {
  pub listener: RawFd,
  pub agent_pid: libc::pid_t,
  helper_sock: RawFd,
  helper_pid: libc::pid_t,
  agent_status: Option<i32>,
}

impl Broker {
  /// Run the decision loop until the agent tree exits, delegating
  /// allow-path connects to the unfiltered helper (the supervisor
  /// itself is filtered, so it must not call connect).
  ///
  /// The listener is set non-blocking: NOTIF_RECV blocks forever while
  /// the supervisor holds the listener open, even after the agent is
  /// gone (ENOENT only fires when every listener fd closes — found
  /// live, 2026-09-05). EAGAIN + waitpid(WNOHANG) is the exit signal.
  pub fn run(&mut self, policy: &mut EgressPolicy, log: &Sender<BrokerEvent>) -> io::Result<u64> {
    let mut count = 0u64;
    let mut last_refresh = std::time::Instant::now();
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
      let (verdict, reason, detail) = decide_notification(&req, policy);
      let _ = log.send(BrokerEvent { pid: req.pid, verdict, reason, detail: detail.clone() });
      let (verdict, _reason) = if verdict == Verdict::Deny
        && !policy.allow_hosts.is_empty()
        && last_refresh.elapsed().as_secs() >= 30
      {
        last_refresh = std::time::Instant::now();
        refresh_hosts(policy);
        let (v2, r2, _) = decide_notification(&req, policy);
        (v2, if v2 == Verdict::Allow { "host-refresh" } else { r2 })
      } else {
        (verdict, reason)
      };
      respond(self.listener, self.helper_sock, &req, verdict)?;
    }
  }

  /// Reap the agent and the helper; returns the agent's exit code.
  pub fn finish(self) -> i32 {
    let code = match self.agent_status {
      Some(c) => c,
      None => reap(self.agent_pid),
    };
    unsafe {
      libc::close(self.helper_sock);
    }
    // The helper exits when its socketpair closes; reap it best-effort.
    let mut status = 0;
    unsafe {
      libc::waitpid(self.helper_pid, &mut status, libc::WNOHANG);
    }
    code
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

/// Install the filter in the supervisor, fork an unfiltered connect
/// helper and the agent. The caller must branch immediately:
/// `Spawn::Agent` -> apply envelope + exec; `Spawn::Supervisor` -> run.
pub fn spawn_broker() -> io::Result<Spawn> {
  let mut sv = [0 as RawFd; 2];
  let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) };
  if rc != 0 {
    return Err(io::Error::last_os_error());
  }
  let helper_pid = unsafe { libc::fork() };
  if helper_pid < 0 {
    return Err(io::Error::last_os_error());
  }
  if helper_pid == 0 {
    // Helper: unfiltered (forked before the filter is installed).
    unsafe { libc::close(sv[0]) };
    helper_loop(sv[1]);
    unsafe { libc::_exit(0) };
  }
  unsafe { libc::close(sv[1]) };
  let listener = install_listener()?;
  let agent_pid = unsafe { libc::fork() };
  if agent_pid < 0 {
    return Err(io::Error::last_os_error());
  }
  if agent_pid == 0 {
    // Agent: inherits the filter. Drop the listener and helper socket.
    unsafe {
      libc::close(listener);
      libc::close(sv[0]);
    }
    return Ok(Spawn::Agent);
  }
  Ok(Spawn::Supervisor(Broker { listener, agent_pid, helper_sock: sv[0], helper_pid, agent_status: None }))
}

/// Unfiltered helper: performs connects on behalf of the supervisor
/// and returns the connected fd via SCM_RIGHTS. Message format:
/// [family u32][len u32][sockaddr bytes] -> [ok u8][errno i32] (+fd).
fn helper_loop(sock: RawFd) {
  loop {
    let mut buf = [0u8; 260];
    let n = unsafe { libc::recv(sock, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
    if n <= 0 {
      return;
    }
    let n = n as usize;
    if n < 8 {
      continue;
    }
    let family = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as i32;
    let len = u32::from_ne_bytes(buf[4..8].try_into().unwrap()) as usize;
    if 8 + len > n {
      continue;
    }
    let sa = &buf[8..8 + len];
    let sfd = unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if sfd < 0 {
      let err = io::Error::last_os_error().raw_os_error().unwrap_or(libc::EPERM);
      reply_err(sock, err);
      continue;
    }
    let rc = unsafe { libc::connect(sfd, sa.as_ptr() as *const libc::sockaddr, len as u32) };
    if rc < 0 {
      let err = io::Error::last_os_error().raw_os_error().unwrap_or(libc::EPERM);
      unsafe { libc::close(sfd) };
      reply_err(sock, err);
      continue;
    }
    if send_fd(sock, sfd).is_err() {
      unsafe { libc::close(sfd) };
    }
    unsafe { libc::close(sfd) };
  }
}

fn reply_err(sock: RawFd, err: i32) {
  let msg = [0u8; 5];
  let mut m = msg;
  m[1..5].copy_from_slice(&err.to_ne_bytes());
  unsafe {
    libc::send(sock, m.as_ptr() as *const _, m.len(), 0);
  }
}

/// Ask the helper for a connected fd. Returns Ok(fd) or Err(errno).
/// NOTE: the request uses `write(2)`, not `send(2)` — glibc's `send`
/// is a `sendto` wrapper, and `sendto` is in the notif filter, so the
/// supervisor would deadlock against its own notification (found live,
/// 2026-09-05).
fn helper_connect(sock: RawFd, family: i32, sa: &[u8]) -> Result<RawFd, i32> {
  let mut req = Vec::with_capacity(8 + sa.len());
  req.extend_from_slice(&(family as u32).to_ne_bytes());
  req.extend_from_slice(&(sa.len() as u32).to_ne_bytes());
  req.extend_from_slice(sa);
  let n = unsafe { libc::write(sock, req.as_ptr() as *const _, req.len()) };
  if n < 0 {
    return Err(libc::EPERM);
  }
  let mut buf = [0u8; 8];
  let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: buf.len() };
  let mut cmsg_buf = [0u8; 64];
  let mut msg: libc::msghdr = unsafe { mem::zeroed() };
  msg.msg_iov = &mut iov;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
  msg.msg_controllen = cmsg_buf.len();
  let rc = unsafe { libc::recvmsg(sock, &mut msg, 0) };
  if rc < 0 {
    return Err(libc::EPERM);
  }
  let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
  if !cmsg.is_null() && unsafe { (*cmsg).cmsg_type } == libc::SCM_RIGHTS {
    let mut fd: RawFd = -1;
    unsafe {
      std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg), &mut fd as *mut RawFd as *mut u8, 4);
    }
    Ok(fd)
  } else {
    Err(i32::from_ne_bytes(buf[1..5].try_into().unwrap_or([libc::EPERM as u8; 4])))
  }
}

pub fn send_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
  // The helper is unfiltered so sendmsg is safe here; the supervisor
  // must never call this (sendmsg is in its filter).
  let mut byte = [1u8; 1];
  let iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut _, iov_len: 1 };
  let mut cmsg_buf = [0u8; 64];
  let mut msg: libc::msghdr = unsafe { mem::zeroed() };
  msg.msg_iov = &iov as *const _ as *mut _;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
  msg.msg_controllen = cmsg_buf.len();
  let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
  unsafe {
    (*cmsg).cmsg_level = libc::SOL_SOCKET;
    (*cmsg).cmsg_type = libc::SCM_RIGHTS;
    (*cmsg).cmsg_len = libc::CMSG_LEN(4) as usize;
    std::ptr::copy_nonoverlapping(&fd as *const RawFd as *const u8, libc::CMSG_DATA(cmsg), 4);
  }
  msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) as usize };
  let rc = unsafe { libc::sendmsg(sock, &msg, 0) };
  if rc < 0 {
    Err(io::Error::last_os_error())
  } else {
    Ok(())
  }
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
    let p = EgressPolicy::new();
    assert_eq!(evaluate_v4(Ipv4Addr::new(127, 0, 0, 1), &p), Verdict::Allow);
    assert_eq!(evaluate_v4(Ipv4Addr::new(8, 8, 8, 8), &p), Verdict::Deny);
    assert_eq!(evaluate_v4(Ipv4Addr::new(192, 168, 1, 227), &p), Verdict::Deny);
  }

  #[test]
  fn resolver_allowed() {
    let mut p = EgressPolicy::new();
    p.resolver_ips.push(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
    assert_eq!(evaluate_v4(Ipv4Addr::new(9, 9, 9, 9), &p), Verdict::Allow);
  }

  #[test]
  fn extra_ip_allowed() {
    let mut p = EgressPolicy::new();
    p.extra_ips.push(IpAddr::V4(Ipv4Addr::new(140, 82, 112, 5)));
    assert_eq!(evaluate_v4(Ipv4Addr::new(140, 82, 112, 5), &p), Verdict::Allow);
  }

  #[test]
  fn systemd_socket_denied_by_default() {
    let p = EgressPolicy::new();
    let sa = Sockaddr::Unix(b"/run/user/1000/systemd/private".to_vec());
    assert_eq!(decide(&sa, &p).0, Verdict::Deny);
    let sa = Sockaddr::Unix(b"/run/user/1000/bus".to_vec());
    assert_eq!(decide(&sa, &p).0, Verdict::Deny);
    let sa = Sockaddr::Unix(b"/run/user/1000/wayland-0".to_vec());
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
