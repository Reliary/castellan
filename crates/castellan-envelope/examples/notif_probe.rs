// B8.0 probe — seccomp user-notification viability on the live kernel.
//
// Validates, before any broker code is written:
//   1. SECCOMP_SET_MODE_FILTER + NEW_LISTENER yields a listener fd.
//   2. The supervisor receives connect() notifications and can read the
//      tracee's sockaddr via process_vm_readv.
//   3. Deny (EPERM) and allow (CONTINUE) both take effect.
//   4. Per-notification overhead vs an unfiltered baseline.
//
// Run: cargo run --release -p castellan-envelope --example notif_probe

use std::io;
use std::mem;
use std::os::fd::RawFd;
use std::time::Instant;

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 8;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xC050_2100;
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xC018_2101;

const DENY_IP: [u8; 4] = [1, 2, 3, 4];
const DENY_PORT: u16 = 443;
const ALLOW_PORT: u16 = 9999;

#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompData {
  nr: i32,
  arch: u32,
  instruction_pointer: u64,
  args: [u64; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompNotif {
  id: u64,
  pid: u32,
  flags: u32,
  data: SeccompData,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompNotifResp {
  id: u64,
  val: i64,
  error: i32,
  flags: u32,
}

fn f(code: u32, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
  libc::sock_filter { code: code as u16, jt, jf, k }
}

fn notif_program() -> Vec<libc::sock_filter> {
  vec![
    f(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
    f(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 1, libc::SYS_connect as u32),
    f(libc::BPF_RET | libc::BPF_K, 0, 0, SECCOMP_RET_USER_NOTIF),
    f(libc::BPF_RET | libc::BPF_K, 0, 0, SECCOMP_RET_ALLOW),
  ]
}

unsafe fn install_listener() -> io::Result<RawFd> {
  let prog = notif_program();
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

unsafe fn send_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
  let mut byte = [0u8; 1];
  let iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut _, iov_len: 1 };
  let mut cmsg_buf = [0u8; 64];
  let mut msg: libc::msghdr = mem::zeroed();
  msg.msg_iov = &iov as *const _ as *mut _;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
  msg.msg_controllen = cmsg_buf.len();
  let cmsg = libc::CMSG_FIRSTHDR(&msg);
  (*cmsg).cmsg_level = libc::SOL_SOCKET;
  (*cmsg).cmsg_type = libc::SCM_RIGHTS;
  (*cmsg).cmsg_len = libc::CMSG_LEN(4) as usize;
  std::ptr::copy_nonoverlapping(&fd as *const RawFd as *const u8, libc::CMSG_DATA(cmsg), 4);
  msg.msg_controllen = libc::CMSG_SPACE(4) as usize;
  if libc::sendmsg(sock, &msg, 0) < 0 {
    Err(io::Error::last_os_error())
  } else {
    Ok(())
  }
}

unsafe fn recv_fd(sock: RawFd) -> io::Result<RawFd> {
  let mut byte = [0u8; 1];
  let iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut _, iov_len: 1 };
  let mut cmsg_buf = [0u8; 64];
  let mut msg: libc::msghdr = mem::zeroed();
  msg.msg_iov = &iov as *const _ as *mut _;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
  msg.msg_controllen = cmsg_buf.len();
  if libc::recvmsg(sock, &mut msg, 0) < 0 {
    return Err(io::Error::last_os_error());
  }
  let cmsg = libc::CMSG_FIRSTHDR(&msg);
  if cmsg.is_null() || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
    return Err(io::Error::new(io::ErrorKind::Other, "no SCM_RIGHTS"));
  }
  let mut fd: RawFd = -1;
  std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg), &mut fd as *mut RawFd as *mut u8, 4);
  Ok(fd)
}

fn sockaddr_v4(ip: [u8; 4], port: u16) -> libc::sockaddr_in {
  let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
  sa.sin_family = libc::AF_INET as u16;
  sa.sin_port = port.to_be();
  sa.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])).to_be();
  sa
}

unsafe fn connect_v4(fd: RawFd, ip: [u8; 4], port: u16) -> i32 {
  let sa = sockaddr_v4(ip, port);
  libc::connect(fd, &sa as *const _ as *const libc::sockaddr, mem::size_of::<libc::sockaddr_in>() as u32)
}

struct Stats {
  notifs: u64,
  denied: u64,
  allowed: u64,
}

unsafe fn supervise(listener: RawFd) -> io::Result<Stats> {
  let mut stats = Stats { notifs: 0, denied: 0, allowed: 0 };
  loop {
    let mut req: SeccompNotif = mem::zeroed();
    if libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &mut req) < 0 {
      let e = io::Error::last_os_error();
      // ENOENT: no more tracees. EINTR: retry. Anything else: report.
      match e.raw_os_error() {
        Some(libc::ENOENT) => return Ok(stats),
        Some(libc::EINTR) => continue,
        _ => return Err(e),
      }
    }
    stats.notifs += 1;
    let ptr = req.data.args[1];
    let len = req.data.args[2].min(128) as usize;
    let mut buf = [0u8; 128];
    let local = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: len };
    let remote = libc::iovec { iov_base: ptr as *mut _, iov_len: len };
    let n = libc::process_vm_readv(req.pid as i32, &local, 1, &remote, 1, 0);
    let mut deny = false;
    if n >= 16 && buf[0] as i32 == libc::AF_INET {
      let port = u16::from_be_bytes([buf[2], buf[3]]);
      let ip = [buf[4], buf[5], buf[6], buf[7]];
      deny = ip == DENY_IP && port == DENY_PORT;
      println!("  notif: connect to {}.{}.{}.{}:{} -> {}", ip[0], ip[1], ip[2], ip[3], port, if deny { "DENY" } else { "ALLOW" });
    } else {
      println!("  notif: connect family={} (unparsed, allowing)", if n >= 2 { buf[0] as i32 } else { -1 });
    }
    if deny {
      stats.denied += 1;
    } else {
      stats.allowed += 1;
    }
    let mut resp = SeccompNotifResp {
      id: req.id,
      val: 0,
      // Kernel contract: `error` must be a NEGATIVE errno (it becomes the
      // syscall return value). +EPERM made connect return 1, not -1.
      error: if deny { -libc::EPERM } else { 0 },
      flags: if deny { 0 } else { SECCOMP_USER_NOTIF_FLAG_CONTINUE },
    };
    if libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &mut resp) < 0 {
      let e = io::Error::last_os_error();
      if e.raw_os_error() != Some(libc::ENOENT) {
        return Err(e);
      }
    }
  }
}

fn baseline() -> io::Result<u128> {
  let n = 200;
  let start = Instant::now();
  unsafe {
    for _ in 0..n {
      let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
      if fd < 0 {
        return Err(io::Error::last_os_error());
      }
      let r = connect_v4(fd, [127, 0, 0, 1], ALLOW_PORT);
      if r != -1 || io::Error::last_os_error().raw_os_error() != Some(libc::ECONNREFUSED) {
        return Err(io::Error::new(io::ErrorKind::Other, "baseline connect not refused"));
      }
      libc::close(fd);
    }
  }
  Ok(start.elapsed().as_micros() / n)
}

fn child_work() -> io::Result<()> {
  unsafe {
    // 1. denied destination
    let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    let r = connect_v4(fd, DENY_IP, DENY_PORT);
    let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    println!("child: connect 1.2.3.4:443 -> r={} errno={} ({})", r, err, if err == libc::EPERM { "DENIED as expected" } else { "UNEXPECTED" });
    libc::close(fd);
    // 2. allowed destination (connection refused proves the syscall ran)
    let n = 199;
    let start = Instant::now();
    let mut refused = 0;
    for _ in 0..n {
      let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
      let r = connect_v4(fd, [127, 0, 0, 1], ALLOW_PORT);
      if r == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::ECONNREFUSED) {
        refused += 1;
      }
      libc::close(fd);
    }
    let us = start.elapsed().as_micros() / n;
    println!("child: allowed loop {}/{} refused; {} us/connect with notification", refused, n, us);
  }
  Ok(())
}

fn main() {
  println!("B8.0 seccomp user-notification probe");
  match baseline() {
    Ok(us) => println!("baseline: {} us/connect (unfiltered)", us),
    Err(e) => println!("baseline failed: {e}"),
  }
  unsafe {
    let mut sv = [0 as RawFd; 2];
    if libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) != 0 {
      println!("socketpair failed: {}", io::Error::last_os_error());
      return;
    }
    let pid = libc::fork();
    if pid == 0 {
      libc::close(sv[0]);
      let listener = match install_listener() {
        Ok(fd) => fd,
        Err(e) => {
          println!("child: install_listener failed: {e}");
          libc::_exit(2);
        }
      };
      if let Err(e) = send_fd(sv[1], listener) {
        println!("child: send_fd failed: {e}");
        libc::_exit(3);
      }
      libc::close(sv[1]);
      libc::close(listener);
      let rc = match child_work() {
        Ok(()) => 0,
        Err(e) => {
          println!("child: work failed: {e}");
          4
        }
      };
      libc::_exit(rc);
    }
    libc::close(sv[1]);
    let listener = match recv_fd(sv[0]) {
      Ok(fd) => fd,
      Err(e) => {
        println!("parent: recv_fd failed: {e}");
        libc::close(sv[0]);
        return;
      }
    };
    libc::close(sv[0]);
    match supervise(listener) {
      Ok(s) => {
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        let ok = s.notifs >= 200 && s.denied == 1 && s.allowed >= 199 && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        println!("summary: notifs={} denied={} allowed={} child_exit={}", s.notifs, s.denied, s.allowed, libc::WEXITSTATUS(status));
        println!("B8.0-BASIC-{}", if ok { "PASS" } else { "FAIL" });
      }
      Err(e) => println!("supervise failed: {e}"),
    }
    libc::close(listener);
  }
  unsafe {
    addfd_probe();
  }
}

// Phase 2: the TOCTOU-safe allow path. The header is explicit that
// SECCOMP_USER_NOTIF_FLAG_CONTINUE cannot implement a security policy
// (a racing thread can rewrite the sockaddr while the tracee waits).
// The safe shape is: the SUPERVISOR performs the connect and injects
// the resulting fd into the tracee with SECCOMP_IOCTL_NOTIF_ADDFD.
// ADDFD alone only installs the fd; the tracee stays blocked until a
// response is sent. ADDFD_FLAG_SEND injects and responds atomically,
// with the fd number as the syscall return value.
const SECCOMP_ADDFD_FLAG_SEND: u32 = 2;
const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0x4018_2103;

#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompNotifAddfd {
  id: u64,
  flags: u32,
  srcfd: u32,
  newfd: u32,
  newfd_flags: u32,
}

unsafe fn addfd_probe() {
  println!("--- phase 2: ADDFD (TOCTOU-safe allow path) ---");
  let mut sv = [0 as RawFd; 2];
  if libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) != 0 {
    println!("ADDFD socketpair failed");
    return;
  }
  let pid = libc::fork();
  if pid == 0 {
    libc::close(sv[0]);
    let listener = match install_listener() {
      Ok(fd) => fd,
      Err(e) => {
        println!("child: install_listener failed: {e}");
        libc::_exit(2);
      }
    };
    if send_fd(sv[1], listener).is_err() {
      libc::_exit(3);
    }
    libc::close(sv[1]);
    libc::close(listener);
    // The child asks to connect to the allowed port; the supervisor
    // will hand it a REAL connected fd and return it as the syscall
    // result. Success = fd >= 0 and a send/recv round-trip on it.
    let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    if fd < 0 {
      println!("child: socket failed");
      libc::_exit(4);
    }
    let r = connect_v4(fd, [127, 0, 0, 1], ALLOW_PORT);
    println!("child(ADDFD): connect returned fd={} (orig {})", r, fd);
    if r < 0 {
      println!("child(ADDFD): injected connect failed errno={}", io::Error::last_os_error().raw_os_error().unwrap_or(0));
      libc::_exit(5);
    }
    libc::_exit(0);
  }
  libc::close(sv[1]);
  let listener = match recv_fd(sv[0]) {
    Ok(fd) => fd,
    Err(e) => {
      println!("ADDFD parent recv_fd failed: {e}");
      return;
    }
  };
  libc::close(sv[0]);
  unsafe {
    let mut req: SeccompNotif = mem::zeroed();
    if libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &mut req) < 0 {
      println!("ADDFD RECV failed: {}", io::Error::last_os_error());
      return;
    }
    // Supervisor opens and connects the socket itself, then injects it
    // with ADDFD_FLAG_SEND: the fd number becomes connect()'s return
    // value and the tracee unblocks. The tracee's own fd argument is
    // ignored by the injected result — a racing rewrite cannot redirect
    // a connection the supervisor already made.
    let sfd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    let r = connect_v4(sfd, [127, 0, 0, 1], ALLOW_PORT);
    println!("supervisor: own connect -> {} (errno {})", r, io::Error::last_os_error().raw_os_error().unwrap_or(0));
    let mut add = SeccompNotifAddfd { id: req.id, flags: SECCOMP_ADDFD_FLAG_SEND, srcfd: sfd as u32, newfd: 0, newfd_flags: libc::O_CLOEXEC as u32 };
    let injected = libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_ADDFD, &mut add);
    println!("supervisor: ADDFD|SEND -> {} (errno {})", injected, io::Error::last_os_error().raw_os_error().unwrap_or(0));
    let mut status = 0;
    libc::waitpid(pid, &mut status, 0);
    let ok = injected >= 0 && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    println!("B8.0-ADDFD-{}", if ok { "PASS" } else { "FAIL" });
  }
}
