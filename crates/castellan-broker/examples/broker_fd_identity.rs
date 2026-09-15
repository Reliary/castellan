// B8.2 gate probe: does ADDFD_FLAG_SEND preserve fd identity?
//
// The broker's allow-path for connect() has the supervisor perform the
// connect and inject the connected fd, which the kernel returns as the
// value of the tracee's connect() call. The tracee's ORIGINAL socket fd
// is therefore never connected.
//
// Virtually every program does:
//     s = socket(); connect(s, ...); write(s, ...)
// ignoring connect's return value. If the injected fd is a different
// number, that pattern breaks (ENOTCONN on the original).
//
// This probe forks an unfiltered echo server, then runs the broker with
// an allow policy for loopback and has the agent write on the ORIGINAL
// fd. Exit codes:
//   0  original fd connected and echoed correctly (identity preserved)
//   2  write on original fd failed with ENOTCONN (identity broken)
//   3  other failure
//
// Run: cargo run --release -p castellan-broker --example broker_fd_identity

use castellan_broker::*;
use std::io;
use std::mem;

fn main() {
  let (srv_pid, port) = match start_echo_server() {
    Some(v) => v,
    None => {
      eprintln!("fd-identity: could not start echo server");
      std::process::exit(3);
    }
  };
  match spawn_broker().expect("spawn_broker") {
    Spawn::Agent => {
      let rc = agent_work(port);
      unsafe { libc::_exit(rc) };
    }
    Spawn::Supervisor(mut broker) => {
      // Open egress (restrict_ip=false): the only broker effect under
      // test is the connect allow-path's fd injection.
      let mut policy = EgressPolicy::new();
      policy.restrict_ip = false;
      let (_tx, rx) = broker_log();
      let _ = broker.run(&mut policy, &_tx).expect("run");
      let code = broker.finish();
      // reap the echo server
      unsafe {
        libc::kill(srv_pid, libc::SIGTERM);
        let mut st = 0;
        libc::waitpid(srv_pid, &mut st, 0);
      }
      let events: Vec<BrokerEvent> = rx.try_iter().collect();
      for e in &events {
        eprintln!("  broker: {:?} {} {}", e.verdict, e.reason, e.detail);
      }
      match code {
        0 => println!("FD-IDENTITY-PRESERVED"),
        2 => println!("FD-IDENTITY-BROKEN"),
        _ => println!("FD-IDENTITY-OTHER(code={code})"),
      }
    }
  }
}

/// Fork a child that listens on an ephemeral loopback port and echoes
/// one message. Returns (child pid, port). The child is forked before
/// the broker filter is installed, so it is unfiltered.
fn start_echo_server() -> Option<(libc::pid_t, u16)> {
  let sfd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
  if sfd < 0 {
    return None;
  }
  let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
  sa.sin_family = libc::AF_INET as u16;
  sa.sin_port = 0;
  sa.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::new(127, 0, 0, 1)).to_be();
  if unsafe { libc::bind(sfd, &sa as *const _ as *const libc::sockaddr, mem::size_of::<libc::sockaddr_in>() as u32) } != 0 {
    return None;
  }
  if unsafe { libc::listen(sfd, 8) } != 0 {
    return None;
  }
  let mut len = mem::size_of::<libc::sockaddr_in>() as u32;
  if unsafe { libc::getsockname(sfd, &mut sa as *mut _ as *mut libc::sockaddr, &mut len) } != 0 {
    return None;
  }
  let port = u16::from_be(sa.sin_port);
  let pid = unsafe { libc::fork() };
  if pid < 0 {
    return None;
  }
  if pid == 0 {
    // Child: unfiltered echo server, one connection.
    let cfd = unsafe { libc::accept(sfd, std::ptr::null_mut(), std::ptr::null_mut()) };
    if cfd >= 0 {
      let mut buf = [0u8; 64];
      let n = unsafe { libc::read(cfd, buf.as_mut_ptr() as *mut _, buf.len()) };
      if n > 0 {
        let _ = unsafe { libc::write(cfd, buf.as_ptr() as *const _, n as usize) };
      }
      unsafe { libc::close(cfd) };
    }
    unsafe { libc::close(sfd) };
    unsafe { libc::_exit(0) };
  }
  unsafe { libc::close(sfd) };
  Some((pid, port))
}

fn agent_work(port: u16) -> i32 {
  let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
  if fd < 0 {
    return 3;
  }
  let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
  sa.sin_family = libc::AF_INET as u16;
  sa.sin_port = port.to_be();
  sa.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::new(127, 0, 0, 1)).to_be();
  let r = unsafe {
    libc::connect(fd, &sa as *const _ as *const libc::sockaddr, mem::size_of::<libc::sockaddr_in>() as u32)
  };
  if r < 0 {
    let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    eprintln!("agent: connect failed errno={err}");
    return 3;
  }
  // The program's pattern: keep using the fd it passed to connect().
  let msg = b"PING\n";
  let wn = unsafe { libc::write(fd, msg.as_ptr() as *const _, msg.len()) };
  if wn < 0 {
    let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    eprintln!("agent: write on ORIGINAL fd failed errno={err} (connect returned {r})");
    if err == libc::ENOTCONN || err == libc::EBADF {
      return 2;
    }
    return 3;
  }
  let mut buf = [0u8; 16];
  let rn = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
  if rn <= 0 {
    eprintln!("agent: read on ORIGINAL fd failed (connect returned {r})");
    return 3;
  }
  if &buf[..rn as usize] == msg {
    0
  } else {
    3
  }
}
