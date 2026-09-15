// B8.1 live verification — the broker crate end-to-end.
//
// Supervisor forks an agent; the agent installs the notif filter and
// hands the listener back; the supervisor decides:
//   - TCP 1.2.3.4:443        -> DENY (public IP not on allowlist)
//   - TCP 127.0.0.1:9999     -> ALLOW (loopback; ECONNREFUSED proves it ran)
//   - unix /run/user/N/systemd/private -> DENY (T4 structural close)
//   - unix /run/user/N/wayland-0       -> ALLOW (legit local socket)
//   - UDP sendto 8.8.8.8:53  -> DENY (public UDP not on allowlist)
//
// Run: cargo run --release -p castellan-broker --example broker_live

use castellan_broker::*;
use std::io;
use std::mem;

fn main() {
  let (tx, rx) = broker_log();
  match spawn_broker().expect("spawn_broker") {
    Spawn::Agent => {
      // Agent side: the notif filter is already installed (inherited).
      let rc = agent_work();
      unsafe { libc::_exit(rc) };
    }
    Spawn::Supervisor(mut broker) => {
      let mut policy = EgressPolicy::new();
      // Resolvers are allowed by default (DNS survival); empty here to
      // keep the probe deterministic on machines with unusual resolvers.
      policy.resolver_ips.clear();
      let n = broker.run(&mut policy, &tx).expect("supervise");
      let code = broker.finish();
      let events: Vec<BrokerEvent> = rx.try_iter().collect();
      println!("--- broker decisions ({} notifications) ---", n);
      for e in &events {
        println!("  pid={} {:?} {} {}", e.pid, e.verdict, e.reason, e.detail);
      }
      let denied = events.iter().filter(|e| e.verdict == Verdict::Deny).count();
      let allowed = events.iter().filter(|e| e.verdict == Verdict::Allow).count();
      let sysd = events.iter().any(|e| e.reason == "systemd-socket" && e.verdict == Verdict::Deny);
      let udp = events.iter().any(|e| e.detail.contains("8.8.8.8") && e.verdict == Verdict::Deny);
      let loopback = events.iter().any(|e| e.detail.contains("127.0.0.1") && e.verdict == Verdict::Allow);
      let unix_ok = events.iter().any(|e| e.reason == "unix" && e.verdict == Verdict::Allow);
      let ok = code == 0 && denied == 3 && allowed == 2 && sysd && udp && loopback && unix_ok;
      println!("summary: denied={denied} allowed={allowed} sysd={sysd} udp={udp} loopback={loopback} unix_ok={unix_ok} agent_exit={code}");
      println!("B8.1-LIVE-{}", if ok { "PASS" } else { "FAIL" });
    }
  }
}

fn agent_work() -> i32 {
  let mut failures = 0;
  // 1. public TCP -> must be denied EPERM
  unsafe {
    let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    let mut sa: libc::sockaddr_in = mem::zeroed();
    sa.sin_family = libc::AF_INET as u16;
    sa.sin_port = 443u16.to_be();
    sa.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::new(1, 2, 3, 4)).to_be();
    let r = libc::connect(fd, &sa as *const _ as *const libc::sockaddr, mem::size_of::<libc::sockaddr_in>() as u32);
    let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if r != -1 || err != libc::EPERM {
      eprintln!("agent: public TCP NOT denied (r={r} errno={err})");
      failures += 1;
    }
    libc::close(fd);
  }
  // 2. loopback TCP -> allowed; connection refused proves the syscall ran
  unsafe {
    let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
    let mut sa: libc::sockaddr_in = mem::zeroed();
    sa.sin_family = libc::AF_INET as u16;
    sa.sin_port = 9999u16.to_be();
    sa.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::new(127, 0, 0, 1)).to_be();
    let r = libc::connect(fd, &sa as *const _ as *const libc::sockaddr, mem::size_of::<libc::sockaddr_in>() as u32);
    let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if r == -1 && err != libc::ECONNREFUSED {
      eprintln!("agent: loopback NOT allowed (errno={err})");
      failures += 1;
    }
    libc::close(fd);
  }
  // 3. systemd private socket -> denied
  unsafe {
    let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
    let mut sa: libc::sockaddr_un = mem::zeroed();
    sa.sun_family = libc::AF_UNIX as u16;
    let path = format!("/run/user/{}/systemd/private", libc::getuid());
    let bytes = path.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
      sa.sun_path[i] = *b as i8;
    }
    let r = libc::connect(fd, &sa as *const _ as *const libc::sockaddr, mem::size_of::<libc::sockaddr_un>() as u32);
    let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if r != -1 || err != libc::EPERM {
      eprintln!("agent: systemd socket NOT denied (r={r} errno={err})");
      failures += 1;
    }
    libc::close(fd);
  }
  // 4. UDP sendto public resolver -> denied
  unsafe {
    let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
    let mut sa: libc::sockaddr_in = mem::zeroed();
    sa.sin_family = libc::AF_INET as u16;
    sa.sin_port = 53u16.to_be();
    sa.sin_addr.s_addr = u32::from(std::net::Ipv4Addr::new(8, 8, 8, 8)).to_be();
    let payload = b"probe";
    let r = libc::sendto(
      fd,
      payload.as_ptr() as *const _,
      payload.len(),
      0,
      &sa as *const _ as *const libc::sockaddr,
      mem::size_of::<libc::sockaddr_in>() as u32,
    );
    let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if r != -1 || err != libc::EPERM {
      eprintln!("agent: UDP sendto NOT denied (r={r} errno={err})");
      failures += 1;
    }
    libc::close(fd);
  }
  // 5. non-manager unix socket -> allowed through the broker (ENOENT
  //    from the helper's connect proves it was not EPERM-denied).
  unsafe {
    let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
    let mut sa: libc::sockaddr_un = mem::zeroed();
    sa.sun_family = libc::AF_UNIX as u16;
    let path = format!("/run/user/{}/castellan-b8-nonexistent.sock", libc::getuid());
    for (i, b) in path.as_bytes().iter().enumerate() {
      sa.sun_path[i] = *b as i8;
    }
    let _r = libc::connect(fd, &sa as *const _ as *const libc::sockaddr, mem::size_of::<libc::sockaddr_un>() as u32);
    let err = io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if err == libc::EPERM {
      eprintln!("agent: non-manager unix socket EPERM-denied (should pass through)");
      failures += 1;
    }
    libc::close(fd);
  }
  failures
}
