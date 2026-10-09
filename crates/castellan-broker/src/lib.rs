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
//! Safety shape (B8.0, revised B8.2, re-revised F4c):
//! - **deny** — `-errno`, the kernel never executes the syscall. Robust:
//!   a racing thread cannot turn a deny into an execution.
//! - **allow** — `CONTINUE` (mandatory: without it the kernel skips
//!   execution and returns resp.val — proven live in F4b, reverted).
//!   CONTINUE re-reads pointer arguments at execution, so a racing
//!   thread CAN redirect a checked-allowed connect — closed instead by:
//!   (a) STABILITY: CONNECT sockaddrs are read twice 2ms apart; a flip
//!   denies as dest-unstable (full-speed flippers never agree; legit
//!   agents pay 2ms/connect); (b) RATE: >1000 connects/sec/pid throttles
//!   the pid for 10s (flippers need volume; agents never trip it).
//!   Residual: a slow flipper (<1 flip/2ms) under the rate cap can still
//!   win individual races — measured in the F4c gate, documented below.
//! - **(defeated)** flags=0 allow: fake-success without execution
//!   (F4b experiment, reverted same session).
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
//!
//! - **F1 signal scope (cross-session kill, fixed 2026-09-27):**
//!   `kill(2)` / `tkill(2)` / `tgkill(2)` / `pidfd_send_signal(2)` are
//!   routed to user-notify and decided by PID scope — a tracee may
//!   signal only PIDs that sit in its own session scope (read from
//!   /proc/<tracee>/cgroup at decision time, compared against
//!   /proc/<target>/cgroup). The supervisor performs no signaling
//!   itself, so it never notifies itself. Signals to self
//!   (pid == tracee, tkill/tgkill to own tid) are always allowed —
//!   runtimes (bash job control, python) use them constantly.

use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::ffi::OsStr;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::mpsc::Receiver;

pub const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 8;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
pub const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xC050_2100;
pub const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xC018_2101;
/// SECCOMP_RET_KILL_PROCESS (libc lacks the constant).
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
/// seccomp_data.arch for the native target. P13 ninja F3: without an
/// arch gate a compat tracee's syscall NUMBERS mean different syscalls
/// (i386 nr 11 is not x86_64 nr 11), so every JEQ compares wrong and
/// the tracee falls through to ALLOW — the whole broker bypassed.
#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64
/// x32 ABI sets bit 30 on every syscall nr while reporting the x86_64
/// arch — the arch gate alone passes it and the nr never equals a
/// plain SYS_* (0x4000002a != 42), so x32 connect() would fall through
/// to ALLOW too. Any nr above this bound is x32/unsupported.
pub const X32_NR_BOUND: u32 = 0x3fff_ffff;

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
#[derive(Debug, Clone)]
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
  /// The ssh/docker escape ports moved to `escape_port_denied` (P13
  /// ninja F2): exact pairs missed 127.0.0.2, v4-mapped loopback and
  /// the host's own LAN address — sshd accepts on all of them.
  pub denied_loopback: Vec<(IpAddr, u16)>,
  /// Local interface addresses (getifaddrs at construction). Used only
  /// by `escape_port_denied`: ssh to SELF via any local IP (docker0,
  /// LAN, tailscale) reaches this host's sshd exactly like 127.0.0.1 —
  /// same sshd-child-outside-every-layer escape (P13 ninja F2).
  pub local_ips: Vec<IpAddr>,
  /// Master switch for the escape-port rule (loopback/self ssh +
  /// docker TCP). Default true — same "escape channels deny by
  /// default" posture as the systemd sockets. `deny_loopback_ssh`
  /// keeps its name (call sites + tests) and toggles this flag.
  pub deny_escape_ports: bool,
  /// Deny the systemd user-manager sockets (T4). Default true.
  pub deny_systemd_sockets: bool,
  /// Deny the session bus (`$XDG_RUNTIME_DIR/bus`). Default true.
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
  /// Deny container/host-control deputy sockets. Default true.
  ///
  /// P13 E-b probed live 2026-09-30: `/run/docker.sock` CONNECTED from
  /// inside an enforced session (uid in the docker group; Landlock does
  /// not gate unix connect; the verdict denylist did not name it). A
  /// single POST /containers/create with a `/:/host` bind is root —
  /// one-shot, zero-cost, outside steelman tolerance. Same shape as the
  /// systemd fix: deny the deputy socket by default, legit use becomes
  /// an explicit grant. Honest limit: `is_deputy_socket` is a FIXED
  /// suffix list (docker, podman, lxd, incus, libvirt, containerd,
  /// crio, snapd) — a new install path IS a code change, plus a test.
  pub deny_deputy_sockets: bool,
  /// Deny the SYSTEM bus (`/run/dbus/system_bus_socket`). Default true.
  ///
  /// P13 E-c probed 2026-09-30: the socket is world-rw, matched neither
  /// the systemd predicate nor the user-bus predicate, and pkcheck
  /// returned rc=0 (authorized WITHOUT authentication) for both
  /// `org.freedesktop.udisks2.loop-setup` and
  /// `org.freedesktop.udisks2.filesystem-mount` for an active session —
  /// a root daemon (UID 0, running) acting on the agent's behalf with no
  /// polkit challenge. That is the frozen plan's one-shot-class gate, so
  /// the bus denies by default. `org.freedesktop.systemd1.manage-units`
  /// measured auth_admin_keep (rc=2) — the systemd1 system route is NOT
  /// the trigger; udisks2 is.
  ///
  /// Same scope note as the user bus: this carries ordinary desktop
  /// traffic too, and denying it can break harnesses that probe
  /// hardware over D-Bus. Breaking is visible (tool errors), denial is
  /// default-on, opt-out is this flag — same posture as the other unix
  /// denies, none of which carry runtime grants either.
  pub deny_system_bus: bool,
  /// When false (default), non-loopback IPs are allowed — the broker
  /// only closes the unix/systemd-socket hole and leaves egress alone.
  /// When true, only loopback + extra_ips + resolver_ips are allowed, and
  /// a destination argument the broker cannot read from tracee memory is
  /// DENIED (fail-closed: no proof of destination, no packet).
  pub restrict_ip: bool,
  /// Deny socket address families other than AF_INET/AF_INET6/AF_UNIX.
  /// Default true. P14 F-E (probed live 2026-10-01): the parser maps any
  /// other family to `Sockaddr::Other(fam)` and `decide()` returned
  /// ALLOW — measured AF_VSOCK and AF_SMC sockets opening inside a
  /// session (a connect on either is then waved through). No host-side
  /// VSOCK peer existed in the test, so this is not a confirmed escape,
  /// but the default was open where every other arm is fail-closed.
  /// AF_NETLINK (name resolution / kernel queries) and AF_ALG (local
  /// kernel crypto) are explicitly allowed; they are kernel-local, not
  /// egress. Everything else denies, and a family that a real workload
  /// needs becomes an explicit allow with a dated rationale.
  pub deny_unknown_family: bool,
}

impl EgressPolicy {
  pub fn new() -> Self {
    // Constructed field-by-field on purpose: `Default` routes through
    // this fn (P13: the derived Default silently skipped the ssh and
    // deputy denies), so new() must not use ..Default::default().
    let mut p = Self {
      extra_ips: Vec::new(),
      resolver_ips: resolver_ips(),
      denied_loopback: Vec::new(),
      local_ips: local_ips(),
      deny_escape_ports: true,
      deny_systemd_sockets: true,
      deny_user_bus: true,
      deny_deputy_sockets: true,
      deny_system_bus: true,
      restrict_ip: false,
      deny_unknown_family: true,
    };
    // Escape channels deny by default (systemd-socket precedent): ssh
    // localhost runs its command in an sshd child outside every layer —
    // same class as systemd-run, so it does not wait for a destination
    // policy. P13 E-a probed live 2026-09-30: default --enforce posture
    // connected to 127.0.0.1:22 from inside a session (fix-scoped-to-
    // with_llm_only was the bug; the first fix only covered the floor).
    p.deny_loopback_ssh();
    p
  }

  /// P13 ninja F12: audit posture — `--no-enforce`'s banner promises
  /// "writes are logged, nothing is blocked", so EVERY default deny is off
  /// (escape ports, systemd, buses, deputies, stub pairs). The daemon's
  /// AuditWatcher is what records WOULD-DENY (daemon-side, no broker
  /// needed); with an allow-everything policy the broker would record
  /// nothing anyway and cost a notification round-trip per connect.
  /// Callers layer an explicitly requested destination policy on top
  /// (`with_llm_only`) — that is operator-requested containment, not a
  /// default contradicting the banner.
  pub fn audit() -> Self {
    let mut p = Self::new();
    p.deny_escape_ports = false;
    p.deny_systemd_sockets = false;
    p.deny_user_bus = false;
    p.deny_deputy_sockets = false;
    p.deny_system_bus = false;
    p.deny_unknown_family = false;
    p.denied_loopback.clear();
    p
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
  /// Loopback SSH (`deny_loopback_ssh`, same mechanism) is applied
  /// automatically too — same relay shape: the server child is outside
  /// every layer.
  pub fn with_llm_only(mut self, hosts: &[String]) -> Self {
    self.restrict_ip = true;
    self.resolver_ips.clear();
    self.deny_resolver_stub();
    self.deny_loopback_ssh();
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

  /// DENY loopback SSH. `ssh localhost <cmd>` is a full three-layer
  /// escape: the client connect to 127.0.0.1:22 is inside the session
  /// (allowed by the blanket loopback rule), but the command runs in a
  /// child forked by sshd — outside the session cgroup, outside the
  /// Landlock domain, outside the seccomp filter. The N6 orphan census
  /// cannot see it (ppid is system sshd, not the user manager) and the
  /// sibling detector never matches `sshd:/bin/sh` basenames, so without
  /// this deny the escape is silent: no spine row, no freeze, no trust
  /// hit.
  ///
  /// P13 ninja F2 (2026-09-30): the first implementation pinned exact
  /// (ip, port) pairs — 127.0.0.1/::1 × {22,2222,200} — which missed
  /// 127.0.0.2, v4-mapped [::ffff:127.0.0.1] and the host's own LAN
  /// address (sshd binds 0.0.0.0; all of them reach it). The pairs are
  /// replaced by `escape_port_denied`: ANY loopback or self address on
  /// an escape port. This fn keeps its name (call sites, tests, spine
  /// history) and toggles the flag that arms that rule.
  ///
  /// Honest limit: port lists are enumerable, and remote ssh / cron / at
  /// need no loopback TCP at all. This closes the LLM-obvious door, not
  /// the class — the exclusion-census (B) closes the class.
  pub fn deny_loopback_ssh(&mut self) {
    self.deny_escape_ports = true;
  }

  /// Escape-port rule (P13 ninja F2): ssh and docker-TCP are dangerous
  /// only when the destination is THIS host — the server child (sshd,
  /// dockerd) then runs locally outside every session layer. Remote
  /// destinations are ordinary egress (default posture allows them;
  /// restrict_ip denies them by allowlist). Covers what the old exact
  /// pairs missed: all of 127.0.0.0/8, ::1, v4-mapped loopback,
  /// 0.0.0.0/[::] (kernel connect() maps them onto loopback), and every
  /// local interface address. Returns the spine reason when denied.
  pub fn escape_port_denied(&self, ip: &IpAddr, port: u16) -> Option<&'static str> {
    if !self.deny_escape_ports {
      return None;
    }
    let ssh = matches!(port, 22 | 2222 | 2200);
    let docker_tcp = matches!(port, 2375 | 2376);
    if !ssh && !docker_tcp {
      return None;
    }
    // Normalize v4-mapped ::ffff:a.b.c.d to its v4 form — the kernel
    // treats it as v4 for loopback/locality purposes.
    let norm = match ip {
      IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => *ip,
      },
      IpAddr::V4(_) => *ip,
    };
    if norm.is_loopback() || norm.is_unspecified() {
      return Some(if ssh { "loopback-ssh" } else { "docker-tcp" });
    }
    if self.local_ips.contains(&norm) {
      return Some(if ssh { "self-ssh" } else { "docker-tcp" });
    }
    None
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

impl Default for EgressPolicy {
  /// Routes through `new()` so the escape-channel denies (loopback ssh,
  /// deputy sockets, systemd) are never silently skipped. The derived
  /// Default would have zeroed every deny flag — found by P13 while
  /// making the ssh deny default-on.
  fn default() -> Self {
    Self::new()
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

/// Local interface addresses for `escape_port_denied` (P13 ninja F2).
///
/// FILTER-SAFE BY CONSTRUCTION: `EgressPolicy::new()` runs after
/// `spawn_broker()` installs the notif filter but before `run()` starts
/// answering, so any trapped syscall here (connect/sendto/sendmsg/...)
/// would self-deadlock the supervisor — `getifaddrs(3)` speaks netlink
/// (`sendto`) and is deliberately NOT used. `socket(2)`+`ioctl(2)` are
/// not in the broker jump table, and `/proc/net/if_inet6` is a plain
/// file read (open/read are not trapped either).
///
/// IPv4 via SIOCGIFCONF; IPv6 via /proc/net/if_inet6 (the ioctl is
/// v4-only). Loopback is in the result — `escape_port_denied` checks
/// loopback before consulting this list, duplicates are harmless.
pub fn local_ips() -> Vec<IpAddr> {
  let mut out: Vec<IpAddr> = Vec::new();
  unsafe {
    let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
    if fd >= 0 {
      let mut buf = [0u8; 4096];
      let mut ifc = libc::ifconf {
        ifc_len: buf.len() as libc::c_int,
        ifc_ifcu: libc::__c_anonymous_ifc_ifcu {
          ifcu_buf: buf.as_mut_ptr() as *mut libc::c_char,
        },
      };
      if libc::ioctl(fd, libc::SIOCGIFCONF, &mut ifc) == 0 {
        let stride = mem::size_of::<libc::ifreq>();
        let len = ifc.ifc_len as usize;
        let mut off = 0usize;
        while off + stride <= len {
          let req = &*(buf.as_ptr().add(off) as *const libc::ifreq);
          if req.ifr_ifru.ifru_addr.sa_family as i32 == libc::AF_INET {
            let sin =
              &req.ifr_ifru.ifru_addr as *const libc::sockaddr as *const libc::sockaddr_in;
            // s_addr is network order; from_be → the big-endian value
            // Ipv4Addr::from expects (first octet = most significant).
            let ip = IpAddr::V4(Ipv4Addr::from(u32::from_be((*sin).sin_addr.s_addr)));
            if !out.contains(&ip) {
              out.push(ip);
            }
          }
          off += stride;
        }
      }
      libc::close(fd);
    }
  }
  // IPv6: 32 hex digits, ifindex, prefixlen, scope, flags, name.
  if let Ok(text) = std::fs::read_to_string("/proc/net/if_inet6") {
    for line in text.lines() {
      let hex: &str = match line.split_whitespace().next() {
        Some(h) if h.len() == 32 => h,
        _ => continue,
      };
      let mut octets = [0u8; 16];
      let mut ok = true;
      for (i, slot) in octets.iter_mut().enumerate() {
        match u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16) {
          Ok(b) => *slot = b,
          Err(_) => {
            ok = false;
            break;
          }
        }
      }
      if ok {
        let ip = IpAddr::V6(Ipv6Addr::from(octets));
        if !out.contains(&ip) {
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
/// Scope note: the manager's private control socket and the cgroup
/// socket deny by default. The session bus (`/run/user/N/bus`) denies by
/// default too (B8.2 route 2: `org.freedesktop.systemd1` is exported
/// there and StartTransientUnit over it escapes — verified live
/// 2026-09-15), with `deny_user_bus` as the opt-out.
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

/// Container/host-control deputy sockets (P13 E-b). Connecting to any of
/// these hands the caller the service's full API: docker.sock is root by
/// contract (`POST /containers/create` + `/:/host` bind), the libvirt
/// sock can define a domain with host-filesystem passthrough. Matched by
/// suffix so the common install paths (/run, /var/run) both hit, and the
/// matched set stays explicit — no wildcard on ".sock" (that would eat
/// wayland, pipewire and every benign desktop socket).
///
/// P13 ninja review (2026-09-30): containerd/crio/incus/snapd added —
/// same contract, same one-shot class. Matched set is a fixed list
/// (paths below), not a pattern: anything not named here is allowed.
///
/// Seat-input deputy (P13 F10, probed 2026-09-30): /tmp/.X11-unix/X*
/// answered CONNECTED from an enforced session AND ~/.Xauthority was
/// readable (read roots are `/`) — with the cookie, any X11 client gets
/// XTEST keystroke injection into the human's seat and XGetImage screen
/// readback (X11 has no per-client input isolation; Wayland's
/// virtual-keyboard protocol IS privileged, X11's equivalent is not).
/// The plan's pre-registered rule: reachable + readable cookie → deny
/// by default. Same mechanism as the host-control deputies.
pub fn is_deputy_socket(path: &[u8]) -> bool {
  let s = String::from_utf8_lossy(path);
  s.ends_with("/docker.sock")
    || s.ends_with("/podman/podman.sock")
    || s.ends_with("/lxd/unix.socket")
    || s.ends_with("/lxd.socket")
    || s.ends_with("/incus/unix.socket")
    || s.ends_with("/libvirt/libvirt-sock")
    || s.ends_with("/libvirt/libvirt-sock-ro")
    || s.ends_with("/containerd/containerd.sock")
    || s.ends_with("/crio/crio.sock")
    || s.ends_with("/snapd.socket")
    || s.contains("/.X11-unix/X")
}

/// Run the unix suffix deny-list against one spelling of a path.
fn unix_match(path: &[u8], policy: &EgressPolicy) -> Option<(Verdict, &'static str)> {
  if policy.deny_systemd_sockets && is_manager_socket(path) {
    Some((Verdict::Deny, "systemd-socket"))
  } else if policy.deny_user_bus && is_user_bus(path) {
    Some((Verdict::Deny, "session-bus"))
  } else if policy.deny_system_bus && is_system_bus(path) {
    Some((Verdict::Deny, "system-bus"))
  } else if policy.deny_deputy_sockets && is_deputy_socket(path) {
    Some((Verdict::Deny, "deputy-socket"))
  } else {
    None
  }
}

/// The system bus path class (P13 E-c). Suffix match covers /run and
/// /var/run installs; kept separate from `is_user_bus` so each deny has
/// its own flag and its own measured trigger.
pub fn is_system_bus(path: &[u8]) -> bool {
  let s = String::from_utf8_lossy(path);
  s.ends_with("/dbus/system_bus_socket")
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sockaddr {
  V4(Ipv4Addr, u16),
  V6(Ipv6Addr, u16),
  Unix(Vec<u8>),
  /// R4: abstract/autobind unix socket — unnameable, always denied.
  Abstract,
  Other(i32),
}

fn sockaddr_eq(a: &Sockaddr, b: &Sockaddr) -> bool {
  a == b
}

impl Sockaddr {
  pub fn detail(&self) -> String {
    match self {
      Sockaddr::V4(ip, port) => format!("{ip}:{port}"),
      Sockaddr::V6(ip, port) => format!("[{ip}]:{port}"),
      Sockaddr::Unix(p) => format!("unix:{}", String::from_utf8_lossy(p)),
      Sockaddr::Abstract => "unix:abstract".to_string(),
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
      // R4 (ninja review): abstract sockets (sun_path[0]==NUL) have no
      // filesystem identity to allowlist — fail closed. Empty paths
      // (autobind/unnamed) likewise.
      if path.is_empty() || path[0] == 0 {
        return Some(Sockaddr::Abstract);
      }
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
      // P13 ninja F2: escape ports (ssh/docker-TCP) to ANY self address,
      // before the exact-pair resolver-stub check below.
      if let Some(reason) = policy.escape_port_denied(&IpAddr::V4(*ip), *port) {
        return (Verdict::Deny, reason);
      }
      if policy.loopback_denied(&IpAddr::V4(*ip), *port) {
        // Reason names the closed relay: resolver-stub (DNS). The old
        // 22/2222/2200 pairs moved to escape_port_denied (F2).
        let reason = if *port == 53 { "resolver-stub" } else { "loopback-ssh" };
        return (Verdict::Deny, reason);
      }
      (evaluate_v4(*ip, policy), "ipv4")
    }
    Sockaddr::V6(ip, port) => {
      if let Some(reason) = policy.escape_port_denied(&IpAddr::V6(*ip), *port) {
        return (Verdict::Deny, reason);
      }
      if policy.loopback_denied(&IpAddr::V6(*ip), *port) {
        let reason = if *port == 53 { "resolver-stub" } else { "loopback-ssh" };
        return (Verdict::Deny, reason);
      }
      (evaluate_v6(*ip, policy), "ipv6")
    }
    Sockaddr::Abstract => (Verdict::Deny, "abstract-socket"),
    Sockaddr::Unix(path) => {
      // P13 ninja F1: a cwd-relative sun_path ("docker.sock" after
      // chdir("/run")) is resolved by the KERNEL against the tracee's
      // cwd — the denylist only ever sees the literal bytes, so every
      // suffix rule misses it. No pid is available here to resolve
      // /proc/<pid>/cwd, and legit unix paths are absolute by
      // convention (XDG_*), so relative fails closed.
      if !path.starts_with(b"/") {
        return (Verdict::Deny, "unix-relative");
      }
      // Literal match first — no I/O, catches direct /run/docker.sock
      // and the "/var/run/..." spellings without touching the fs.
      if let Some(v) = unix_match(path, policy) {
        return v;
      }
      // P13 ninja F1: symlink resolution. A static symlink
      // (`ln -s /run/.../systemd/private /tmp/x`) is closed
      // deterministically by canonicalize; a FLIPPING symlink is
      // caught by F4c-style stability (two reads 2ms apart must agree,
      // else "unix-unstable" deny). Residual — same class as the F4c
      // TCP one: a flip landing between the second read and the
      // kernel's own path walk after CONTINUE, microseconds wide and
      // rate-gated by CONNECT_RATE_PER_SEC. ENOENT twice = path does
      // not exist: the kernel will fail the connect anyway (and b8's
      // absent-socket probe plus docker-CLI up-checks must see
      // FileNotFound, not EPERM — literal match already ran above).
      let first = std::fs::canonicalize(OsStr::from_bytes(path));
      std::thread::sleep(std::time::Duration::from_millis(2));
      let second = std::fs::canonicalize(OsStr::from_bytes(path));
      match (first, second) {
        (Ok(a), Ok(b)) if a == b => {
          let resolved = a.as_os_str().as_bytes();
          unix_match(resolved, policy).unwrap_or((Verdict::Allow, "unix"))
        }
        (Ok(_), Ok(_)) | (Err(_), Ok(_)) | (Ok(_), Err(_)) => (Verdict::Deny, "unix-unstable"),
        (Err(_), Err(_)) => (Verdict::Allow, "unix"),
      }
    }
    Sockaddr::Other(fam) => {
      // P14 F-E: fail closed on families we do not model. AF_NETLINK
      // (name resolution / kernel queries) and AF_ALG (local kernel
      // crypto) are kernel-local — they reach no peer — so they stay
      // allowed; every other family denies by default rather than
      // falling through the way the parser's `Other` arm used to.
      if !policy.deny_unknown_family {
        return (Verdict::Allow, "other-family");
      }
      if *fam == libc::AF_NETLINK || *fam == libc::AF_ALG {
        (Verdict::Allow, "kernel-local-family")
      } else {
        (Verdict::Deny, "unknown-family")
      }
    }
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
  /// so the ProofCertificate's bounds proof can count it. F1: a denied
  /// cross-scope signal lands as `signal_deny` (kill-scope violation).
  pub fn as_spine_row(&self) -> Option<(String, String, &'static str)> {
    if self.verdict == Verdict::Deny {
      let kind =
        if self.reason.starts_with("signal-") { "signal_deny" } else { "broker_deny" };
      Some((
        kind.to_string(),
        format!("{} {} pid={}", self.reason, self.detail, self.pid),
        "deny",
      ))
    } else {
      None
    }
  }
}

pub type BrokerLog = (std::sync::mpsc::SyncSender<BrokerEvent>, Receiver<BrokerEvent>);
/// R8 (ninja review): bounded recorder channel. The F4c backlog shape
/// (2.78M queued denies) showed an unbounded mpsc lets a flipper grow
/// the supervisor RSS until OOM. sync_channel(4096) back-pressures the
/// DECISION loop instead — but the decision loop must never block on
/// logging (a blocked loop stalls the tracee's syscalls), so all sends
/// use try_send and count drops (see BrokerEvent::dropped / log_drop).
/// Deny events are never dropped (they are the evidence); allow events
/// are the first shed under pressure.
pub fn broker_log() -> BrokerLog {
  std::sync::mpsc::sync_channel(4096)
}

/// R8: drop counter, shared by the run loop (increments) and the
/// recorder (drains into a spine row). Lock-free enough: updated only
/// in run(), read by the recorder thread between recvs.
#[derive(Debug, Default)]
pub struct DropCount(pub std::sync::atomic::AtomicU64);

/// R8: verdict-aware logging. Denies are evidence — blocking send
/// (the 4096 buffer drains via the recorder thread; a full buffer
/// means the recorder died, i.e. the session is ending anyway).
/// Allows are shed with try_send + drop counting (the decision loop
/// must never block on logging — a blocked loop stalls tracee
/// syscalls, which is exactly the px-stall shape).
pub fn log_event(log: &std::sync::mpsc::SyncSender<BrokerEvent>, drops: &DropCount, ev: BrokerEvent) {
  if ev.verdict == Verdict::Deny {
    let _ = log.send(ev);
  } else if log.try_send(ev).is_err() {
    drops.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

/// F1: extract the target PID from a signal-syscall notification.
/// kill(pid,sig): args[0]=pid. tkill(tid,sig): args[0]=tid (own
/// thread only — always in-scope). tgkill(tgid,tid,sig): args[1]=tid.
/// pidfd_send_signal(pidfd,sig,...): resolve /proc/self/fd/<pidfd>
/// (of the TRACEE, not us) — unreadable means deny.
fn signal_target_pid(req: &SeccompNotif) -> SignalTarget {
  match req.data.nr as i64 {
    libc::SYS_kill => {
      let pid = req.data.args[0] as i64 as i32;
      SignalTarget::Pid(pid)
    }
    libc::SYS_tkill => SignalTarget::SelfThread,
    libc::SYS_tgkill => {
      let tid = req.data.args[1] as i64 as i32;
      SignalTarget::Tid(tid)
    }
    libc::SYS_pidfd_send_signal => SignalTarget::Pidfd(req.data.args[0] as i32),
    // R1 (ninja review): rt_sigqueueinfo(pid,sig,uinfo) delivers any
    // signal incl. SIGKILL with same-uid creds — same gate as kill.
    // rt_tgsigqueueinfo(tgid,tid,sig,uinfo): gate on the tid like tgkill.
    libc::SYS_rt_sigqueueinfo => SignalTarget::Pid(req.data.args[0] as i64 as i32),
    libc::SYS_rt_tgsigqueueinfo => SignalTarget::Tid(req.data.args[1] as i64 as i32),
    _ => SignalTarget::None,
  }
}

enum SignalTarget {
  Pid(i32),
  Tid(i32),
  Pidfd(i32),
  SelfThread,
  None,
}

/// F1: read /proc/<pid>/cgroup and return the castellan session scope
/// id (`s...` after `castellan.slice/`), or None when the process is
/// not in any session scope / unreadable.
fn session_scope_of(pid: u32) -> Option<String> {
  let cg = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
  for line in cg.lines() {
    if let Some(idx) = line.find("castellan.slice/") {
      let rest = &line[idx + "castellan.slice/".len()..];
      let end = rest.find(['\n', '/', ' ']).unwrap_or(rest.len());
      let scope = rest[..end].trim_end_matches(".scope").to_string();
      if !scope.is_empty() {
        return Some(scope);
      }
    }
  }
  None
}

/// F1: resolve a pidfd (in the TRACEE's fd table) to its target pid
/// via /proc/<tracee>/fdinfo/<fd>. Returns None when unreadable.
fn pidfd_target(tracee: u32, fd: i32) -> Option<u32> {
  let info = std::fs::read_to_string(format!("/proc/{tracee}/fdinfo/{fd}")).ok()?;
  for line in info.lines() {
    if let Some(rest) = line.strip_prefix("Pid:") {
      return rest.trim().parse().ok();
    }
  }
  None
}

/// F1: decide a signal notification. Same-process and same-scope
/// signals are allowed; cross-scope signals are denied with EPERM
/// (mirrors the kernel's own errno for a forbidden signal).
/// Unreadable scope on either side fails closed (deny).
pub fn decide_signal(req: &SeccompNotif) -> (Verdict, &'static str, String) {
  let tracee = req.pid;
  let (target, self_ok): (Option<u32>, bool) = match signal_target_pid(req) {
    SignalTarget::SelfThread => (None, true),
    SignalTarget::Pid(pid) => {
      if pid <= 0 {
        // kill(0/-pgid): process-group signaling reaches outside any
        // scope by construction — deny (agents have no legitimate
        // use; shells use job control on their own pgrp, which is
        // inside the scope... except kill(0) reaches the whole pgrp
        // including the supervisor. Deny all non-positive pids).
        return (Verdict::Deny, "signal-pgrp", format!("pid={pid}"));
      }
      (Some(pid as u32), pid as u32 == tracee)
    }
    SignalTarget::Tid(tid) => {
      // tgkill to own tid (thread self-signal, e.g. abort paths).
      // Cross-thread tgkill within the same process is decided by
      // process scope below; resolve tid -> tgid via /proc.
      if tid <= 0 {
        return (Verdict::Deny, "signal-pgrp", format!("tid={tid}"));
      }
      let tgid = std::fs::read_to_string(format!("/proc/{tid}/stat"))
        .ok()
        .and_then(|st| st.rsplit_once(')').map(|(_, r)| r.to_string()))
        .and_then(|r| r.split_whitespace().nth(1).map(String::from))
        .and_then(|s| s.parse::<u32>().ok());
      match tgid {
        Some(g) if g == tracee => (None, true),
        Some(g) => (Some(g), false),
        None => return (Verdict::Deny, "signal-unreadable", format!("tid={tid}")),
      }
    }
    SignalTarget::Pidfd(fd) => match pidfd_target(tracee, fd) {
      Some(p) => (Some(p), p == tracee),
      None => return (Verdict::Deny, "signal-unreadable", format!("pidfd={fd}")),
    },
    // P20/F8: fail-closed default. None means the notification carried a
    // syscall this matcher does not know — a filter/table mismatch (the
    // "guard does not guard" class). Unknown must deny, not allow.
    SignalTarget::None => return (Verdict::Deny, "signal-unknown-nr", String::new()),
  };
  if self_ok {
    return (Verdict::Allow, "signal-self", String::new());
  }
  let target = match target {
    Some(t) => t,
    None => return (Verdict::Allow, "signal-self", String::new()),
  };
  match (session_scope_of(tracee), session_scope_of(target)) {
    (Some(a), Some(b)) if a == b => {
      (Verdict::Allow, "signal-same-scope", format!("{tracee}->{target} [{a}]"))
    }
    (a, b) => (
      Verdict::Deny,
      "signal-cross-scope",
      format!("{tracee}->{target} [{:?}->{:?}]", a.unwrap_or_default(), b.unwrap_or_default()),
    ),
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
/// F4/R2: max sendmmsg batch elements examined per decision. Past
/// this the batch is Unreadable (fail-closed under restriction).
pub const MAX_SENDMMSG_ELEMS: usize = 16;

pub enum DestRead {
  Parsed(Sockaddr),
  /// F4/R2: sendmmsg batch — per-element explicit dest (None element =
  /// implicit/connected). decide_dest denies the batch if ANY explicit
  /// element denies or is unreadable-at-element.
  Batch(Vec<Option<Sockaddr>>),
  /// F4c: the destination was read STABLY (same bytes across spaced
  /// re-reads) — the anti-flipper agreement signal. decide_dest treats
  /// it like Parsed; the distinction is recorded in the spine reason
  /// ("stable-ipv4" vs "ipv4") so a future audit can tell a stable
  /// decision from a single-read one.
  Stable(Sockaddr),
  /// F4c: the destination FLIPPED between spaced re-reads — a live
  /// race in progress. Always denied ("dest-unstable"), counts on the
  /// spine, and feeds the per-pid rate limiter below.
  Unstable,
  /// The syscall carries no destination (sendto on an already-connected
  /// socket, or a connect form we do not parse) — vetted at connect time.
  None,
  /// The destination was not readable from the tracee.
  Unreadable,
}

pub fn read_dest(req: &SeccompNotif) -> DestRead {
  read_dest_stable(req, false)
}

/// F4c: stability-checked destination read. When `check` is true (the
/// CONNECT path — new destinations are the race target), the sockaddr
/// bytes are read, the thread sleeps 2ms, and the bytes are read again:
/// agreement yields Stable, disagreement yields Unstable (always
/// denied). A full-speed flipper mutates every ~100ns, so two reads
/// 2ms apart never agree — its connects all die as dest-unstable while
/// legit agents (stable sockaddrs) pay 2ms per connect. UDP/sendmsg
/// explicit-dest paths keep single-read (unchecked) — see the F4c note
/// in decide_dest for why the residual there is accepted.
pub fn read_dest_stable(req: &SeccompNotif, check: bool) -> DestRead {
  let nr = req.data.nr as i64;
  let read = |ptr: u64, len: u64| read_tracee(req.pid, ptr, len as usize);
  match nr {
    libc::SYS_connect => {
      let (ptr, len) = (req.data.args[1], req.data.args[2]);
      match read(ptr, len) {
        Some(first) => {
          if !check {
            return match parse_sockaddr(&first) {
              Some(sa) => DestRead::Parsed(sa),
              None => DestRead::Unreadable,
            };
          }
          std::thread::sleep(std::time::Duration::from_millis(2));
          match read(ptr, len) {
            Some(second) if second == first => match parse_sockaddr(&first) {
              Some(sa) => DestRead::Stable(sa),
              None => DestRead::Unreadable,
            },
            _ => DestRead::Unstable,
          }
        }
        None => DestRead::Unreadable,
      }
    }
    libc::SYS_sendto => {
      // sendto(fd, buf, len, flags, dest_addr, addrlen). glibc implements
      // send() as sendto with a NULL destination on a connected socket,
      // so a NULL here is the normal implicit case, not a failure.
      if req.data.args[4] == 0 {
        return DestRead::None;
      }
      // R3 (ninja review): explicit-dest sends are the UDP-exfil race
      // surface (no prior connect to gate). Stability-check like connect.
      match read(req.data.args[4], req.data.args[5]) {
        Some(first) => {
          if !check {
            return match parse_sockaddr(&first) {
              Some(sa) => DestRead::Parsed(sa),
              None => DestRead::Unreadable,
            };
          }
          std::thread::sleep(std::time::Duration::from_millis(2));
          match read(req.data.args[4], req.data.args[5]) {
            Some(second) if second == first => match parse_sockaddr(&first) {
              Some(sa) => DestRead::Stable(sa),
              None => DestRead::Unreadable,
            },
            _ => DestRead::Unstable,
          }
        }
        None => DestRead::Unreadable,
      }
    }
    libc::SYS_sendmsg => {
      // R3: same stability treatment when checked and a name is present.
      // read_msghdr_dest has no check param; wrap: single-read first,
      // and on explicit-dest + check, re-read the name bytes for agreement.
      match read_msghdr_dest(&read, req.data.args[1]) {
        DestRead::Parsed(sa) if check => {
          std::thread::sleep(std::time::Duration::from_millis(2));
          match read_msghdr_dest(&read, req.data.args[1]) {
            DestRead::Parsed(sa2) if sockaddr_eq(&sa, &sa2) => DestRead::Stable(sa),
            DestRead::Stable(sa2) if sockaddr_eq(&sa, &sa2) => DestRead::Stable(sa),
            _ => DestRead::Unstable,
          }
        }
        other => other,
      }
    }
    // F4/R2: sendmmsg(fd, msgvec, vlen, flags): msgvec is an array
    // of mmsg_hdr { struct msghdr msg_hdr; unsigned int msg_len }
    // (32 bytes on x86_64). R2 (ninja review): first-element-decides
    // is fail-OPEN for tails — [allowed, denied] delivers element 1.
    // Read ALL elements (cap below) and deny the batch if ANY element
    // is denied or unreadable. Fail-closed, atomic-deny shape.
    libc::SYS_sendmmsg => {
      let vlen = (req.data.args[2] as usize).min(MAX_SENDMMSG_ELEMS + 1);
      if vlen == 0 {
        return DestRead::Unreadable;
      }
      if vlen > MAX_SENDMMSG_ELEMS {
        // Absurd batch: fail closed under restriction rather than
        // paying an unbounded read loop in the decision path.
        return DestRead::Unreadable;
      }
      let raw = match read(req.data.args[1], (vlen * 32) as u64) {
        Some(h) if h.len() >= vlen * 32 => h,
        _ => return DestRead::Unreadable,
      };
      let mut elems: Vec<Option<Sockaddr>> = Vec::with_capacity(vlen);
      for i in 0..vlen {
        let msg_ptr = u64::from_ne_bytes(raw[i * 32..i * 32 + 8].try_into().unwrap());
        if msg_ptr == 0 {
          return DestRead::Unreadable;
        }
        match read_msghdr_dest(&read, msg_ptr) {
          DestRead::None => elems.push(None),
          DestRead::Parsed(sa) => elems.push(Some(sa)),
          _ => return DestRead::Unreadable,
        }
      }
      DestRead::Batch(elems)
    }
    // F4: recvmmsg has no destination (receive side) — vetted at bind/
    // connect time like any receive. Explicit arm (not silent fallthrough).
    libc::SYS_recvmmsg => DestRead::None,
    _ => DestRead::None,
  }
}

fn read_msghdr_dest(read: &dyn Fn(u64, u64) -> Option<Vec<u8>>, msg_ptr: u64) -> DestRead {
  // sendmsg(fd, msg, flags): msghdr.msg_name at offset 0,
  // msg_namelen at offset 8 on x86_64.
  let hdr = match read(msg_ptr, 16) {
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

pub fn decide_dest(
  dest: &DestRead,
  policy: &EgressPolicy,
) -> (Verdict, &'static str, String) {
  match dest {
    DestRead::Parsed(sa) => {
      let (v, r) = decide(sa, policy);
      (v, r, sa.detail())
    }
    DestRead::Stable(sa) => {
      let (v, r) = decide(sa, policy);
      // stable- prefix marks the anti-flipper agreement path on the spine.
      let reason: &'static str = match r {
        "ipv4" => "stable-ipv4",
        "ipv6" => "stable-ipv6",
        "resolver-stub" => "resolver-stub",
        other => other,
      };
      (v, reason, sa.detail())
    }
    // F4c: a flipping destination is a live race. Deny always, count
    // loudly. Note the accepted residual: single-read UDP/sendmsg
    // explicit-dest paths can still race (same CONTINUE shape), but
    // winning requires the flipper to also beat the CONNECT gate first
    // for TCP (every TCP send needs a connected socket, and connects
    // are stability-gated) — UDP exfil to a denied IP via a raced
    // sendto remains the residual. It is rate-limited below.
    DestRead::Unstable => (Verdict::Deny, "dest-unstable", String::new()),
    DestRead::Batch(elems) => {
      let mut saw_explicit = false;
      for (i, el) in elems.iter().enumerate() {
        match el {
          None => {}
          Some(sa) => {
            saw_explicit = true;
            let (v, r) = decide(sa, policy);
            if v == Verdict::Deny {
              return (Verdict::Deny, "batch-denied", format!("elem{i}:{r} {}", sa.detail()));
            }
          }
        }
      }
      if saw_explicit {
        let first = elems.iter().flatten().next().unwrap();
        let (v, r) = decide(first, policy);
        (v, r, first.detail())
      } else {
        (Verdict::Allow, "implicit-dest", String::new())
      }
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
  if std::env::var("CASTELLAN_BROKER_DEBUG").is_ok() {
    eprintln!("castellan-broker: send_response id={id} error={error} flags={flags} rc={rc}");
  }
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
  // Allow: CONTINUE. The kernel re-reads pointer arguments (sockaddr)
  // from tracee memory at execution — a racing thread CAN redirect a
  // checked-allowed connect to a denied destination (F4 round 4: 216,766
  // denied-connect wins in 20s at 90% denied bias, getpeername-proven).
  // flags=0 is NOT a fix: without CONTINUE the kernel skips execution
  // and returns resp.val (0) — every allowed syscall fake-succeeds
  // without executing (connect "succeeds" unconnected, sendto returns 0
  // forever; proven live, reverted same session). There is no third
  // response mode. CONTINUE is mandatory for a working broker; the race
  // is closed instead by STABILITY (multi-read agreement, below) and
  // RATE (per-pid connect cap) — a flipper needs volume + instability,
  // both of which are now the tripwire.
  send_response(listener, req.id, 0, SECCOMP_USER_NOTIF_FLAG_CONTINUE)
}

/// Install the notification filter on the current process and return
/// the listener fd. The filter intercepts connect/sendto/sendmsg (F1:
/// also kill/tkill/tgkill/pidfd_send_signal); everything else falls
/// through to ALLOW.
///
/// Callers use `spawn_broker`, which installs this in the SUPERVISOR
/// and forks the agent — the filter is inherited across fork/exec, so
/// no fd handoff is needed. (A handoff via SCM_RIGHTS deadlocks: the
/// handoff's own sendmsg is intercepted before the supervisor has the
/// listener. Found live, 2026-09-05.)
/// The seccomp program installed by `install_listener`, extracted for
/// unit tests (P13 ninja F3: the arch/x32 gates need layout assertions
/// and a mini-interpreter test — those must not require seccomp perms).
///
/// Layout (indices are load-bearing; jt/jf in the jump table are
/// position-relative, so the table's offsets did NOT change when the
/// gate was prepended — only the gate's own offsets are new):
///
/// ```text
/// 0  LD  [4]                    arch
/// 1  JEQ AUDIT_ARCH_NATIVE jt=1 jf=0   native → 3, foreign → 2
/// 2  RET KILL_PROCESS           foreign arch: i386 nrs mean other syscalls
/// 3  LD  [0]                    nr
/// 4  JGT X32_NR_BOUND jt=0 jf=1 x32 (bit 30) → 5, native → 6
/// 5  RET KILL_PROCESS           x32: 0x4000002a never equals SYS_connect
/// 6.. jump table (jt 10..0 → RET NOTIF; fall → RET ALLOW)
/// ```
///
/// Without the gate a compat tracee falls through every JEQ (its
/// syscall numbers are the i386 table) and reaches RET ALLOW — the
/// entire broker bypassed, closing not just egress but also the F1
/// signal-scope trap. KILL_PROCESS on mismatch is the libseccomp
/// standard: the process cannot be decided, so it does not run.
pub fn broker_program() -> Vec<libc::sock_filter> {
  vec![
    // P13 ninja F3: arch gate. seccomp_data.arch is at offset 4.
    bpf(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 4),
    bpf(
      libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
      1,
      0,
      AUDIT_ARCH_NATIVE,
    ),
    bpf(libc::BPF_RET | libc::BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
    // x32 gate: bit-30-set nrs report the native arch but never match
    // a plain SYS_* below.
    bpf(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
    bpf(
      libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K,
      0,
      1,
      X32_NR_BOUND,
    ),
    bpf(libc::BPF_RET | libc::BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
    // Jump table: connect/sendto/sendmsg/sendmmsg/recvmmsg/connect-time + F1 signals -> NOTIF, else -> ALLOW.
    // F4 (2026-09-27, .227 breakout round 4): sendmmsg/recvmmsg bypassed
    // the broker entirely — one sendmmsg carried an allowed loopback AND
    // a denied-public datagram past the filter untouched (proven live:
    // ret=2, both delivered). They share sendmsg's mmsghdr shape, so
    // read_dest handles them through the same path (args[1]=msgvec,
    // args[2]=vlen; first-element dest decides, fail-closed on
    // unreadable — a mixed batch with ANY denied dest is denied).
    bpf(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 10, 0, libc::SYS_connect as u32),
    bpf(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 9, 0, libc::SYS_sendto as u32),
    bpf(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 8, 0, libc::SYS_sendmsg as u32),
    bpf(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 7, 0, libc::SYS_sendmmsg as u32),
    bpf(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 6, 0, libc::SYS_recvmmsg as u32),
    bpf(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 5, 0, libc::SYS_kill as u32),
    bpf(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 4, 0, libc::SYS_tkill as u32),
    bpf(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 3, 0, libc::SYS_tgkill as u32),
    bpf(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 2, 0, libc::SYS_pidfd_send_signal as u32),
    bpf(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 1, 0, libc::SYS_rt_sigqueueinfo as u32),
    bpf(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 1, libc::SYS_rt_tgsigqueueinfo as u32),
    bpf(libc::BPF_RET | libc::BPF_K, 0, 0, SECCOMP_RET_USER_NOTIF),
    bpf(libc::BPF_RET | libc::BPF_K, 0, 0, SECCOMP_RET_ALLOW),
  ]
}

pub fn install_listener() -> io::Result<RawFd> {
  let prog = broker_program();
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
  /// F4c: per-pid notification rate gate. A flipper needs volume
  /// (~100k notifies/sec at full speed); legit agents connect rarely
  /// (an LLM API call is one reused connection). (pid -> (window_start,
  /// count, throttled_until)). Checked on every notification; a hot pid
  /// gets all its connects denied until it cools down.
  notify_rate: std::collections::HashMap<u32, (std::time::Instant, u32, Option<std::time::Instant>)>,
  /// F4c round 2: per-pid unstable-read cluster gate.
  /// (pid -> (window_start, unstable_count, throttled_until)).
  unstable_rate: std::collections::HashMap<u32, (std::time::Instant, u32, Option<std::time::Instant>)>,
}

/// F4c: max CONNECT-class notifications per pid per second before the
/// pid is throttled (all its connects denied for the cooldown). Normal
/// agents: single digits/sec (an LLM API call is one reused connection;
/// even aypytest burst stays <50/sec). The F4 flipper: ~100k/sec. The
/// gap is three orders of magnitude; 200/sec trips no legitimate
/// workload we have ever measured and bites flippers 5x sooner.
pub const CONNECT_RATE_PER_SEC: u32 = 200;
/// F4c: throttle duration once tripped.
pub const CONNECT_THROTTLE_SECS: u64 = 10;
/// F4c round 2: unstable-cluster gate. Legit agents generate ZERO
/// unstable reads (a stable sockaddr agrees with itself across 2ms).
/// ANY unstable read is racer-signature (or a genuine memory race).
/// N unstable reads within the window throttles the pid for the long
/// cooldown — a full-speed flipper trips this in under a millisecond;
/// a slow flipper must keep flips rarer than ~1 per window-quota to
/// stay under, which bounds its win rate (see the F4c gate numbers).
pub const UNSTABLE_WINDOW_SECS: u64 = 5;
pub const UNSTABLE_MAX_PER_WINDOW: u32 = 10;
pub const UNSTABLE_THROTTLE_SECS: u64 = 60;

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
  let mut sup = Broker {
    listener,
    agent_pid: pid,
    agent_status: None,
    notify_rate: std::collections::HashMap::new(),
    unstable_rate: std::collections::HashMap::new(),
  };
  let (btx, _brx) = broker_log();
  let drops = DropCount::default();
  let _ = sup.run(&mut policy, &btx, &drops);
  if drops.0.load(std::sync::atomic::Ordering::Relaxed) > 0 {
    eprintln!(
      "broker: shed {} allow-events under pressure",
      drops.0.load(std::sync::atomic::Ordering::Relaxed)
    );
  }
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
  pub fn run(
    &mut self,
    policy: &mut EgressPolicy,
    log: &std::sync::mpsc::SyncSender<BrokerEvent>,
    drops: &DropCount,
  ) -> io::Result<u64> {
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
      let nr = req.data.nr as i64;
      // F4c: rate gate (connect-class only — sends are too frequent in
      // legitimate TLS stacks to cap).
      if nr == libc::SYS_connect {
        let now = std::time::Instant::now();
        let e = self.notify_rate.entry(req.pid).or_insert((now, 0, None));
        if let Some(until) = e.2 {
          if now < until {
            log_event(log, drops, BrokerEvent {
              pid: req.pid,
              verdict: Verdict::Deny,
              reason: "connect-throttled",
              detail: String::new(),
            });
            respond(self.listener, &req, Verdict::Deny)?;
            continue;
          }
          e.2 = None;
          e.0 = now;
          e.1 = 0;
        }
        if now.duration_since(e.0).as_secs() >= 1 {
          e.0 = now;
          e.1 = 0;
        }
        e.1 += 1;
        if e.1 > CONNECT_RATE_PER_SEC {
          e.2 = Some(now + std::time::Duration::from_secs(CONNECT_THROTTLE_SECS));
          log_event(log, drops, BrokerEvent {
            pid: req.pid,
            verdict: Verdict::Deny,
            reason: "connect-flood",
            detail: format!("{} connects/sec", e.1),
          });
          respond(self.listener, &req, Verdict::Deny)?;
          continue;
        }
      }
      if std::env::var("CASTELLAN_BROKER_DEBUG").is_ok() {
        eprintln!("castellan-broker: notif nr={nr} pid={} args={:?}", req.pid, req.data.args);
      }
      // F1: signal syscalls are decided by PID scope, not destination.
      if nr == libc::SYS_kill
        || nr == libc::SYS_tkill
        || nr == libc::SYS_tgkill
        || nr == libc::SYS_pidfd_send_signal
        || nr == libc::SYS_rt_sigqueueinfo
        || nr == libc::SYS_rt_tgsigqueueinfo
      {
        let (verdict, reason, detail) = decide_signal(&req);
        log_event(log, drops, BrokerEvent { pid: req.pid, verdict, reason, detail });
        respond(self.listener, &req, verdict)?;
        continue;
      }
      // F4c+R3: CONNECT and explicit-dest SENDs take the
      // stability-checked path (new destinations are the race target).
      // Implicit (connected-socket) sends return before any sleep, so
      // the common TLS-send path pays nothing. recvmmsg/kill-class keep
      // the single-read path.
      let dest = if nr == libc::SYS_connect
        || nr == libc::SYS_sendto
        || nr == libc::SYS_sendmsg
        || nr == libc::SYS_sendmmsg
      {
        read_dest_stable(&req, true)
      } else {
        read_dest(&req)
      };
      // F4c round 2: unstable-cluster throttle. Any Unstable outcome
      // feeds the per-pid cluster gate; a hot cluster denies (already
      // denied by decide_dest — this extends the denial to ALL of the
      // pid's connects for the long cooldown).
      if nr == libc::SYS_connect && matches!(dest, DestRead::Unstable) {
        let now = std::time::Instant::now();
        let e = self.unstable_rate.entry(req.pid).or_insert((now, 0, None));
        if let Some(until) = e.2 {
          if now < until {
            log_event(log, drops, BrokerEvent {
              pid: req.pid,
              verdict: Verdict::Deny,
              reason: "unstable-throttled",
              detail: String::new(),
            });
          } else {
            e.2 = None;
            e.0 = now;
            e.1 = 0;
          }
        }
        if e.2.is_none() {
          if now.duration_since(e.0).as_secs() >= UNSTABLE_WINDOW_SECS {
            e.0 = now;
            e.1 = 0;
          }
          e.1 += 1;
          if e.1 >= UNSTABLE_MAX_PER_WINDOW {
            e.2 = Some(now + std::time::Duration::from_secs(UNSTABLE_THROTTLE_SECS));
            log_event(log, drops, BrokerEvent {
              pid: req.pid,
              verdict: Verdict::Deny,
              reason: "unstable-flood",
              detail: format!("{} unstable/{}s", e.1, UNSTABLE_WINDOW_SECS),
            });
          }
        }
      }
      // A pid under unstable-throttle gets everything denied even if
      // this particular read was stable (the flipper parks allowed
      // between flips — stable-allowed reads during a throttle window
      // are untrustworthy by construction).
      if nr == libc::SYS_connect {
        if let Some((_, _, Some(until))) = self.unstable_rate.get(&req.pid) {
          if std::time::Instant::now() < *until {
            log_event(log, drops, BrokerEvent {
              pid: req.pid,
              verdict: Verdict::Deny,
              reason: "unstable-throttled",
              detail: String::new(),
            });
            respond(self.listener, &req, Verdict::Deny)?;
            continue;
          }
        }
      }
      let (verdict, reason, detail) = decide_dest(&dest, policy);
      log_event(log, drops, BrokerEvent { pid: req.pid, verdict, reason, detail });
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
  Ok(Spawn::Supervisor(Broker { listener, agent_pid, agent_status: None, notify_rate: std::collections::HashMap::new(), unstable_rate: std::collections::HashMap::new() }))
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
  fn unknown_family_denied_by_default() {
    // P17 battery (live .227 2026-10-03): vsock_create OK, vsock_connect
    // EPERM — the arm below is what carried that verdict; this pin keeps
    // a regression from reopening the P14 F-E hole (pre-81c1a87 any
    // Other(fam) waved through).
    let p = EgressPolicy::new();
    assert_eq!(decide(&Sockaddr::Other(40), &p).0, Verdict::Deny); // AF_VSOCK
    assert_eq!(decide(&Sockaddr::Other(31), &p).0, Verdict::Deny); // AF_BLUETOOTH
    assert_eq!(decide(&Sockaddr::Other(2), &p).0, Verdict::Deny); // AF_AX25 junk
  }

  #[test]
  fn kernel_local_families_allowed() {
    // AF_NETLINK carries getifaddrs/getaddrinfo route queries; AF_ALG is
    // local crypto. Both reach no peer — denying them breaks name
    // resolution (measured OK in the same battery: netlink_getifaddrs).
    let p = EgressPolicy::new();
    let (v, r) = decide(&Sockaddr::Other(libc::AF_NETLINK), &p);
    assert_eq!((v, r), (Verdict::Allow, "kernel-local-family"));
    let (v, r) = decide(&Sockaddr::Other(libc::AF_ALG), &p);
    assert_eq!((v, r), (Verdict::Allow, "kernel-local-family"));
  }

  #[test]
  fn audit_policy_waves_unknown_families() {
    // Audit posture observes without gating (the banner's contract).
    let p = EgressPolicy::audit();
    assert_eq!(decide(&Sockaddr::Other(40), &p).0, Verdict::Allow);
  }

  #[test]
  fn llm_only_denies_loopback_ssh() {
    // HN ssh-localhost escape (2026-09-30): `ssh localhost <cmd>` runs
    // the command in an sshd child outside all three layers. The client
    // connect must die at the broker. Audit posture leaves ssh alone.
    let p = EgressPolicy::new().with_llm_only(&[]);
    for port in [22u16, 2222, 2200] {
      let sa = Sockaddr::V4(Ipv4Addr::new(127, 0, 0, 1), port);
      let (v, reason) = decide(&sa, &p);
      assert_eq!(v, Verdict::Deny, "127.0.0.1:{port} must deny");
      assert_eq!(reason, "loopback-ssh");
      let sa = Sockaddr::V6(Ipv6Addr::LOCALHOST, port);
      assert_eq!(decide(&sa, &p).0, Verdict::Deny, "[::1]:{port} must deny");
    }
    // Non-ssh loopback (honeypot, discard port) still allowed.
    let sa = Sockaddr::V4(Ipv4Addr::new(127, 0, 0, 1), 9);
    assert_eq!(decide(&sa, &p).0, Verdict::Allow);
    let sa = Sockaddr::V4(Ipv4Addr::new(127, 0, 0, 1), 44407);
    assert_eq!(decide(&sa, &p).0, Verdict::Allow);
  }

  #[test]
  fn loopback_ssh_denied_by_default() {
    // P13 E-a (probed live 2026-09-30): the first fix scoped the deny
    // to with_llm_only, so the default --enforce posture still
    // connected to 127.0.0.1:22. Escape channels deny by default now
    // (systemd-socket precedent); egress policy is a separate axis.
    let p = EgressPolicy::new();
    let sa = Sockaddr::V4(Ipv4Addr::new(127, 0, 0, 1), 22);
    assert_eq!(decide(&sa, &p).0, Verdict::Deny);
    let sa = Sockaddr::V6(Ipv6Addr::LOCALHOST, 22);
    assert_eq!(decide(&sa, &p).0, Verdict::Deny);
    // Non-ssh loopback is untouched (the deny is port-scoped).
    let sa = Sockaddr::V4(Ipv4Addr::new(127, 0, 0, 1), 9);
    assert_eq!(decide(&sa, &p).0, Verdict::Allow);
  }

  #[test]
  fn escape_ports_cover_all_self_ip_shapes() {
    // P13 ninja F2: exact (ip,port) pairs missed every self spelling
    // but 127.0.0.1/::1 — sshd binds 0.0.0.0 and accepts on all of them.
    let p = EgressPolicy::new();
    for (ip, port) in [
      // the rest of 127.0.0.0/8
      (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 22u16),
      (IpAddr::V4(Ipv4Addr::new(127, 255, 255, 254)), 2200),
      // v4-mapped loopback
      (
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001)),
        22,
      ),
      // unspecified — kernel connect() maps 0.0.0.0/[::] onto loopback
      (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 22),
      (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 2222),
      // docker TCP: same one-shot root contract as docker.sock
      (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 2375),
      (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 2376),
    ] {
      let sa = match ip {
        IpAddr::V4(v4) => Sockaddr::V4(v4, port),
        IpAddr::V6(v6) => Sockaddr::V6(v6, port),
      };
      assert_eq!(decide(&sa, &p).0, Verdict::Deny, "{ip}:{port} must deny");
    }
    // Self via a real local interface address (F2's LAN/dockery hole).
    let self_ip = local_ips().into_iter().find(|ip| !ip.is_loopback());
    if let Some(ip) = self_ip {
      let sa = match ip {
        IpAddr::V4(v4) => Sockaddr::V4(v4, 22),
        IpAddr::V6(v6) => Sockaddr::V6(v6, 22),
      };
      assert_eq!(
        decide(&sa, &p).0,
        Verdict::Deny,
        "ssh to own address {ip} must deny"
      );
    }
    // Remote destinations are ordinary egress (destination policy is a
    // separate axis; default posture allows, restrict_ip denies).
    let sa = Sockaddr::V4(Ipv4Addr::new(8, 8, 8, 8), 22);
    assert_eq!(decide(&sa, &p).0, Verdict::Allow);
    let sa = Sockaddr::V4(Ipv4Addr::new(8, 8, 8, 8), 2375);
    assert_eq!(decide(&sa, &p).0, Verdict::Allow);
    // Turning the flag off restores observation posture.
    let mut audit = EgressPolicy::new();
    audit.deny_escape_ports = false;
    let sa = Sockaddr::V4(Ipv4Addr::new(127, 0, 0, 1), 22);
    assert_eq!(decide(&sa, &audit).0, Verdict::Allow);
  }

  #[test]
  fn local_ips_is_filter_safe_and_nonempty() {
    // P13 ninja F2/F3: new() calls this AFTER install_listener but
    // BEFORE run() — getifaddrs (netlink sendto) would self-deadlock.
    // The impl must only use socket+ioctl+/proc. Non-empty on any
    // normal host (loopback at minimum); the call completing at all
    // inside the test binary is the no-hang evidence at unit level.
    let ips = local_ips();
    assert!(!ips.is_empty(), "local_ips() must at least report loopback");
  }

  #[test]
  fn relative_unix_paths_denied() {
    // P13 ninja F1: `chdir("/run"); connect("docker.sock")` hands the
    // kernel a sun_path with no leading slash — every suffix rule
    // missed it because the literal bytes are "docker.sock".
    let p = EgressPolicy::new();
    for path in [
      &b"docker.sock"[..],
      b"run/systemd/private",
      b"./../run/dbus/system_bus_socket",
    ] {
      let sa = Sockaddr::Unix(path.to_vec());
      let (v, reason) = decide(&sa, &p);
      assert_eq!(v, Verdict::Deny, "{path:?} must deny");
      assert_eq!(reason, "unix-relative");
    }
  }

  #[test]
  fn symlinked_unix_paths_resolve_to_their_target() {
    // P13 ninja F1: static symlink bypass — `ln -s /run/docker.sock
    // /tmp/evil` then connect("/tmp/evil"): the literal bytes match no
    // suffix rule. canonicalize resolves the chain; the resolved path
    // hits the denylist. Target is a real file in a tempdir so the test
    // is host-independent (no docker required).
    let dir = std::env::temp_dir().join(format!("castellan-sym-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let target = dir.join("docker.sock");
    std::fs::write(&target, b"").unwrap();
    let link = dir.join("innocent");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let sa = Sockaddr::Unix(link.to_string_lossy().into_owned().into_bytes());
    let (v, reason) = decide(&sa, &EgressPolicy::new());
    assert_eq!(v, Verdict::Deny, "symlink must resolve to docker.sock");
    assert_eq!(reason, "deputy-socket");
    let _ = std::fs::remove_dir_all(&dir);
  }

  #[test]
  fn absent_unix_path_still_falls_through_to_kernel_errno() {
    // b8's over-block probe and docker-CLI up-checks must see
    // FileNotFound (kernel ENOENT), never EPERM: an ENOENT-twice
    // canonicalize means the path does not exist, so the literal
    // match (already run) is all there is to decide on.
    let p = EgressPolicy::new();
    let path = format!("/tmp/castellan-absent-{}.sock", std::process::id());
    let sa = Sockaddr::Unix(path.into_bytes());
    assert_eq!(decide(&sa, &p).0, Verdict::Allow);
  }

  /// Minimal BPF interpreter for `broker_program()` (P13 ninja F3).
  /// seccomp_data: nr at offset 0, arch at offset 4. Supports the three
  /// opcode classes the program uses: LD|W|ABS, JMP|JEQ|K, JMP|JGT|K,
  /// RET|K. Returns the RET value.
  fn eval_bpf(prog: &[libc::sock_filter], nr: u32, arch: u32) -> u32 {
    let mut a: u32 = 0;
    let mut pc: usize = 0;
    loop {
      let ins = prog[pc];
      let code = ins.code;
      if code == (libc::BPF_RET | libc::BPF_K) as u16 {
        return ins.k;
      } else if code == (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16 {
        a = match ins.k {
          0 => nr,
          4 => arch,
          other => panic!("unexpected load offset {other}"),
        };
        pc += 1;
      } else if code == (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16 {
        pc += if a == ins.k { 1 + ins.jt as usize } else { 1 + ins.jf as usize };
      } else if code == (libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K) as u16 {
        pc += if a > ins.k { 1 + ins.jt as usize } else { 1 + ins.jf as usize };
      } else {
        panic!("unsupported opcode {code:#x} at pc {pc}");
      }
    }
  }

  #[test]
  fn broker_program_arch_and_x32_gates() {
    // P13 ninja F3: without the gates a compat tracee (i386 nr table)
    // matches no JEQ and falls through to ALLOW — the whole broker
    // (egress + unix denylist + F1 signal scope) bypassed. x32 reports
    // the native arch but sets bit 30 on nrs, so it needs the JGT too.
    let prog = broker_program();
    let native = AUDIT_ARCH_NATIVE;
    #[cfg(target_arch = "x86_64")]
    let compat = 0x4000_0003u32; // AUDIT_ARCH_I386
    #[cfg(target_arch = "aarch64")]
    let compat = 0x4000_0001u32; // AUDIT_ARCH_ARM
    // Native, connect → NOTIF (the broker's whole job).
    assert_eq!(
      eval_bpf(&prog, libc::SYS_connect as u32, native),
      SECCOMP_RET_USER_NOTIF
    );
    // Native, a signal the scope gate owns → NOTIF.
    assert_eq!(
      eval_bpf(&prog, libc::SYS_tgkill as u32, native),
      SECCOMP_RET_USER_NOTIF
    );
    // Native, an unrelated syscall (write) → ALLOW.
    assert_eq!(eval_bpf(&prog, libc::SYS_write as u32, native), SECCOMP_RET_ALLOW);
    // Foreign arch, even with a native-looking nr → KILL, never ALLOW.
    assert_eq!(eval_bpf(&prog, libc::SYS_connect as u32, compat), SECCOMP_RET_KILL_PROCESS);
    // x32: native arch, bit-30 nr → KILL (it would otherwise fall to ALLOW).
    assert_eq!(
      eval_bpf(&prog, (libc::SYS_connect as u32) | 0x4000_0000, native),
      SECCOMP_RET_KILL_PROCESS
    );
    // Layout sanity: gates precede the table, RET NOTIF before RET ALLOW.
    assert_eq!(prog[0].k, 4, "first load is seccomp_data.arch");
    assert_eq!(prog[3].k, 0, "second load is seccomp_data.nr");
  }

  #[test]
  fn system_bus_denied_by_default() {
    // P13 E-c (probed 2026-09-30): world-rw socket, matched neither
    // prior predicate, pkcheck rc=0 for udisks2 loop-setup + mount.
    let p = EgressPolicy::new();
    for path in [
      &b"/run/dbus/system_bus_socket"[..],
      b"/var/run/dbus/system_bus_socket",
    ] {
      assert_eq!(
        decide(&Sockaddr::Unix(path.to_vec()), &p).0,
        Verdict::Deny,
        "{path:?} must deny"
      );
    }
    // The opt-out exists (audit posture), same as the other unix denies.
    let mut audit = EgressPolicy::new();
    audit.deny_system_bus = false;
    let sa = Sockaddr::Unix(b"/run/dbus/system_bus_socket".to_vec());
    assert_eq!(decide(&sa, &audit).0, Verdict::Allow);
  }

  #[test]
  fn deputy_sockets_denied_by_default() {
    // P13 E-b (probed live 2026-09-30): docker.sock CONNECTED from an
    // enforced session — one-shot root via container bind-mount.
    // P13 F10: /tmp/.X11-unix/X0 CONNECTED + cookie readable — seat
    // input/screen via XTEST/XGetImage (pre-registered deny trigger).
    let p = EgressPolicy::new();
    for path in [
      &b"/run/docker.sock"[..],
      b"/var/run/docker.sock",
      b"/run/podman/podman.sock",
      b"/var/lib/libvirt/libvirt-sock",
      b"/run/containerd/containerd.sock",
      b"/tmp/.X11-unix/X0",
      b"/tmp/.X11-unix/X1",
    ] {
      assert_eq!(
        decide(&Sockaddr::Unix(path.to_vec()), &p).0,
        Verdict::Deny,
        "{path:?} must deny"
      );
    }
    // Benign desktop sockets must survive (wayland/pipewire/bus-adjacent).
    for path in [
      &b"/run/user/1000/wayland-0"[..],
      b"/run/user/1000/pipewire-0",
      b"/run/user/1000/gnupg/S.gpg-agent",
    ] {
      assert_eq!(
        decide(&Sockaddr::Unix(path.to_vec()), &p).0,
        Verdict::Allow,
        "{path:?} must allow"
      );
    }
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
  fn unknown_socket_family_denied_by_default() {
    // P14 F-E (probed live 2026-10-01): AF_VSOCK/AF_SMC sockets opened
    // inside a session and decide()'s Other arm returned Allow — the one
    // fail-open arm in the policy. Now unknown families deny; the two
    // kernel-local families stay allowed (a connect on them reaches no
    // peer, and AF_NETLINK is used by name resolution).
    let p = EgressPolicy::new();
    // Linux AF_* numbers (libc does not export AF_VSOCK/AF_SMC on gnu).
    const AF_VSOCK: i32 = 40;
    const AF_SMC: i32 = 43;
    const AF_PACKET: i32 = 17;
    const AF_NETLINK: i32 = 16;
    const AF_ALG: i32 = 38;
    assert_eq!(decide(&Sockaddr::Other(AF_VSOCK), &p).0, Verdict::Deny);
    assert_eq!(decide(&Sockaddr::Other(AF_SMC), &p).0, Verdict::Deny);
    assert_eq!(decide(&Sockaddr::Other(AF_PACKET), &p).0, Verdict::Deny);
    assert_eq!(decide(&Sockaddr::Other(AF_NETLINK), &p).0, Verdict::Allow);
    assert_eq!(decide(&Sockaddr::Other(AF_ALG), &p).0, Verdict::Allow);
    // Audit posture restores the old blanket-allow (banner honesty).
    let a = EgressPolicy::audit();
    assert_eq!(decide(&Sockaddr::Other(AF_VSOCK), &a).0, Verdict::Allow);
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

  #[test]
  fn signal_pgrp_denied() {
    let req = SeccompNotif {
      id: 0,
      pid: 100,
      flags: 0,
      data: SeccompData { nr: libc::SYS_kill as i32, arch: 0, instruction_pointer: 0, args: [0, 0, 0, 0, 0, 0] },
    };
    assert_eq!(decide_signal(&req).0, Verdict::Deny);
  }

  #[test]
  fn signal_unknown_nr_denied() {
    // P20/F8: a syscall number the matcher does not know (filter/table
    // mismatch reaching decide_signal) must deny, never allow.
    let req = SeccompNotif {
      id: 0,
      pid: 100,
      flags: 0,
      data: SeccompData { nr: 424_242, arch: 0, instruction_pointer: 0, args: [0, 0, 0, 0, 0, 0] },
    };
    let (v, r, _) = decide_signal(&req);
    assert_eq!(v, Verdict::Deny);
    assert_eq!(r, "signal-unknown-nr");
  }

  #[test]
  fn abstract_socket_denied() {
    // R4: abstract (leading NUL) and empty unix paths deny.
    let p = EgressPolicy::new();
    let buf = vec![1u8, 0, 0, b'x'];
    match parse_sockaddr(&buf).unwrap() {
      Sockaddr::Abstract => {}
      other => panic!("expected Abstract, got {other:?}"),
    }
    let (v, r, _) = decide_dest(&DestRead::Parsed(Sockaddr::Abstract), &p);
    assert_eq!(v, Verdict::Deny);
    assert_eq!(r, "abstract-socket");
  }

  #[test]
  fn batch_any_denied_denies() {
    // R2: [allowed, denied] and [denied, allowed] both deny.
    use std::net::IpAddr;
    let p = EgressPolicy { restrict_ip: true, ..EgressPolicy::new() };
    let lo = Sockaddr::V4(Ipv4Addr::new(127, 0, 0, 1), 9);
    let pub1 = Sockaddr::V4(Ipv4Addr::new(8, 8, 8, 8), 53);
    let (v, r, _) = decide_dest(&DestRead::Batch(vec![Some(lo.clone()), Some(pub1.clone())]), &p);
    assert_eq!(v, Verdict::Deny);
    assert_eq!(r, "batch-denied");
    let (v, _, _) = decide_dest(&DestRead::Batch(vec![Some(pub1), Some(lo.clone())]), &p);
    assert_eq!(v, Verdict::Deny);
    let (v, _, _) = decide_dest(&DestRead::Batch(vec![Some(lo.clone()), Some(lo)]), &p);
    assert_eq!(v, Verdict::Allow);
    let (v, r, _) = decide_dest(&DestRead::Batch(vec![]), &p);
    assert_eq!(v, Verdict::Allow);
    assert_eq!(r, "implicit-dest");
    let _ = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
  }

  #[test]
  fn signal_cookie_pair_gated() {
    // R1: rt_sigqueueinfo routes to Pid, rt_tgsigqueueinfo to Tid.
    let req = SeccompNotif {
      id: 0, pid: 100, flags: 0,
      data: SeccompData { nr: libc::SYS_rt_sigqueueinfo as i32, arch: 0, instruction_pointer: 0, args: [0, 0, 0, 0, 0, 0] },
    };
    // pid 0 = pgrp signaling -> deny
    assert_eq!(decide_signal(&req).0, Verdict::Deny);
    let req2 = SeccompNotif {
      id: 0, pid: 100, flags: 0,
      data: SeccompData { nr: libc::SYS_rt_tgsigqueueinfo as i32, arch: 0, instruction_pointer: 0, args: [0, 0, 0, 0, 0, 0] },
    };
    assert_eq!(decide_signal(&req2).0, Verdict::Deny);
  }

  #[test]
  fn signal_self_allowed_without_proc() {
    // tkill is always own-thread: allowed even when /proc is odd.
    let req = SeccompNotif {
      id: 0,
      pid: 1,
      flags: 0,
      data: SeccompData { nr: libc::SYS_tkill as i32, arch: 0, instruction_pointer: 0, args: [0, 0, 0, 0, 0, 0] },
    };
    assert_eq!(decide_signal(&req).0, Verdict::Allow);
  }

  #[test]
  fn stable_and_unstable_decisions() {
    // F4c: stability outcomes decide correctly.
    let p = EgressPolicy { restrict_ip: true, ..EgressPolicy::new() };
    let (v, r, _) = decide_dest(&DestRead::Stable(Sockaddr::V4(Ipv4Addr::new(127, 0, 0, 1), 9)), &p);
    assert_eq!(v, Verdict::Allow);
    assert_eq!(r, "stable-ipv4");
    let (v, _, _) = decide_dest(&DestRead::Stable(Sockaddr::V4(Ipv4Addr::new(8, 8, 8, 8), 53)), &p);
    assert_eq!(v, Verdict::Deny);
    let (v, r, _) = decide_dest(&DestRead::Unstable, &p);
    assert_eq!(v, Verdict::Deny);
    assert_eq!(r, "dest-unstable");
  }

  #[test]
  fn continue_is_required_for_execution() {
    // F4c (supersedes the F4b no-CONTINUE experiment): flags=0 on an
    // allow response makes the kernel skip execution and return
    // resp.val (0) — every allowed syscall fake-succeeds (proven live:
    // connect "succeeds" unconnected, sendto spins on 0-returns). There
    // is no third response mode; allow REQUIRES CONTINUE. The TOCTOU
    // race that CONTINUE re-opens is closed by stability + rate gates
    // instead. This test pins the constant relationship so a future
    // flags=0 reintroduction must delete it loudly.
    assert_ne!(SECCOMP_USER_NOTIF_FLAG_CONTINUE, 0);
  }

  #[test]
  fn sendmmsg_first_dest_denied_under_restriction() {
    // F4: a batch whose first dest is public is denied outright.
    // (P13 ninja F13: the comment here used to claim "first element
    // decides" — stale. F4/R2 widened it: ANY denied dest denies the
    // WHOLE batch, fail-closed; batch_any_denied_denies pins that rule.
    // This test keeps the first-element case as the named regression.)
    let p = EgressPolicy { restrict_ip: true, ..EgressPolicy::new() };
    let _ = &p;
    // decide_dest on a parsed public dest denies; the batch rule then
    // propagates that deny to every element.
    let (v, _, _) = decide_dest(&DestRead::Parsed(Sockaddr::V4(Ipv4Addr::new(8, 8, 8, 8), 53)), &p);
    assert_eq!(v, Verdict::Deny);
  }

  #[test]
  fn signal_unknown_nr_falls_through() {
    // P20/F8 contract change (was: Allow / "signal-other"). A syscall
    // number decide_signal does not recognize means the filter routed
    // something the matcher cannot classify — a table mismatch. Old
    // behavior was fail-open for exactly that class; it now denies.
    // SYS_getpid here stands in for "a real syscall that reached the
    // signal matcher by mistake"; signal_unknown_nr_denied covers a
    // garbage nr.
    let req = SeccompNotif {
      id: 0,
      pid: 1,
      flags: 0,
      data: SeccompData { nr: libc::SYS_getpid as i32, arch: 0, instruction_pointer: 0, args: [0, 0, 0, 0, 0, 0] },
    };
    let (v, r, _) = decide_signal(&req);
    assert_eq!(v, Verdict::Deny);
    assert_eq!(r, "signal-unknown-nr");
  }
}
