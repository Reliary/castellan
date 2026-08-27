use castellan_policy::Policy;
use crate::seccomp::seccomp_apply;
use std::io;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u8 = 1;
const LANDLOCK_RULE_NET_PORT: u8 = 2;

#[repr(C)]
struct LandlockRulesetAttr {
  handled_access_fs: u64,
  handled_access_net: u64,
}

// kernel struct is two u64s, naturally aligned (NOT packed)
#[repr(C)]
#[derive(Clone, Copy)]
struct LandlockNetPortAttr {
  allowed_access: u64,
  port: u64,
}

const NET_BIND_TCP: u64 = 1 << 0;
const NET_CONNECT_TCP: u64 = 1 << 1;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct LandlockPathBeneathAttr {
  allowed_access: u64,
  parent_fd: i32,
}

const ACCESS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_READ_FILE: u64 = 1 << 2;
const ACCESS_READ_DIR: u64 = 1 << 3;
const ACCESS_REMOVE_DIR: u64 = 1 << 4;
const ACCESS_REMOVE_FILE: u64 = 1 << 5;
const ACCESS_MAKE_CHAR: u64 = 1 << 6;
const ACCESS_MAKE_DIR: u64 = 1 << 7;
const ACCESS_MAKE_REG: u64 = 1 << 8;
const ACCESS_MAKE_SOCK: u64 = 1 << 9;
const ACCESS_MAKE_FIFO: u64 = 1 << 10;
const ACCESS_MAKE_BLOCK: u64 = 1 << 11;
const ACCESS_MAKE_SYM: u64 = 1 << 12;
const ACCESS_REFER: u64 = 1 << 13;
const ACCESS_TRUNCATE: u64 = 1 << 14;
const ACCESS_IOCTL_DEV: u64 = 1 << 15;

const READ_ACCESS: u64 = ACCESS_READ_FILE | ACCESS_READ_DIR;

const FILE_WRITE_ACCESS: u64 = ACCESS_WRITE_FILE;

fn syscall4(nr: libc::c_long, a: usize, b: usize, c: usize, d: u32) -> io::Result<i64> {
  let r = unsafe { libc::syscall(nr, a, b, c, d) };
  if r < 0 {
    Err(io::Error::last_os_error())
  } else {
    Ok(r)
  }
}

pub fn landlock_abi() -> Option<u32> {
  let r = unsafe {
    libc::syscall(libc::SYS_landlock_create_ruleset, 0usize, 0usize, LANDLOCK_CREATE_RULESET_VERSION)
  };
  (r >= 0).then_some(r as u32)
}

fn write_access_for(abi: u32) -> u64 {
  let mut access = ACCESS_WRITE_FILE
    | ACCESS_REMOVE_DIR
    | ACCESS_REMOVE_FILE
    | ACCESS_MAKE_CHAR
    | ACCESS_MAKE_DIR
    | ACCESS_MAKE_REG
    | ACCESS_MAKE_SOCK
    | ACCESS_MAKE_FIFO
    | ACCESS_MAKE_BLOCK
    | ACCESS_MAKE_SYM;
  if abi >= 2 {
    access |= ACCESS_REFER;
  }
  if abi >= 3 {
    access |= ACCESS_TRUNCATE;
  }
  if abi >= 6 {
    access |= ACCESS_IOCTL_DEV;
  }
  access
}

fn handled_access(abi: u32) -> u64 {
  READ_ACCESS | write_access_for(abi)
}

fn libc_open_path(path: &Path) -> io::Result<RawFd> {
  let cstr = match std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
    Ok(c) => c,
    Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad path")),
  };
  let fd = unsafe { libc::open(cstr.as_ptr(), libc::O_PATH | libc::O_CLOEXEC | libc::O_RDONLY) };
  if fd < 0 {
    Err(io::Error::last_os_error())
  } else {
    Ok(fd)
  }
}

pub struct Ruleset {
  fd: RawFd,
}

impl Ruleset {
  /// `net_connect_allow`: TCP ports the session may CONNECT to. When
  /// `handle_net` is true, ALL other connect/bind is kernel-denied.
  pub fn create(
    write_roots: &[PathBuf],
    file_write_roots: &[PathBuf],
    read_roots: &[PathBuf],
    abi: u32,
    handle_net: bool,
    net_connect_allow: &[u16],
  ) -> io::Result<Self> {
    let handled = handled_access(abi);
    let handled_net =
      if handle_net && abi >= 4 { NET_BIND_TCP | NET_CONNECT_TCP } else { 0 };
    let attr = LandlockRulesetAttr { handled_access_fs: handled, handled_access_net: handled_net };
    let fd = syscall4(
      libc::SYS_landlock_create_ruleset,
      &attr as *const _ as usize,
      std::mem::size_of::<LandlockRulesetAttr>(),
      0,
      0,
    )? as RawFd;
    let ruleset = Self { fd };
    for root in read_roots {
      ruleset.add_rule(root, READ_ACCESS)?;
    }
    for root in write_roots {
      ruleset.add_rule(root, write_access_for(abi))?;
    }
    for root in file_write_roots {
      ruleset.add_rule(root, FILE_WRITE_ACCESS | (if abi >= 3 { ACCESS_TRUNCATE } else { 0 }))?;
    }
    if handled_net != 0 {
      // BIND stays fully denied (no bind rules at all)
      for port in net_connect_allow {
        ruleset.add_net_rule(NET_CONNECT_TCP, *port as u64)?;
      }
    }
    Ok(ruleset)
  }

  fn add_rule(&self, path: &Path, access: u64) -> io::Result<()> {
    let pfd = match libc_open_path(path) {
      Ok(fd) => fd,
      Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
      Err(e) => return Err(e),
    };
    let beneath = LandlockPathBeneathAttr { allowed_access: access, parent_fd: pfd };
    let r = syscall4(
      libc::SYS_landlock_add_rule,
      self.fd as usize,
      LANDLOCK_RULE_PATH_BENEATH as usize,
      &beneath as *const _ as usize,
      0,
    );
    unsafe { libc::close(pfd) };
    r.map(|_| ())
  }

  fn add_net_rule(&self, access: u64, port: u64) -> io::Result<()> {
    let attr = LandlockNetPortAttr { allowed_access: access, port };
    let r = syscall4(
      libc::SYS_landlock_add_rule,
      self.fd as usize,
      LANDLOCK_RULE_NET_PORT as usize,
      &attr as *const _ as usize,
      0,
    );
    r.map(|_| ())
  }

  pub fn restrict_self(self) -> io::Result<()> {
    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    let r = syscall4(libc::SYS_landlock_restrict_self, self.fd as usize, 0, 0, 0);
    unsafe { libc::close(self.fd) };
    r.map(|_| ())
  }
}

impl Drop for Ruleset {
  fn drop(&mut self) {
    unsafe { libc::close(self.fd) };
  }
}

pub fn read_roots_for_envelope() -> Vec<PathBuf> {
  vec![PathBuf::from("/")]
}

pub fn apply_envelope(policy: &Policy) -> io::Result<()> {
  let abi = landlock_abi()
    .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "landlock not available"))?;
  let dir_roots: Vec<PathBuf> = policy.write_roots().to_vec();
  let file_roots: Vec<PathBuf> = policy.allow_write_roots().to_vec();
  let (handle_net, net_allow): (bool, Vec<u16>) = match policy.net() {
    castellan_policy::NetMode::Loopback(ports) => (true, ports.clone()),
    castellan_policy::NetMode::Open => (false, vec![]),
  };
  let ruleset =
    Ruleset::create(&dir_roots, &file_roots, &read_roots_for_envelope(), abi, handle_net, &net_allow)?;
  seccomp_apply()?;
  ruleset.restrict_self()
}
