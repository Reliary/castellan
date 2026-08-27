use std::io;

const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const EPERM_U: u32 = 1;

#[rustfmt::skip]
fn blocked_syscalls() -> &'static [libc::c_long] {
  &[
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_open_by_handle_at,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_kcmp,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_keyctl,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_setxattr, libc::SYS_lsetxattr, libc::SYS_fsetxattr,
    libc::SYS_removexattr, libc::SYS_lremovexattr, libc::SYS_fremovexattr,
  ]
}

fn f(code: u32, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
  libc::sock_filter { code: code as u16, jt, jf, k }
}

fn ld_abs_nr() -> libc::sock_filter {
  f(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0)
}

fn ret(k: u32) -> libc::sock_filter {
  f(libc::BPF_RET | libc::BPF_K, 0, 0, k)
}

fn jeq_kill(nr: libc::c_long) -> [libc::sock_filter; 2] {
  [
    f(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 1, nr as u32),
    ret(SECCOMP_RET_ERRNO | EPERM_U),
  ]
}

pub fn seccomp_program() -> Vec<libc::sock_filter> {
  let blocked = blocked_syscalls();
  let mut prog = Vec::with_capacity(2 + blocked.len() * 2 + 1);
  prog.push(ld_abs_nr());
  for nr in blocked.iter().copied() {
    prog.extend_from_slice(&jeq_kill(nr));
  }
  prog.push(ret(SECCOMP_RET_ALLOW));
  prog
}

pub fn seccomp_apply() -> io::Result<()> {
  // P8 fault injection: the D4 drill must fail loudly when seccomp is
  // dropped. Test-only, env-gated — the daemon's env is not agent-set.
  if std::env::var("CASTELLAN_TEST_DISABLE_SECCOMP").is_ok() {
    return Ok(());
  }
  let prog = seccomp_program();
  unsafe {
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
      return Err(io::Error::last_os_error());
    }
    let fprog = libc::sock_fprog { len: prog.len() as u16, filter: prog.as_ptr() as *mut _ };
    if libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &fprog, 0, 0) != 0 {
      return Err(io::Error::last_os_error());
    }
  }
  Ok(())
}
