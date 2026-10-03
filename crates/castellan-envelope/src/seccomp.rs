use std::io;

const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const EPERM_U: u32 = 1;
/// SECCOMP_RET_KILL_PROCESS — arch/x32 mismatch (P13 ninja F3).
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
/// seccomp_data.arch for the native target. i386 syscall numbers mean
/// different syscalls, so without this gate a compat tracee's
/// `mount`/`ptrace`/`bpf` never match the denylist and fall to ALLOW.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7;
/// x32 sets bit 30 on every nr while reporting the native arch; any nr
/// above this bound is x32/unsupported and cannot match the table.
const X32_NR_BOUND: u32 = 0x3fff_ffff;

/// Syscalls that exist only on x86 (iopl/ioperm) or whose generic-ABI
/// architectures dropped the legacy nr (aarch64 has no chown/lchown —
/// glibc wraps them through fchownat). They are uninvocable on the
/// architectures that lack the constant, so the filter simply does not
/// mention them there. The cross-arch CI job caught the E0425s this
/// design previously produced (the const list named them unconditionally).
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const ARCH_ONLY_SYSCALLS: [libc::c_long; 4] =
  [libc::SYS_iopl, libc::SYS_ioperm, libc::SYS_chown, libc::SYS_lchown];
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
const ARCH_ONLY_SYSCALLS: [libc::c_long; 0] = [];

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const ARCH_ONLY_FILTER_NAMES: &[(&str, libc::c_long)] =
  &[("iopl", libc::SYS_iopl), ("ioperm", libc::SYS_ioperm), ("chown", libc::SYS_chown), ("lchown", libc::SYS_lchown)];
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
const ARCH_ONLY_FILTER_NAMES: &[(&str, libc::c_long)] = &[];

#[rustfmt::skip]
fn blocked_syscalls() -> Vec<libc::c_long> {
  let mut v: Vec<libc::c_long> = vec![
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    // P14 F-B/F-C (probed live 2026-10-01): pidfd_getfd is the modern
    // process-memory / fd-theft primitive — it duplicates a file
    // descriptor out of another process with only
    // PTRACE_MODE_ATTACH_REALCREDS. Measured: pidfd_getfd on a child in
    // the SAME session returned a working fd and the read succeeded
    // (FD-THEFT-CONFIRMED); it was in no class and not blocked.
    // process_madvise/process_mrelease were declared Hard but not
    // blocked. Adding the filter entries makes the filter match the
    // table; pidfd_open stays unblocked (a handle is powerless without a
    // trapped action — pidfd_send_signal is already trapped).
    libc::SYS_pidfd_getfd,
    libc::SYS_process_madvise,
    libc::SYS_process_mrelease,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_open_by_handle_at,
    // P14 F-C: name_to_handle_at was declared Hard (file-handle-bypass
    // pairs with open_by_handle_at) but not blocked. It only produces the
    // handle the open consumes; blocking both closes the class rather
    // than halving it.
    libc::SYS_name_to_handle_at,
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    // P14 F-C: syslog was in the kernel-observer Hard class and unblocked.
    libc::SYS_syslog,
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
    // P14 F-A (probed live 2026-10-01): the class table declared the new
    // mount API as Hard but the filter never blocked it — a mismatch the
    // drift gate could not see (F-D). Measured inside an enforced
    // session: legacy mount() EPERM, but fsopen/fsconfig(CREATE)/fsmount/
    // open_tree("/") all SUCCEEDED (open_tree gave a traversable fd).
    // A mount obtained through the new API is a write surface outside
    // every Landlock rule, exactly the capability the class names.
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_mount_setattr,
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    // P14 F-C (probed live 2026-10-01): the machine-admin Hard class
    // named these as capability-closing members but the filter blocked
    // only reboot/swapon/swapoff. Machine-wide state (disk quota, clock,
    // hostname, raw I/O port access, process accounting) has blast
    // radius beyond the session, which is the class's stated rationale.
    libc::SYS_quotactl,
    libc::SYS_quotactl_fd,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_clock_adjtime,
    libc::SYS_adjtimex,
    libc::SYS_sethostname,
    libc::SYS_setdomainname,
    // iopl/ioperm live in ARCH_ONLY_SYSCALLS (x86-only constants).
    libc::SYS_acct,
    libc::SYS_setxattr, libc::SYS_lsetxattr, libc::SYS_fsetxattr,
    libc::SYS_removexattr, libc::SYS_lremovexattr, libc::SYS_fremovexattr,
    // B6 phase 1: chown/utime families. chmod is deliberately NOT
    // blocked: git chmods .git/config.lock during init/commit (P1
    // kernel finding — verified live: blocking chmod breaks git).
    // The chmod residual is ownership-bounded: the agent can only
    // chmod files it owns inside the Landlock write roots.
    // chown/lchown live in ARCH_ONLY_SYSCALLS (no nr on aarch64);
    // fchown/fchownat exist everywhere and stay in the core list.
    libc::SYS_fchown, libc::SYS_fchownat,
    // V3 (2026-09-02): utime family UNBLOCKED. Blocking it broke every
    // compiled workflow: cargo/cc/touch set mtimes for fingerprints
    // and build artifacts (verified live: "touch: setting times ...
    // Operation not permitted", cargo build fails). The original
    // rationale (ownership-bounded timestamp abuse) is preserved by
    // Landlock: utime only works on files inside write roots.
  ];
  v.extend_from_slice(&ARCH_ONLY_SYSCALLS);
  v
}

fn f(code: u32, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
  libc::sock_filter { code: code as u16, jt, jf, k }
}

fn ld_abs_nr() -> libc::sock_filter {
  f(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0)
}

fn ld_abs_arch() -> libc::sock_filter {
  f(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 4)
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

/// Program layout (P13 ninja F3): 6-instruction arch/x32 prologue,
/// then the denylist pairs, then ALLOW.
///
/// ```text
/// 0  LD  [4]                 arch
/// 1  JEQ NATIVE  jt=1 jf=0   native → 3, foreign → 2
/// 2  RET KILL_PROCESS        compat nrs mean different syscalls
/// 3  LD  [0]                 nr
/// 4  JGT X32_NR_BOUND jt=0 jf=1  x32 → 5, native → 6
/// 5  RET KILL_PROCESS        x32 nrs never match the table below
/// 6+ (JEQ, RET EPERM) pairs ...
///    RET ALLOW
/// ```
///
/// Without the gate a 32-bit compat process bypasses the entire
/// denylist: its syscall numbers are the i386 table, so no JEQ matches
/// and every syscall (mount, ptrace, bpf — the Hard class) falls
/// through to ALLOW. KILL_PROCESS on mismatch is the libseccomp
/// standard: a process whose ABI we cannot evaluate does not run.
/// The tests below index pairs starting at PROLOGUE_LEN.
pub fn seccomp_program() -> Vec<libc::sock_filter> {
  const PROLOGUE_LEN: usize = 6;
  let blocked = blocked_syscalls();
  let mut prog = Vec::with_capacity(PROLOGUE_LEN + blocked.len() * 2 + 1);
  prog.push(ld_abs_arch());
  prog.push(f(
    libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
    1,
    0,
    AUDIT_ARCH_NATIVE,
  ));
  prog.push(ret(SECCOMP_RET_KILL_PROCESS));
  prog.push(ld_abs_nr());
  prog.push(f(
    libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K,
    0,
    1,
    X32_NR_BOUND,
  ));
  prog.push(ret(SECCOMP_RET_KILL_PROCESS));
  for nr in blocked.iter().copied() {
    prog.extend_from_slice(&jeq_kill(nr));
  }
  prog.push(ret(SECCOMP_RET_ALLOW));
  prog
}

/// The filter's real contents, as names, for the drift gate.
///
/// The gate must compare the class table against what the filter
/// **actually blocks**, not against a second declaration of the same
/// list — comparing a table against a copy of itself proves nothing.
/// The numbers are resolved back to names through the same constant
/// table the tests use, and a number with no name is reported as
/// `nr:<n>` rather than dropped, so an unrecognised entry cannot
/// disappear from the report.
/// Name -> number for every syscall the filter may reference. Single
/// source of truth: `blocked_names()` (for the drift gate) and the
/// tests' `syscall_nr` both read this. P14 F-D: this table used to be
/// copied in two places, which is how a member could be added to the
/// class table and never blocked while every check stayed green.
#[rustfmt::skip]
const FILTER_NAMES: &[(&str, libc::c_long)] = &[
  ("ptrace", libc::SYS_ptrace),
  ("process_vm_readv", libc::SYS_process_vm_readv),
  ("process_vm_writev", libc::SYS_process_vm_writev),
  ("pidfd_getfd", libc::SYS_pidfd_getfd),
  ("process_madvise", libc::SYS_process_madvise),
  ("process_mrelease", libc::SYS_process_mrelease),
  ("io_uring_setup", libc::SYS_io_uring_setup),
  ("io_uring_enter", libc::SYS_io_uring_enter),
  ("io_uring_register", libc::SYS_io_uring_register),
  ("open_by_handle_at", libc::SYS_open_by_handle_at),
  ("name_to_handle_at", libc::SYS_name_to_handle_at),
  ("bpf", libc::SYS_bpf),
  ("perf_event_open", libc::SYS_perf_event_open),
  ("userfaultfd", libc::SYS_userfaultfd),
  ("syslog", libc::SYS_syslog),
  ("kcmp", libc::SYS_kcmp),
  ("add_key", libc::SYS_add_key),
  ("request_key", libc::SYS_request_key),
  ("keyctl", libc::SYS_keyctl),
  ("init_module", libc::SYS_init_module),
  ("finit_module", libc::SYS_finit_module),
  ("delete_module", libc::SYS_delete_module),
  ("kexec_load", libc::SYS_kexec_load),
  ("kexec_file_load", libc::SYS_kexec_file_load),
  ("pivot_root", libc::SYS_pivot_root),
  ("chroot", libc::SYS_chroot),
  ("mount", libc::SYS_mount),
  ("umount2", libc::SYS_umount2),
  ("fsopen", libc::SYS_fsopen),
  ("fsconfig", libc::SYS_fsconfig),
  ("fsmount", libc::SYS_fsmount),
  ("move_mount", libc::SYS_move_mount),
  ("open_tree", libc::SYS_open_tree),
  ("mount_setattr", libc::SYS_mount_setattr),
  ("reboot", libc::SYS_reboot),
  ("swapon", libc::SYS_swapon),
  ("swapoff", libc::SYS_swapoff),
  ("quotactl", libc::SYS_quotactl),
  ("quotactl_fd", libc::SYS_quotactl_fd),
  ("settimeofday", libc::SYS_settimeofday),
  ("clock_settime", libc::SYS_clock_settime),
  ("clock_adjtime", libc::SYS_clock_adjtime),
  ("adjtimex", libc::SYS_adjtimex),
  ("sethostname", libc::SYS_sethostname),
  ("setdomainname", libc::SYS_setdomainname),
  ("acct", libc::SYS_acct),
  ("setxattr", libc::SYS_setxattr),
  ("lsetxattr", libc::SYS_lsetxattr),
  ("fsetxattr", libc::SYS_fsetxattr),
  ("removexattr", libc::SYS_removexattr),
  ("lremovexattr", libc::SYS_lremovexattr),
  ("fremovexattr", libc::SYS_fremovexattr),
  ("fchown", libc::SYS_fchown),
  ("fchownat", libc::SYS_fchownat),
];

/// Core table plus the arch-only entries — the sole lookup used by
/// `blocked_names()` and `syscall_nr`, so an arch-split pair can never
/// diverge from what the filter blocks on that arch.
fn filter_names() -> Vec<(&'static str, libc::c_long)> {
  let mut v = FILTER_NAMES.to_vec();
  v.extend_from_slice(ARCH_ONLY_FILTER_NAMES);
  v
}

pub fn blocked_names() -> Vec<String> {
  blocked_syscalls()
    .iter()
    .map(|nr| match filter_names().iter().find(|(_, v)| v == nr) {
      Some((n, _)) => (*n).to_string(),
      None => format!("nr:{}", *nr),
    })
    .collect()
}

pub fn seccomp_apply() -> io::Result<()> {
  // P8 fault injection: the D4 drill must fail loudly when seccomp is
  // dropped. Compile-time hook only — a release build cannot skip this.
  if castellan_core::fault_injected("seccomp") {
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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::syscall_classes::{by_decision, Decision};

  /// Every syscall the filter blocks must belong to a `Hard` class.
  ///
  /// This is the invariant that makes the drift table meaningful. A
  /// blocked syscall with no class is a block whose rationale nobody
  /// wrote down; a `Hard` class whose consts are not blocked is a
  /// capability the table claims is closed and the filter leaves open.
  /// Either way the filter and its justification have drifted apart.
  #[test]
  fn every_blocked_syscall_has_a_hard_class() {
    let hard: Vec<&str> = by_decision(Decision::Hard).flat_map(|c| c.libc_consts.iter().copied()).collect();
    for name in blocked_syscalls() {
      let key = format!("SYS_{}", syscall_name(name).unwrap_or("<unknown>"));
      assert!(
        hard.contains(&key.as_str()),
        "{key} is in blocked_syscalls() but no Hard class claims it — \
         add it to a class with a rationale, or remove it from the filter"
      );
    }
  }

  /// P14 F-D: every MEMBER of a Hard class must resolve to a blocked
  /// syscall, not just the class's own `libc_consts`. The prior test only
  /// checked that a Hard class named *some* const; a member the filter
  /// omitted (fsopen, pidfd_getfd before P14) passed every check while
  /// running free. This is the invariant the drift gate tried to state
  /// but computed on the wrong set.
  #[test]
  fn every_hard_class_member_is_blocked() {
    let blocked = blocked_syscalls();
    for c in by_decision(Decision::Hard) {
      for m in c.members {
        let nr = syscall_nr(m).unwrap_or_else(|| {
          panic!(
            "Hard class {} lists member '{m}' but it has no FILTER_NAMES entry — \
             add the constant (and block it), or reclassify the member",
            c.name
          )
        });
        assert!(
          blocked.contains(&nr),
          "Hard class {} lists member '{m}' but blocked_syscalls() omits it — \
           the class claims a closure the filter does not have",
          c.name
        );
      }
    }
  }

  /// Every `Hard` class const must actually be blocked, or the class's
  /// capability is not actually closed.
  #[test]
  fn every_hard_class_const_is_blocked() {
    let blocked = blocked_syscalls();
    for c in by_decision(Decision::Hard) {
      for k in c.libc_consts {
        let stripped = k.strip_prefix("SYS_").unwrap_or(k);
        let nr = syscall_nr(stripped);
        assert!(
          nr.map(|n| blocked.contains(&n)).unwrap_or(false),
          "class {} lists {k} as Hard but it is not in blocked_syscalls() — \
           the table claims a closure the filter does not have",
          c.name
        );
      }
    }
  }

  /// Map a number back to its name using the libc constants the table
  /// uses. Kept explicit rather than via strace: the gate's job is to
  /// compare the filter to the table, not to observe the system.
  fn syscall_name(nr: libc::c_long) -> Option<&'static str> {
    for c in crate::syscall_classes::CLASSES {
      for k in c.libc_consts {
        if syscall_nr(k.strip_prefix("SYS_").unwrap_or(k)) == Some(nr) {
          return Some(k.strip_prefix("SYS_").unwrap_or(k));
        }
      }
    }
    None
  }

  fn syscall_nr(name: &str) -> Option<libc::c_long> {
    // P14 F-D: single source of truth (filter_names = core + arch
    // entries). This used to be a second copy of the same list, which
    // is how the table and the filter could drift with every check
    // still green.
    filter_names().iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
  }

  /// The filter must be a default-ALLOW denylist (commitment #8) with a
  /// terminating allow, not an accidental allowlist. A one-line change
  /// here would silently invert the whole threat model.
  ///
  /// P13 ninja F3: also pins the arch/x32 prologue — if the gate is
  /// dropped, a compat tracee bypasses the whole denylist (i386 nrs
  /// match no JEQ and fall to ALLOW).
  #[test]
  fn filter_ends_in_allow() {
    let prog = seccomp_program();
    let last = prog.last().expect("non-empty program");
    assert_eq!(last.k, SECCOMP_RET_ALLOW, "filter must fall through to ALLOW");
    // Prologue: LD arch (k=4), JEQ native, RET KILL, LD nr (k=0),
    // JGT x32-bound, RET KILL — pairs begin at index 6.
    assert_eq!(prog[0].code, (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16);
    assert_eq!(prog[0].k, 4, "first load must be seccomp_data.arch");
    assert_eq!(prog[1].k, AUDIT_ARCH_NATIVE, "arch JEQ must compare the native audit arch");
    assert_eq!(prog[2].k, SECCOMP_RET_KILL_PROCESS, "foreign arch must kill");
    assert_eq!(prog[3].k, 0, "second load must be seccomp_data.nr");
    assert_eq!(prog[4].k, X32_NR_BOUND, "x32 gate must bound the nr");
    assert_eq!(prog[5].k, SECCOMP_RET_KILL_PROCESS, "x32 nr must kill");
    assert_eq!(
      prog[6].code,
      (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
      "first denylist pair must start at index 6"
    );
  }

  /// Every syscall the filter blocks must return EPERM, never a kill or
  /// a trap: the agent must get a clean error it can handle, not a
  /// signal it cannot. (The arch/x32 prologue kills — different
  /// contract: an unevaluable ABI must not run at all.)
  #[test]
  fn every_deny_is_eperm() {
    let prog = seccomp_program();
    let n = blocked_syscalls().len();
    for i in 0..n {
      // Pairs start after the 6-instruction prologue: [JEQ, RET] at
      // 6+2i, so the RET is at 7+2i.
      let ret = &prog[7 + (i * 2)];
      assert_eq!(ret.k, SECCOMP_RET_ERRNO | EPERM_U, "deny {i} is not EPERM");
    }
  }
}
