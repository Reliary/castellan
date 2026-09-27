//! Measure the syscalls a real agent workload needs.
//!
//! The drift gate's `Hard` classes are only safe to block if the
//! workload does not need them. Today that claim is an argument —
//! "git needs chmod, cargo needs utime" — and THREAT_MODEL A4 records
//! that the metadata family was unblocked because blocking it broke
//! real compiled workflows. That decision should be re-derivable, not
//! remembered.
//!
//! This is a minimal ptrace-based syscall tracer: no strace, no
//! external dependency, so it runs wherever the workload runs.
//!
//!   syscall-probe <out-dir> <program> [args...]
//!
//! It writes `<out-dir>/syscalls.txt`, the sorted unique set of syscall
//! numbers the workload entered, and `<out-dir>/report.txt`, a summary.
//! The companion `test/workload-syscalls.sh` maps numbers to names via
//! the kernel's own table and fails when the workload needs a syscall
//! the capability table classifies as `Hard` — because that means the
//! block would break real work and the `Probed` decision that replaced
//! it has to be re-examined.
//!
//! Why ptrace and not seccomp: SECCOMP_RET_TRACE needs an attached
//! tracer, and SECCOMP_RET_TRAP's handler does not survive `exec`, so
//! neither can measure a process across exec without a tracer anyway.
//! PTRACE_SYSCALL gives the same data with one moving part.
//!
//! Cost: the tracee stops at every syscall, so the workload runs several
//! times slower. That is fine for measurement and is stated here rather
//! than discovered later.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::Command;

const PTRACE_TRACEME: i32 = 0;
const PTRACE_CONT: i32 = 7;
const PTRACE_SYSCALL: i32 = 24;
const PTRACE_SETOPTIONS: i32 = 0x4200;
const PTRACE_GETREGS: i32 = 12;
const PTRACE_O_TRACESYSGOOD: i64 = 1;

/// `struct user_regs_struct` from <sys/user.h>, x86_64. The field ORDER
/// is load-bearing: ptrace returns a raw register blob, so a field added
/// or reordered silently shifts every register after it and orig_rax
/// reads as garbage. Index 15 is orig_rax (the syscall number on entry).
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct UserRegs {
  r15: u64,     // 0
  r14: u64,     // 1
  r13: u64,     // 2
  r12: u64,     // 3
  rbp: u64,     // 4
  rbx: u64,     // 5
  r11: u64,     // 6
  r10: u64,     // 7
  r9: u64,      // 8
  r8: u64,      // 9
  rax: u64,     // 10
  rcx: u64,     // 11
  rdx: u64,     // 12
  rsi: u64,     // 13
  rdi: u64,     // 14
  orig_rax: u64,// 15  <- syscall number on entry
  rip: u64,     // 16
  cs: u64,      // 17
  eflags: u64,  // 18
  rsp: u64,     // 19
  ss: u64,      // 20
  fs_base: u64, // 21
  gs_base: u64, // 22
  ds: u64,      // 23
  es: u64,      // 24
  fs: u64,      // 25
  gs: u64,      // 26
}

fn ptrace(req: i32, pid: i32, addr: u64, data: u64) -> i64 {
  unsafe { libc::syscall(libc::SYS_ptrace, req, pid, addr, data) as i64 }
}

fn main() {
  let argv: Vec<String> = std::env::args().collect();
  if argv.len() < 3 {
    eprintln!("usage: syscall-probe <out-dir> <program> [args...]");
    std::process::exit(2);
  }
  let outdir = argv[1].clone();
  let prog = argv[2].clone();
  let rest: Vec<String> = argv[3..].to_vec();
  std::fs::create_dir_all(&outdir).expect("out-dir");

  let mut cmd = Command::new(&prog);
  cmd.args(&rest);
  unsafe {
    cmd.pre_exec(|| {
      // TRACEME before exec: the exec itself raises SIGTRAP, which is how
      // the parent learns the image is loaded and can set options.
      if ptrace(PTRACE_TRACEME, 0, 0, 0) != 0 {
        return Err(std::io::Error::last_os_error());
      }
      Ok(())
    });
  }
  let mut child = match cmd.spawn() {
    Ok(c) => c,
    Err(e) => {
      eprintln!("syscall-probe: spawn failed: {e}");
      std::process::exit(1);
    }
  };
  let pid = child.id() as i32;

  let mut seen: BTreeMap<i64, u64> = BTreeMap::new();
  let mut in_syscall = false;
  let mut stops = 0u64;
  let mut status: i32 = 0;

  loop {
    let mut st: i32 = 0;
    let r = unsafe { libc::waitpid(pid, &mut st, 0) };
    if r < 0 {
      break;
    }
    if libc::WIFEXITED(st) || libc::WIFSIGNALED(st) {
      status = st;
      break;
    }
    stops += 1;
    // Cap: a runaway tracee must not hang the gate. 4M stops is far
    // beyond any realistic short workload.
    if stops > 4_000_000 {
      eprintln!("syscall-probe: stop cap reached; report is partial");
      ptrace(PTRACE_CONT, pid, 0, 0);
      break;
    }
    let sig = libc::WSTOPSIG(st);
    if sig == libc::SIGTRAP {
      // First stop is the post-exec trap. Arm syscall tracing there.
      ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD as u64);
      ptrace(PTRACE_SYSCALL, pid, 0, 0);
      continue;
    }
    if sig == libc::SIGTRAP | 0x80 {
      // syscall-entry / syscall-exit alternation. On entry orig_rax is
      // the syscall number; on exit it is -1, which is how the two stops
      // are told apart without tracking a flag.
      let mut regs = UserRegs::default();
      if ptrace(PTRACE_GETREGS, pid, 0, &mut regs as *mut _ as u64) == 0 {
        let nr = regs.orig_rax as i64;
        if !in_syscall && nr >= 0 {
          *seen.entry(nr).or_insert(0) += 1;
        }
        in_syscall = !in_syscall;
      }
      ptrace(PTRACE_SYSCALL, pid, 0, 0);
      continue;
    }
    // Any other signal: deliver it and keep going, so the workload
    // behaves as it normally would.
    ptrace(PTRACE_SYSCALL, pid, 0, sig as u64);
  }

  let _ = child.wait();
  let body: String = seen
    .iter()
    .map(|(n, c)| format!("{n}\t{c}\n"))
    .collect();
  std::fs::write(format!("{outdir}/syscalls.txt"), body).expect("write syscalls");
  let mut rep = String::new();
  rep.push_str(&format!("workload: {prog} {}\n", rest.join(" ")));
  rep.push_str(&format!("unique syscalls: {}\n", seen.len()));
  rep.push_str(&format!("stops: {stops}\n"));
  if libc::WIFEXITED(status) {
    rep.push_str(&format!("exit: {}\n", libc::WEXITSTATUS(status)));
  } else if libc::WIFSIGNALED(status) {
    rep.push_str(&format!("signal: {}\n", libc::WTERMSIG(status)));
  }
  std::fs::write(format!("{outdir}/report.txt"), &rep).expect("write report");
  print!("{rep}");
  let _ = std::io::stdout().flush();
}
