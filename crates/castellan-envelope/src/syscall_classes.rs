//! Syscall capability classes, for the kernel-drift gate.
//!
//! The seccomp filter is a denylist (commitment #8 — it is not an
//! allowlist, see THREAT_MODEL A4). A denylist can only block the
//! syscalls somebody remembered to write down. That is fine for a
//! fixed universe and unsafe across a kernel upgrade: a new syscall
//! ships with no block entry, and nothing notices.
//!
//! The gate (`test/syscall-drift.sh`) reads the table from this file
//! and cross-checks it against the running kernel's syscall table, so a
//! kernel that adds a member to one of these classes turns CI red
//! instead of silently widening the attack surface.
//!
//! ## Why classes, not a list of new syscalls to block
//!
//! Blocking the calls in a class is not safe in the abstract: the class
//! exists because the kernel can add a *new* call to it, and the gate's
//! job is to notice that. Some classes are safe to block outright and
//! some are load-bearing, and that distinction is data, not judgement:
//!
//! - `Hard`: blocked today, and nothing legitimate in the agent workload
//!   needs it.
//! - `Probed`: load-bearing, deliberately ALLOWED (see the git chmod and
//!   cargo utime findings). The gate records the block-state and fails if
//!   the state is ever flipped without a dated justification next to it.
//! - `Novel`: not blocked, not yet needed. If a kernel adds one, the gate
//!   reports it and requires an explicit decision.
//!
//! `Hard` is where the danger lives. `Probed` is where the honest
//! residual lives. `Novel` is the early-warning channel.

/// Decision recorded for one class. Deliberately a closed set: a new
/// member of an existing class must arrive through one of these three
/// buckets, not through a code change nobody reviewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
  /// Blocked in `blocked_syscalls()`. A kernel adding a call here is a
  /// gate FAIL until the new call is added to the denylist.
  Hard,
  /// Deliberately allowed, with a dated reason. A kernel adding a call
  /// here is a gate FAIL until the reason is re-checked.
  Probed,
  /// Not blocked and not yet needed. A kernel adding a call here is a
  /// gate WARN with the new name, and a decision is required.
  Novel,
}

/// One capability class.
pub struct Class {
  /// Class name, used as the gate's grouping key.
  pub name: &'static str,
  /// Why this class matters — the capability an agent would gain.
  pub capability: &'static str,
  /// Current decision, with the evidence that justified it.
  pub decision: Decision,
  /// Dated justification. Non-empty for every class; the gate requires
  /// it, so a decision can never be made silently.
  pub rationale: &'static str,
  /// Syscall names in the class. Names, not numbers: the numbers move
  /// with the architecture and the header, and a hardcoded number is
  /// exactly the kind of thing that silently rots.
  pub members: &'static [&'static str],
  /// libc crate constant suffixes, for the ones we actually reference in
  /// `blocked_syscalls()`. Only needed for `Hard`.
  pub libc_consts: &'static [&'static str],
}

/// Every class the gate watches.
pub const CLASSES: &[Class] = &[
  Class {
    name: "mount-namespace",
    capability: "mount an arbitrary filesystem, or move an existing mount tree around it",
    decision: Decision::Hard,
    rationale: "C25/B6: the rootless overlay owns the session mount view. A second \
                mount capability is a second write surface outside every Landlock rule.",
    members: &[
      "mount",
      "umount2",
      "pivot_root",
      "chroot",
      "fsopen",
      "fsconfig",
      "fsmount",
      "move_mount",
      "open_tree",
      "mount_setattr",
    ],
    libc_consts: &[
      "SYS_mount",
      "SYS_umount2",
      "SYS_pivot_root",
      "SYS_chroot",
      "SYS_fsopen",
      "SYS_fsconfig",
      "SYS_fsmount",
      "SYS_move_mount",
      "SYS_open_tree",
      "SYS_mount_setattr",
    ],
  },
  Class {
    name: "namespace-membership",
    capability: "enter or leave a namespace, changing which policy applies to the caller",
    decision: Decision::Probed,
    rationale: "Measured 2026-09-27 (.227, kernel 7.1.8): `unshare(CLONE_NEWUSER|CLONE_NEWPID)` \
                succeeds inside the envelope, the child enters PID 1 of a fresh namespace, and \
                Landlock plus seccomp BOTH still apply inside it (outside-write EACCES, ptrace \
                EPERM). So entering a namespace is not a policy bypass. `setns` is the riskier \
                direction — it can move into a namespace with weaker policy — and it is allowed \
                only because uid 0 in a user namespace is the intended launcher path. Revisit if \
                the envelope ever runs non-root.",
    members: &["unshare", "setns", "move_mount"],
    libc_consts: &[],
  },
  Class {
    name: "file-handle-bypass",
    capability: "open a file by handle rather than by path, so Landlock's path rules do not apply",
    decision: Decision::Hard,
    rationale: "Landlock is path-based. A handle-based open is a documented path-rule bypass, \
                which is the same class of failure as the bubblewrap path-synonym escape (A1).",
    members: &["open_by_handle_at", "name_to_handle_at"],
    libc_consts: &["SYS_open_by_handle_at", "SYS_name_to_handle_at"],
  },
  Class {
    name: "io-uring",
    capability: "submit syscalls from a shared ring that the seccomp filter does not re-evaluate per call",
    decision: Decision::Hard,
    rationale: "io_uring moves work out of the syscall path where the filter runs. Blocked as a \
                unit (setup/enter/register) because one blocked member does not stop the ring. \
                The kernel exposes exactly these three io_uring syscalls (measured 7.0.3, \
                unistd_64.h); io_uring_stats / io_uring_get_sqe / io_uring_cqe_seen are RING \
                OPCODES, not syscalls, and listing them here was found by this gate's typo check — \
                they were entries that could never match anything.",
    members: &[
      "io_uring_setup",
      "io_uring_enter",
      "io_uring_register",
    ],
    libc_consts: &["SYS_io_uring_setup", "SYS_io_uring_enter", "SYS_io_uring_register"],
  },
  Class {
    name: "kernel-module",
    capability: "load code into the kernel",
    decision: Decision::Hard,
    rationale: "Terminal. Not reachable unprivileged, and a kernel load would make every other \
                control in this document advisory.",
    members: &[
      "init_module",
      "finit_module",
      "delete_module",
      "kexec_load",
      "kexec_file_load",
    ],
    libc_consts: &[
      "SYS_init_module",
      "SYS_finit_module",
      "SYS_delete_module",
      "SYS_kexec_load",
      "SYS_kexec_file_load",
    ],
  },
  Class {
    name: "process-memory",
    capability: "read or write another process's address space",
    decision: Decision::Hard,
    rationale: "Direct cross-session read/write primitive. Same uid is the point: the session is \
                not a privilege boundary from its own siblings without this.",
    members: &[
      "ptrace",
      "process_vm_readv",
      "process_vm_writev",
      "process_mrelease",
      "process_madvise",
      "kcmp",
      "pidfd_getfd",
    ],
    libc_consts: &[
      "SYS_ptrace",
      "SYS_process_vm_readv",
      "SYS_process_vm_writev",
      "SYS_pidfd_getfd",
      "SYS_process_madvise",
      "SYS_process_mrelease",
      "SYS_kcmp",
    ],
  },
  Class {
    name: "kernel-observer",
    capability: "observe or steer kernel-internal state (BPF, perf, faults)",
    decision: Decision::Hard,
    rationale: "BPF can rewrite a syscall return value, which would let a session lie to its own \
                daemon about a file write. perf_event_open and userfaultfd are read/control \
                channels over other processes.",
    members: &[
      "bpf",
      "perf_event_open",
      "userfaultfd",
      "syslog",
      "kexec_file_load",
    ],
    libc_consts: &["SYS_bpf", "SYS_perf_event_open", "SYS_userfaultfd", "SYS_syslog"],
  },
  Class {
    name: "keyring",
    capability: "read or inject kernel keyring material",
    decision: Decision::Hard,
    rationale: "Keyrings persist beyond the session. A write is an injection channel that a \
                later, differently-scoped process would consume.",
    members: &["add_key", "request_key", "keyctl"],
    libc_consts: &["SYS_add_key", "SYS_request_key", "SYS_keyctl"],
  },
  Class {
    name: "machine-admin",
    capability: "change machine-wide state (swap, reboot, quota, clock)",
    decision: Decision::Hard,
    rationale: "Blast radius is the whole machine, not the session. The compromise of one \
                session must not reach the host's persistence.",
    members: &[
      "reboot",
      "swapon",
      "swapoff",
      "quotactl",
      "quotactl_fd",
      "settimeofday",
      "clock_settime",
      "clock_adjtime",
      "adjtimex",
      "sethostname",
      "setdomainname",
      "iopl",
      "ioperm",
      "acct",
    ],
    libc_consts: &[
      "SYS_reboot",
      "SYS_swapon",
      "SYS_swapoff",
      "SYS_quotactl",
      "SYS_quotactl_fd",
      "SYS_settimeofday",
      "SYS_clock_settime",
      "SYS_clock_adjtime",
      "SYS_adjtimex",
      "SYS_sethostname",
      "SYS_setdomainname",
      "SYS_iopl",
      "SYS_ioperm",
      "SYS_acct",
    ],
  },
  Class {
    name: "extended-attribute",
    capability: "attach arbitrary xattrs to files inside the write roots",
    decision: Decision::Hard,
    rationale: "B6 phase 1. xattrs are a covert channel and a persistence vector: security.* and \
                trusted.* xattrs change how other tools and the kernel treat a file, from outside \
                the Landlock path decision.",
    members: &[
      "setxattr",
      "lsetxattr",
      "fsetxattr",
      "removexattr",
      "lremovexattr",
      "fremovexattr",
    ],
    libc_consts: &[
      "SYS_setxattr",
      "SYS_lsetxattr",
      "SYS_fsetxattr",
      "SYS_removexattr",
      "SYS_lremovexattr",
      "SYS_fremovexattr",
    ],
  },
  Class {
    name: "ownership-transfer",
    capability: "hand a file to another uid, changing who the Landlock rules apply to",
    decision: Decision::Hard,
    rationale: "B6 phase 1. Ownership is how Landlock's write-root decision is scoped, so \
                transferring it is a way to move a file across that decision. The session is \
                same-uid with its siblings, so chown is not a privilege the agent legitimately \
                has. Blocked; the separate timestamp class below is the one that was relaxed.",
    members: &["chown", "fchown", "lchown", "fchownat"],
    libc_consts: &["SYS_chown", "SYS_fchown", "SYS_lchown", "SYS_fchownat"],
  },
  Class {
    name: "timestamp-permission",
    capability: "relax the permission bits or timestamps on a file inside the write roots",
    decision: Decision::Probed,
    rationale: "V3 (2026-09-02) deliberately UNBLOCKED this whole family. Blocking it broke \
                every compiled workflow: cargo/cc/touch set mtimes for fingerprints and build \
                artifacts, measured live as \"touch: setting times ... Operation not permitted\" \
                and cargo build failing. chmod was never blocked for the same reason: git \
                chmods .git/config.lock during init and commit. This is the honest residual — \
                the agent can make a file it owns inside the write roots more permissive. The \
                bound is ownership plus Landlock: the agent can only chmod files it already \
                owns, inside roots it already controls, so the reach stops at the envelope. The \
                gate keeps this class visible precisely because the residual is real, and a \
                kernel that adds a member here (e.g. a new mode-bit call) needs the question \
                re-asked rather than inherited by default.",
    members: &[
      "chmod",
      "fchmod",
      "fchmodat",
      "utime",
      "utimes",
      "futimesat",
      "utimensat",
    ],
    libc_consts: &[],
  },
  Class {
    name: "landlock-self-service",
    capability: "create a Landlock ruleset, add rules to it, or restrict the caller with it",
    decision: Decision::Probed,
    rationale: "Found by the drift gate on kernel 7.0.3, 2026-09-27 — the kernel exposes \
                landlock_create_ruleset / landlock_add_rule / landlock_restrict_self and the table \
                did not classify them. Landlock is monotonic: a process may only ever NARROW its \
                own domain, and only by intersecting a new ruleset with the one it already has, so \
                the agent cannot widen its own access by calling these. That is the reason they \
                are safe to allow. The residual is an information and code-path surface rather \
                than a privilege one: a session can build rulesets and observe EPERM/EOPNOTSUPP \
                to fingerprint the ABI it is confined by, and can spend its own budget on ruleset \
                syscalls. Revisit if Landlock ever gains a non-monotonic operation, or if a future \
                kernel adds an LSM-syscall in this family that                 is not monotonic.",
    members: &[
      "landlock_create_ruleset",
      "landlock_add_rule",
      "landlock_restrict_self",
      "lsm_get_self_attr",
      "lsm_set_self_attr",
      "lsm_list_modules",
    ],
    libc_consts: &[],
  },
  Class {
    name: "resource-tuning",
    capability: "raise or observe limits the sandbox intends to bound",
    decision: Decision::Novel,
    rationale: "Not blocked. No measured escape, and several calls here are load-bearing for a \
                real toolchain. Listed so a kernel that adds a member shows up as a WARN with a \
                name attached rather than as silence. The kernel's own rseq_slice_yield (7.0.3) is \
                in this family: rseq is register-based and fast, and a future rseq call that can \
                fault-inject or reprioritise is the shape worth watching.",
    members: &[
      "setrlimit",
      "prlimit64",
      "getrlimit",
      "sched_setattr",
      "sched_setaffinity",
      "membarrier",
      "rseq",
      "rseq_slice_yield",
    ],
    libc_consts: &[],
  },
];

/// Syscall names in a class, for gate output.
pub fn members_of(name: &str) -> Option<&'static [&'static str]> {
  CLASSES.iter().find(|c| c.name == name).map(|c| c.members)
}

/// Classes by decision, for the gate's summary.
pub fn by_decision(d: Decision) -> impl Iterator<Item = &'static Class> {
  CLASSES.iter().filter(move |c| c.decision == d)
}

/// Name -> class index, for attributing a new syscall the gate finds.
pub fn class_of_syscall(nr: &str) -> Option<&'static Class> {
  CLASSES.iter().find(|c| c.members.contains(&nr))
}

/// Every watched syscall name, deduplicated and sorted, for the gate's
/// coverage check against a running kernel.
pub fn watched_syscalls() -> Vec<&'static str> {
  let mut v: Vec<&'static str> =
    CLASSES.iter().flat_map(|c| c.members.iter().copied()).collect();
  v.sort_unstable();
  v.dedup();
  v
}

/// Machine-readable dump for the shell gate. Keeping the data in Rust
/// and the driver in bash means the table is type-checked and lives in
/// the same crate as the filter it describes.
pub fn dump() -> String {
  let mut out = String::new();
  out.push_str("# name\tdecision\tmembers\n");
  for c in CLASSES {
    out.push_str(&format!("{}\t{:?}\t{}\n", c.name, c.decision, c.members.join(",")));
  }
  out
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::collections::BTreeMap;

  #[test]
  fn every_class_has_a_rationale() {
    for c in CLASSES {
      assert!(!c.rationale.trim().is_empty(), "{} has no rationale", c.name);
      assert!(c.rationale.len() > 40, "{} rationale is too thin to be a decision record", c.name);
    }
  }

  #[test]
  fn every_class_has_members() {
    for c in CLASSES {
      assert!(!c.members.is_empty(), "{} has no members", c.name);
    }
  }

  #[test]
  fn class_names_are_unique() {
    let mut v: Vec<&str> = CLASSES.iter().map(|c| c.name).collect();
    v.sort_unstable();
    let n = v.len();
    v.dedup();
    assert_eq!(v.len(), n, "duplicate class name");
  }

  #[test]
  fn every_member_is_lowercase_ascii() {
    // The gate matches names against the kernel's own table, which is
    // all lowercase. A typo here would silently never match.
    for c in CLASSES {
      for m in c.members {
        assert!(
          m.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_' || ch.is_ascii_digit()),
          "{}.{m} is not a valid kernel syscall name",
          c.name
        );
      }
    }
  }

  #[test]
  fn hard_classes_all_name_a_blocked_const() {
    for c in by_decision(Decision::Hard) {
      assert!(
        !c.libc_consts.is_empty(),
        "Hard class {} names no libc const, so the gate cannot tell whether it is actually blocked",
        c.name
      );
    }
  }

  #[test]
  fn a_syscall_can_span_at_most_two_classes() {
    // Some calls legitimately sit in two classes (move_mount is a mount
    // primitive AND a namespace primitive; kexec_file_load is module
    // AND observer). More than two would mean the classes are not
    // orthogonal and the gate's attribution is meaningless.
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for c in CLASSES {
      for m in c.members {
        *counts.entry(*m).or_default() += 1;
      }
    }
    for (name, n) in counts {
      assert!(n <= 2, "{name} appears in {n} classes");
    }
  }

  #[test]
  fn watched_list_is_sorted_and_deduped() {
    let v = watched_syscalls();
    let mut sorted = v.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(v, sorted);
  }
}
