# P14 — Esoteric escape sweep: gaps within gaps

Status: EXECUTED (2026-10-01) — probes measured live, all findings fixed
Branch: `escape-sweep`
Predecessor: P13 (C37/C37n in THREAT_MODEL). P13 closed the *named*
vectors. P14 hunts the gaps **inside the controls themselves** — the
places where the thing that is supposed to catch an escape is itself
blind.

The operating rule is the castellan honesty rule: every assertion below
is a live measurement on this box (kernel 7.0.3, and the exercise box
runs 7.1.8); nothing is argued from documentation. Probes:
`test/probe-p14-*.py`.

## The through-line

Three independent "the guard does not guard" findings, all confirmed
from inside an enforced session:

1. **The filter is smaller than its own spec.** The capability-class
   table (`syscall_classes.rs`) declares 21 members across 5 `Hard`
   classes that `blocked_syscalls()` never blocks. The drift gate that
   exists to catch exactly this cannot, because of a dead branch in its
   own logic (finding 3). Measured: legacy `mount` → EPERM, but the
   **new mount API** (`fsopen`/`fsconfig`/`fsmount`/`open_tree`) → OK.
2. **A new capability in a watched family is unclassified.** `pidfd_getfd`
   is the modern process-memory / fd-theft primitive. It is in no class
   and not blocked. Measured: `pidfd_getfd` on a same-session child
   returns a working fd and the read succeeds (`FD-THEFT-CONFIRMED`).
   Cross-session is unconfirmed (YAMA ptrace_scope=1 likely denies it),
   reported as unconfirmed, not as a break.
3. **The drift gate's "Hard class → is blocked" branch is unreachable.**
   `check_kw` computes `hits = comm -23 <kernel-matching-names> <known>`,
   i.e. it *excludes* every name the table already lists — so a member
   the table lists (as Hard) but the filter omits is invisible. The
   Rust test `hard_classes_all_name_a_blocked_const` only checks that a
   class names *some* const, not that each *member* is blocked. The
   gate passes green while 21 declared-Hard members run free.

A fourth, lower-severity family gap: the broker's sockaddr parser maps
any non-INET/INET6/UNIX family to `Sockaddr::Other(fam)` and `decide()`
returns `Allow "other-family"` (`lib.rs:708`). Measured: `AF_VSOCK` and
`AF_SMC` sockets open inside the session; a `connect()` on one is
trapped by the seccomp filter (connect is connect) and then **allowed**
by the broker. No confirmed escape (would need a host-side VSOCK peer),
but the default is open where the rest of the design is fail-closed.

## Measured results

Session: `castellan launch --harness claude --enforce`.

| Probe | Result | Reading |
|---|---|---|
| `unshare(CLONE_NEWUSER\|CLONE_NEWNS)` | OK | matches the Probed class measurement |
| legacy `mount("tmpfs", tgt)` | **ERRNO-1** | denylist works for the legacy call |
| `fsopen("tmpfs",0)` | **OK fd=3** | new-API member, declared Hard, not blocked |
| `fsconfig(fd, CREATE)` | **OK** | same |
| `fsmount(fd,0,0)` | **OK mfd=4** | same |
| `move_mount(mfd, tgt)` | ERRNO-1 | **incidentally** denied — see note |
| `open_tree(AT_FDCWD,"/",0)` | **OK fd=5** | a traversable mount fd to `/` |
| `openat` through that mount fd | **OK fd=6** | the fd is usable |
| `pidfd_open(self)` | OK | harmless alone |
| `pidfd_getfd(child,fd3)` | **OK fd=4** | then `read` → `SECRET-CONTENT-P14` (`FD-THEFT-CONFIRMED`, same session) |
| cross-session `pidfd_getfd` | no theft | target pid not reachable as a descendant; **unconfirmed**, not a pass |
| `process_madvise` / `process_mrelease` | ERRNO-9 | not blocked; EBADF on the bogus args used |
| `name_to_handle_at` | ERRNO-14 | not blocked; EFAULT on the null handle |
| `AF_VSOCK` / `AF_SMC` socket() | **OK** | broker `Other=>Allow` would wave a connect through |
| `AF_PACKET`/`AF_XDP` socket() | ERRNO-1 | denied (unprivileged), not by us |
| `AF_ALG`/`AF_NETLINK`/`AF_KCM` | ERRNO-94 | protocol unsupported on this kernel |
| `AF_TIPC`/`AF_QIPCRTR` | ERRNO-97/91 | unsupported |

### Note on `move_mount` ERRNO-1

`move_mount` was denied while the rest of the new API opened fds. This
is **not necessarily our filter**: at `move_mount` the process is
namespace-root but on a kernel with a locked-down `mount` path the
attach can fail for reasons unrelated to seccomp. The `fsopen`/`fsmount`
successes plus `open_tree` are the confirmed half; whether a different
kernel admits the attach is exactly the kind of thing this project does
not assume away, so the fix blocks the whole family rather than relying
on the incidental denial.

## Findings

| ID | Finding | Severity | Class |
|----|---------|----------|-------|
| F-A | New mount API (`fsopen`/`fsconfig`/`fsmount`/`move_mount`/`open_tree`/`mount_setattr`) declared Hard, not blocked | High | mount-namespace |
| F-B | `pidfd_getfd` unclassified and unblocked (fd theft primitive) | High | new → process-memory |
| F-C | `process_madvise`/`process_mrelease`/`name_to_handle_at`/`syslog`/`quotactl(_fd)`/time-and-hostname family declared Hard, not blocked | Medium | process-memory, machine-admin, kernel-observer, file-handle-bypass |
| F-D | Drift gate's Hard-member→filter check is dead; Rust test checks consts not members | High | gate |
| F-E | Broker `Other(_) => Allow` waves any non-INET/UNIX family through | Medium | broker |

## Fixes

- **F-A / F-C:** every unblocked `Hard` member added to `blocked_syscalls()`
  and to its class's `libc_consts` (mount family, `pidfd_getfd`,
  `process_madvise`/`process_mrelease`, `name_to_handle_at`, `syslog`,
  the machine-admin family: `quotactl`/`quotactl_fd`/`settimeofday`/
  `clock_settime`/`clock_adjtime`/`adjtimex`/`sethostname`/
  `setdomainname`/`iopl`/`ioperm`/`acct`). Filter grew 36 → 58 blocked
  syscalls. **Negative control: `test/workload-syscalls.py` PASS** —
  none of the newly-blocked syscalls are needed by the 8 real workloads
  (git init/commit, `rustc -O`, touch, python, sh, cargo, echo), so no
  member had to be reclassified `Probed`. A shared `FILTER_NAMES` table
  now backs both `blocked_names()` and the tests' `syscall_nr` (the old
  triple copy is how F-A drifted unnoticed).
- **F-B:** `pidfd_getfd` added to the `process-memory` class + filter.
  `pidfd_open` stays (a handle is powerless without a trapped action;
  `pidfd_send_signal` is already trapped) — recorded, not blocked.
- **F-D:** `test/syscall-drift.sh` gains "every Hard-class member is in
  the filter" computed on the member set directly, and a Rust test
  `every_hard_class_member_is_blocked`. Both proven able to fail: the
  drift selftest's seeds and a hand-seeded `fsopen` removal both go red
  (`FAIL: Hard-class members NOT blocked …: fsopen`).
- **F-E:** `EgressPolicy::deny_unknown_family` (default true) denies any
  address family other than INET/INET6/UNIX, except the two kernel-local
  families `AF_NETLINK` and `AF_ALG`. Audit posture restores the old
  blanket-allow. Verified: AF_VSOCK connect in-session → EPERM; on the
  host → ECONNRESET (kernel tried) — the probe is discriminating.

## Results (post-fix)

Probe battery `test/shell.d/p14-esoteric.sh`: **8/0** — legacy `mount`,
`fsopen`, `open_tree`, `pidfd_getfd`, `process_madvise`,
`name_to_handle_at` all EPERM inside the session, with the host control
proving the probe discriminates. Drift gate: **PASS** with the new
member-closure check (and red when seeded). P13 battery **17/0**, b8
**19/19**, workspace **207 tests**, clippy 0, workload probe PASS.

## Kill criteria (pre-registered) — outcome

- Mount family breaks a workload → reclassify `Probed`. **Not triggered**
  (workload probe PASS).
- Broker family-deny breaks a real workload connect → list it `Probed`.
  **Not triggered** (AF_NETLINK/AF_ALG explicitly allowed; desktop
  workloads use INET/UNIX).
- Drift-gate fix must go red when a Hard member is removed. **Confirmed**
  (seeded `fsopen` removal → `GATE: FAIL`).
