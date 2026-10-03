# P17 — close the measured /dev and raw-socket holes

**Date:** 2026-10-03 · **Box:** .227 (kernel 7.1.8) · **Precondition:** `test/shell.d/p16-probe.py` landed in this branch (probe-first discipline)

## The problems we measured live

All from inside an enforced session on kernel 7.1.8. Numbers are the battery's result lines, not theory.

- **F-G1** `open("/dev/kvm", O_RDONLY)` → live fd. Harm: `ioctl(fd, KVM_CREATE_VM…)` — but only if ioctls work. (Landlock header: "currently not possible to restrict some file-related actions" — chdir, stat, **open**, ioctl are *not* in the handled list.)
- **F-G2** `open("/dev/ptmx", O_RDWR)` → 9 bytes read. Harm: same, plus `ioctl(TIOCSTI)` could inject keystrokes into another session's terminal.
- **F-G3** `open("/dev/dri/card0", O_RDWR)` → 9 bytes read. Harm: GPU command submission, but only if ioctls work.
- **F-G4** `socket(AF_INET, SOCK_RAW)` succeeds. Harm: craft packets bypassing the egress proxy entirely. (Legit use: nmap-style scanning — that's an operator decision to grant, not default-on.)
- **F-G5** `socket(40/*AF_VSOCK*/)` succeeds → `connect` allowed via the broker's old `Other(_) => Allow` arm. Harm: cross-hypervisor / cross-VM IPC.

## Why Landlock alone can't close these

The kernel header (`include/uapi/linux/landlock.h`, ABI v9 tested 2026-10-03 on .227) says so explicitly:

1. `open(2)` is in the documented *unrestrictable* list. Landlock's fs table gates reads and writes to *paths beneath a rule that allows them* — / is read-only, so device opens fall through to the kernel's device driver, not to Landlock.
2. `scoped` (v6+) covers *signal isolation* and *abstract sockets*, nothing about device files.

The one Landlock lever that IS relevant: `ACCESS_FS_IOCTL_DEV` (bit 15, present in `write_access_for()` since we handle it). It's in `handled_access` and no rule grants it, so ioctls on an opened device fd should be denied by default. **That's a testable property** — and it's P17's first probe, because if it holds, most of the harm disappears with no new code.

## The fix (four phases, in order)

### Phase 0 — revert the dead edit

`crates/castellan-envelope/src/landlock.rs` had an uncommitted edit adding a `scoped` field and v6-scoping. That edit is dead-on-arrival: the `open()` test on .227 proved `scoped` doesn't gate device opens. Reverted before building (Phase 0).

**Gate:** `git diff --check` shows the revert is clean; `cargo check -p castellan-envelope` compiles; no behavior change.

### Phase 1 — Landlock ioctl-dev probe (no fix yet)

Probe on .227:

1. Launch an enforced session.
2. Inside, `open("/dev/kvm", O_RDONLY)` (works — device opens aren't gated).
3. `ioctl(fd, 0xae00)` (`KVM_CREATE_VM` on x86).
4. Also test `/dev/ptmx`'s `TIOCSTI` (`ioctl(fd, TIOCSTI, "x")`) against a file we control (a tmpfs file named `.p17-tty`) to avoid harming any real session.

**Hypothesis:** `ioctl` fails with EPERM because Landlock handles `IOCTL_DEV` and no rule allows it on "/" or on the device path.

**Verdict rule:** if the probe shows ioctl-denied, Phase 2 (tmpfs) is optional — the agent can open but cannot execute the harmful ioctl. If it shows ioctl-allowed, Phase 2 becomes mandatory.

### Phase 2 — tmpfs-over-/dev via privileged launch hop

Only execute if Phase 1 shows ioctl-allowed. The launcher already does a privileged hop (`systemd-run --scope` in `hop_into_user_service()` at cli/main.rs:1252). Extend that hop:

1. Create a private mount namespace inside the transient scope.
2. `mount tmpfs /dev` — the namespace isolates it from the host /dev.
3. Create exactly the devices the session legitimately needs: `null`, `zero`, `full`, `random`, plus a *session-owned* `ptmx` (the pty master fd inherited from the launcher's console).
4. `pivot_root` or `chroot` into the namespace — the agent now sees a curated /dev with no kvm/dri/raw-input.

This mirrors every container runtime (Docker/bubblewrap) and is the pattern P-Phase 2's pidns empirical gate already validated (`CLONE_NEWUSER|CLONE_NEWPID` works unprivileged; mount namespaces are the analogous primitive, gated by `userns` availability).

**Kill gate (pre-frozen):** if any step fails on a fresh launch on .227 (e.g. `pivot_root` EPERM on the transient scope, or the pty fd can't be re-imported), record the failure verbatim and fall back to documenting F-G1–3 as accepted-residual on this kernel — the probe in Phase 1 is the arbiter of how bad that is.

### Phase 3 — socket family deny in the broker

The broker's `evaluate()` arm `Sockaddr::Other(_) => Action::Allow` is what let `AF_VSOCK` and `AF_INET+SOCK_RAW` through. Two changes:

1. In `EgressPolicy`, add `deny_unknown_socket_families: bool = true` (default-on).
2. In `evaluate()`, on `Other(_)` return `Action::Deny` when `deny_unknown_socket_families` — with a small allowlist of kernel-local families (netlink, alg) exempted (these never reach `evaluate` for *creation*, only `connect`, which is what we're denying).

**Negative control:** the P13 probe's own VSOCK test (`connect` → `family 40 unsupported`) must still return EPERM after the change. The P13 suite (`test/shell.d/p13-escape-probe.sh`) covers this via `socket(40)` in its battery.

### Phase 4 — regression gate

1. `test/syscall-drift.sh` + `test/syscall-drift-selftest.sh` — must PASS with 5/5. The `deny_unknown_socket_families` change must not appear as a drift (it's a policy flag, not a syscall).
2. `test/shell.d/p13-escape-probe.sh` — re-run against the fixed binary; F-G1–5 must all now show as PASS or the documented-residual (no FAIL).
3. `test/shell.d/p16-probe.py` — extended: add the Phase-1 ioctl probe, the Phase-2 mount-namespace check, and an AF_INET/raw+AF_VSOCK connect test. Any FAIL = Phase 4a (fix the fix, don't ship the broken one).

## What stays a residual (documented, not fixed)

- `/dev/kvm`, `/dev/ptmx`, `/dev/dri/card0` **opens** — Landlock can't gate these without tmpfs. We're accepting *open* as harmless-on-its-own given ioctls are denied, because the alternative (ptrace `openat` supervisor) has the documented TOCTOU race that the broker design *rejected* at B8.0 for connect (the same race class, now on file paths instead of sockaddrs).
- Raw IPv4 / AF_VSOCK sockets can still be *created* — only `connect` and `bind` are gated. A created socket with no usable address is the same blast radius as a `sleep` syscall; the meaningful hole is `connect`, which Phase 3 closes.

## Non-negotiable constraints

- No new runtime deps (`libc` only), no Python in the trusted path.
- Grammar-free, deterministic, fail-closed.
- Every kernel behavior assertion must come from a test on .227 (we already proved the Landlock header's "currently not possible" claim — Phase 1 tests are the evidence).
- The probe (`test/shell.d/p16-probe.py`) stays in the tree as regression evidence, not as the test harness that gates the fix.

## Verification

- `cargo clippy --workspace --all-targets -- -D warnings` exit 0 (we're already at 0 baseline).
- `cargo test --workspace` keeps passing (currently 211/211 — the new pins must not drop this).
- All six CI workflows stay green.
- New acceptance: extend `test/shell.d/p13-escape-probe.sh`'s probe script to include the device+socket family assertions from P16, so the p13 suite itself catches regressions on the escape battery's findings.

## Out of scope (explicitly)

- LsmAppArmor, SELinux policy edits, or any root-level kernel changes.
- Changing the launcher's cgroup-migration hop behavior (that's where the fix lives, but it's already correct).
- pidns or userns additions (empirically validated additive-isolation but separate phase).
- Anything that makes device access easy for the agent — the policy is "deny by default; bless for legitimate expansions."

## History this builds on

- P13 (2026-09-30): loopback-ssh, deputy sockets, system D-Bus, X11.
- P14 (2026-10-02): mount API (fsopen/fsmount/open_tree/move_mount), pidfd_getfd, process_madvise, process_mrelease, name_to_handle_at, syslog, machine-admin, drift gate.
- P15 (2026-10-03): cross-session canary framing fix, proxy `deny_ports`, marker renames.
- P16 (2026-10-03): breakout battery — the five FAILs this plan closes.

## Execution record (2026-10-03)

### Pre-run corrections (before any fix code — the plan's premises, checked against the tree)

1. **Phase 3 already landed in P14** (`81c1a87`): `deny_unknown_family` exists with
   default true, netlink/ALG exempt, audit off — the plan's F5/fix was stale. What
   was actually missing: live verification on .227 and **unit pins (none existed)**.
2. **F-G4's "raw PASS" was a probe bug**: P16's raw probe used `protocol 0` →
   `EPROTONOSUPPORT` (93), which I recorded as a NOTE and later summarized as a
   pass. Correct protocols (`IPPROTO_RAW` 255, ICMP 1) both return EPERM — the
   kernel-caps path, measured `CapEff=0` on both boxes.
3. **`p16-probe.py` was never in the tree** (plan precondition wrong — it lived in
   `/tmp` only). The battery lands here instead as `test/shell.d/p17-device-sweep.sh`.
4. **Phase 2's trigger was evaluated first, not assumed** — see verdict below.

### Phase 1 verdict (measured, .227 + dev box, negative-controlled)

| Probe | In session | Host (control) | Meaning |
|---|---|---|---|
| kvm `KVM_GET_API_VERSION` ioctl | **EACCES** | OK | Landlock `ACCESS_FS_IOCTL_DEV` (handled since P12, no allow rule) **gates ioctls on in-domain fds** — hypothesis confirmed |
| ptmx write-open / `TIOCGPTN` / `openpty` | **EACCES ×3** | — | write-opens denied (WRITE_FILE); pty allocation chain dead |
| dri write-open + `DRM_IOCTL_VERSION` | **EACCES** | — | same class |
| device **read-opens** (kvm/ptmx/dri) | OK | — | documented residual: open-without-ioctl cannot create a VM, alloc a pty, or submit GPU work |
| `tcgetattr`/`TIOCGWINSZ` on inherited tty fd0 | OK | — | "decided during open" semantics — pre-restrict fds keep ioctl rights (by design; `script`-launched tools keep working) |
| `TIOCSTI` on inherited tty | **EIO** | — | kernel-side dead: `legacy_tiocsti=0` (measured) |
| raw `SOCK_RAW` ×2 / `AF_PACKET` | **EPERM** | EPERM | kernel caps, not ours |
| vsock **create** | OK | — | accepted residual (creation is not trapped, by design) |
| vsock **connect** | **EPERM** | **ECONNRESET** | broker `deny_unknown_family` — the control proves the EPERM is ours (host kernel actually *attempted* the connect) |
| `getifaddrs` (AF_NETLINK) | OK | — | exempt arm keeps name resolution alive |

**Phase 2 (tmpfs-over-/dev) NOT mandatory** — its kill-gate (ioctls work) did not
trigger. Deferred with a standing re-trigger: if a kernel ever lets in-domain device
ioctls through, or `legacy_tiocsti=1` appears on a deployment, Phase 2 becomes the fix.

### Found during execution: the XDG_RUNTIME_DIR × R7-hop interaction

Running p13 on .227 failed with `no session id` where it passed locally. Bisected
live (a/b/c/d): `systemd-run --user` resolves the user bus at
`$XDG_RUNTIME_DIR/bus` and **ignores** `DBUS_SESSION_BUS_ADDRESS` — so p13's F11
socket isolation (fake `XDG_RUNTIME_DIR`) made every `hop_into_user_service()`
fail closed ("Failed to connect to user scope bus") and no session ever started.
Local suites passed only because the dev box's agent sits *inside* `user@.service`
and never hops.

Fixed in the launcher (the correct layer — any custom runtime dir hit this, not
just tests): `systemd-run` is invoked with the real `/run/user/<uid>` for *its* bus
lookup, and the spawned child gets our XDG back via `--setenv=XDG_RUNTIME_DIR=…`
(verified on both boxes: child sees the restored value). The suites' attempted
`DBUS_SESSION_BUS_ADDRESS` export was reverted — the bisect disproved that mechanism.

### Results

- `test/shell.d/p17-device-sweep.sh`: **dev box 17 pass / 0 fail / 3 note** (dri
  skipped — no card0), **.227 19 pass / 0 fail / 2 note** (full set incl. dri).
- Negative control executed: the same probes outside a session behave oppositely
  (kvm ioctl OK, vsock ECONNRESET) — the gates discriminate, not theatre.
- `p13-escape-probe.sh` re-run after the hop fix: **17/0 on .227** (previously
  FAIL=9 with empty verdicts) and **17/0 on the dev box**.
- Workspace 214 (ratchet floor bumped 211 → 214), clippy 0, drift gate PASS,
  selftest 5/5, shellcheck error-level clean on the new suite.
- Unit pins added (the Phase-3 gap): `unknown_family_denied_by_default`,
  `kernel_local_families_allowed`, `audit_policy_waves_unknown_families`.
