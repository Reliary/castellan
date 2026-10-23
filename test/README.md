# Test suites

`test/run-all.sh` runs the wired-system suites in the execution context each
one requires and prints one table. The unit tests (`cargo test --workspace`)
are separate and run in CI.

```sh
cargo build --release --workspace
test/run-all.sh              # green bar: 23 suites
test/run-all.sh --local      # plus machine-local suites
test/run-all.sh --only p1,p2 # subset by name prefix
test/run-all.sh --list       # manifest with contexts
```

`CASTELLAN_BIN_DIR` points the suite at any directory holding `castellan` and
`castellan-daemon` (for example an extracted release tarball), so the battery
can test shipped artifacts instead of a local build.

## Contexts

| Context | Meaning |
|---------|---------|
| `bare` | launches nothing; runs directly |
| `wrap-pty` | launches sessions but makes no pty itself; the runner must supply one (`script -qec`) |
| `self-pty` | creates its own ptys internally; must **not** be nested, or the tty witness stops matching |
| `local` | needs machine-local data or binaries; excluded from the green bar |

All suites need a real user cgroup slice (`user@<uid>.service`) and a Linux
kernel with Landlock ABI 4+. They do not run on macOS or Windows, and they do
not run in a GitHub-hosted runner (no logind user session).

## Matrix

| Suite | Context | What it proves |
|-------|---------|----------------|
| b8-broker | wrap-pty | seccomp user-notification broker blocks the systemd routes and destination-scoped egress |
| b8-sweep | wrap-pty | periodic escape-shape sweep, no over-block |
| ch5-proof | self-pty | hash-chained spines and ed25519 certificate signing |
| i0-journey | self-pty | the README quickstart executes verbatim |
| p0-freeze | self-pty | freeze/thaw semantics on real processes |
| p1-envelope | wrap-pty | workspace writes allowed, home writes denied, audit classifies |
| p11-tier-egress | self-pty | tier-gated egress floor |
| p12-proxy | self-pty | per-session egress proxy, conditional auth strip, credential injection |
| p13-escape-probe | self-pty | attempt-only escape battery (ssh, deputy sockets, D-Bus, X11) |
| p14-esoteric | self-pty | mount API, pidfd, socket families, unknown-family default-deny |
| p15-fingerprint-framing | self-pty | canary trip attribution and cross-session framing |
| p17-device-sweep | self-pty | device opens, ioctl denial, socket-family denial |
| p18-lifecycle | wrap-pty | install / service / uninstall / gc |
| p19-watchdog-survival | bare | supervisor watchdog on daemon loss, including an orphaned agent |
| p2-undo | wrap-pty | overlay undo: diff, discard, keep |
| p20-restart | wrap-pty | state rehydration across daemon restarts |
| p21-desktop | wrap-pty | freeze/thaw oneshot units and desktop controls |
| p21-freeze-ux | wrap-pty | opt-in auto-kill timer and the daemon-written freeze banner |
| p21-visibility | wrap-pty | watch transitions, notify, status --json, bless show |
| p3-trust | bare | trust tier ordering against revert outcomes |
| p4-certificates | bare | certificate classification on known-bad/good corpora |
| p6-floor | self-pty | tier floor confines and gates egress without deadlock |
| p9-policycheck | wrap-pty | policy replay flags false-new-denies on a self-built fixture |
| p9-stack | local | composed stack: undo, proof, artifact scan, canaries, trace |
| p8-drills | local | live-fire drills; needs a `--features drills` build |
| v3-corpus | local | pre-registered V3 corpus evaluation |

## Local-only suites

`p9-stack` needs `relay-vuln` and `stria` binaries (`RELAY_VULN_CMD`,
`STRIA_BIN`). `p8-drills` needs a drills build and refuses a release build.
`v3-corpus` drives real model sessions through the stack and needs the
session corpus. None are part of the green bar, and none are counted as
passing when they are skipped.

## Last measured

Green bar 23/23 on 2026-10-09, kernel 7.0.3 (dev box), from `target/release`.
The battery is not yet in CI: it needs a self-hosted runner with a real user
session.
