# Daemon

One static Rust binary, `castellan-daemon`. Owns the single-writer-per-session correctness boundary. Unix-socket CLI. Orchestrates every component. Fail-closed watchdog.

## Why a daemon (and not spawn-time + timers)

Concurrent sessions writing to `trust.db`, sentinel-vs-undo races, tier-change-mid-session hazards, fleet sync state, the egress proxy's persistent keyring, the honeypot listener's persistent socket: all need a single-writer-per-session and a long-lived process. Spawn-time-only can't do this correctly. The daemon justifies itself on correctness grounds, not convenience.

This mirrors the reliary-agent daemon pattern (TCP line protocol, lock-protected DaemonState), a proven design in our repos. Castellan uses a unix socket instead of TCP (no network surface) and a richer protocol (newline-delimited JSON, not line commands).

## Responsibilities

| Responsibility | Component | Plane |
|---|---|---|
| Mint Landlock + seccomp rulesets at spawn | envelope | enforcement |
| Create systemd user scopes (or cgroup fallback) | freezer | enforcement |
| Own cgroup.freeze files (commitment #1) | freezer | enforcement |
| Set up overlayfs in user namespace | undo | enforcement |
| Run inotify watchers on allowed paths (fallback) | ledger | enforcement |
| Run the egress proxy (keyring, allowlist, injection) | egress-proxy | enforcement |
| Run the honeypot listener | canary-credentials | enforcement |
| Ingest audit-chain events, tag advisory vs kernel | ledger | enforcement |
| Compute trust scores (single writer to trust.db) | trust | analysis |
| Compute HV fingerprints, sign with ed25519 | hv-radar | analysis |
| Run the bless broker (nonce, dbus, rate limit, biometric) | bless-broker | enforcement |
| Re-run tests independently in a side-scope (commitment #3) | proof-carrying | analysis |
| Generate ProofCertificates from kernel-witnessed state | proof-carrying | analysis |
| Run the harness-state watcher (skein + carrion crates) | harness-state-watcher | observation |
| Watchdog: heartbeat loss → restart + auto-freeze (commitment #7) | self | enforcement |

## Unix socket protocol

`/run/user/<uid>/castellan.sock` (or `$XDG_RUNTIME_DIR/castellan.sock`). Newline-delimited JSON. Examples:

```
-> {"op": "spawn", "harness": "claude", "project": "~/Work/foo", "tier": 2}
<- {"ok": true, "session": "uuid", "scope": "castellan-uuid.scope"}
-> {"op": "freeze", "session": "uuid"}
<- {"ok": true, "frozen": true}
-> {"op": "undo", "session": "uuid", "mode": "dry-run"}
<- {"ok": true, "changes": [...]}
-> {"op": "trust", "project": "~/Work/foo", "action": "explain"}
<- {"ok": true, "score": 62, "tier": 2, "events": [...]}
-> {"op": "bless", "action": "request", "want": "egress", "reason": "..."}
<- {"ok": true, "nonce": "..."}
```

## Single-writer-per-session

Each session has a mutex in the daemon's `DaemonState`. Writes to `trust.db`, the event spine, and the blob store are serialized per session. Different sessions run concurrently (different mutexes). This prevents:
- tier-change-mid-session hazards (a tier change during an ongoing proof computation)
- sentinel-vs-undo races (sentinel fires while undo is reverting)
- concurrent proof writes (two proofs for the same session)

## Watchdog (commitment #7) — built, but in the launcher, not the daemon

The fail-closed-on-daemon-loss property is real and lives in the **launcher supervisor**,
not in the daemon (`crates/castellan-cli/src/main.rs`): a detached thread probes the
daemon socket every 2s and, after a 5s grace with the daemon unreachable, freezes the
session through the pre-opened scope fd (`openat`→`/proc/self/fd/<n>/cgroup.freeze`;
fds survive the mount-ns switch), falling back to `CgroupRoot::detect()`. This is the
mechanism behind "agents are frozen on daemon loss, not freed" (**for sessions started
with `castellan launch`**.

Limits, measured against the code rather than the design:

- **Only `castellan launch` sessions get a watchdog.** `castellan spawn` and `castellan
  adopt` create a session with no supervisor, so a daemon loss leaves them un-frozen.
- **The supervisor is the launcher's child — P20 closed the gap this
  created (THREAT_MODEL C43, found and fixed 2026-10-08).** The original
  measurement: a terminal closing killed the supervisor (SIGHUP), and
  then `eprintln` to the dead pty would panic it anyway (`panic=abort`
  would have taken the watchdog down mid-freeze). The fix has three
  parts, all in the supervisor branch: SIGHUP is ignored **after**
  `spawn_broker` forked (the agent child keeps default SIGHUP, so a normal
  agent still dies with its terminal), stderr is redirected to
  `sessions/<id>/supervisor.log` right after the launch banner (a closed
  pty can no longer panic the process; the freeze record now survives
  the terminal too), and the watchdog writes `cgroup.freeze` **before**
  it logs (a failing log must never preempt the action it describes).
  Verified live on .227 by `test/shell.d/p19-watchdog-survival.sh`,
  run twice: ARM A (terminal intact, daemon killed) and ARM B
  (SIGHUP-ignoring agent, terminal closed, orphaned, daemon killed)
  both freeze (5/0, 5/0). Residual: if the state dir is unwritable AND
  the pty is dead, the log redirect fails and a later print can still
  panic (documented at the redirect site).
- Landlock + cgroup membership persist without the daemon (kernel-enforced), so
  *enforcement* survives daemon death regardless; only the active freeze action needs
  the watchdog.

Design target, **not built**: daemon-side `Type=notify` + `WatchdogSec=10s` with
`sd_notify(WATCHDOG=1)`. No `sd_notify`, `NOTIFY_SOCKET`, or `WatchdogSec` exists in the
tree. If it is built, it complements the launcher watchdog; it does not replace it.

## Lifecycle

- `castellan-daemon` — starts the daemon in the **foreground**; opens the unix socket
  and starts watchers. It does **not** daemonize (no fork/setsid/pidfile). Run it under
  the user manager or a terminal supervisor.
- `castellan service install` — writes `~/.config/systemd/user/castellan.service`
  (`Type=simple`, `ExecStartPre=<cli> preflight`, `Restart=on-failure`,
  `NoNewPrivileges=yes`), then `systemctl --user enable --now`. `service stop`,
  `service status`, `service logs [-f]` round it out. `--skip-preflight` omits the
  `ExecStartPre` check (for boxes where preflight is known to warn).
- `castellan uninstall --yes` — the destructive inverse: stop+disable+remove the unit,
  kill the daemon, tear down every session scope and `castellan.slice`, remove the
  socket, then delete state (`--keep-data` to keep it) and config incl. the keyring
  (`--keep-config` to keep it). Deletion is chmod-aware: session `overlay/work/work`
  dirs are mode `000` and a naive `rm -rf` fails on the first one (verified).
- `castellan gc [--keep-last N] [--older-than DAYS] --yes` — prunes old session state,
  skipping any session with a live scope. There was previously no retention at all.
- `castellan init` — scaffolds `keyring.toml` and `egress.toml`. `castellan doctor`
  reports daemon/socket/service/keyring/session health in one place.
- The CLI connects to the daemon's unix socket; a missing daemon is a hard error
  (`castellan daemon not reachable ...`), not auto-started.

## Degrade modes

- Daemon absent: the CLI prints "castellan daemon not reachable at <socket>: ..." then "start it with: castellan-daemon". No crash.
- Daemon present but overlayfs unavailable: undo returns "not available (overlayfs required)"; ledger falls back to inotify; envelope still works.
- Daemon present but Landlock unavailable: envelope returns "Landlock ABI insufficient; running in audit-only mode"; launch refuses in enforce mode.

## Antagonism survivors

- A11 (event flooding DoS): closed — per-session rate limit on ingest.
- C7 (daemon crash): **partly closed** — the launcher supervisor watchdog freezes
  `castellan launch` sessions on daemon loss (see Watchdog above); `spawn`/`adopt`
  sessions and supervisor-death-before-daemon-loss are open. Kernel enforcement
  (Landlock + cgroup membership) persists either way.

## Dependencies

- All `castellan-*` crates.
- `zbus` (systemd, dbus).
- `nix` (syscalls).
- `rusqlite` (bundled, trust.db, blob index, HV store).
- `ed25519-dalek` (signing).
- `mimalloc` (global allocator).
- systemd user manager (assumed present on Omarchy; degrade tier 3 if absent).

## Status

Greenfield. Pattern reused from reliary-agent daemon. P0 skeleton (scope + freezer) → P1 (envelope + ledger) → P2 (undo + canary + egress v0) → P3 (trust + bless) → P4 (proofs + replay) → P5 (radar + sentinel).
