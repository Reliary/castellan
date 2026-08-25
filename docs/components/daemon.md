# Daemon

One static Rust binary, `castellan-daemon`. Owns the single-writer-per-session correctness boundary. Unix-socket CLI. Orchestrates every component. Fail-closed watchdog.

## Why a daemon (and not spawn-time + timers)

Concurrent sessions writing to `trust.db`, sentinel-vs-undo races, tier-change-mid-session hazards, fleet sync state, the egress proxy's persistent keyring, the honeypot listener's persistent socket — all need a single-writer-per-session and a long-lived process. Spawn-time-only can't do this correctly. The daemon justifies itself on correctness grounds, not convenience.

This mirrors the reliary-agent daemon pattern (TCP line protocol, lock-protected DaemonState) — a proven design in our repos. Castellan uses a unix socket instead of TCP (no network surface) and a richer protocol (newline-delimited JSON, not line commands).

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
| Ingest agent-audit-trail events, tag advisory vs kernel | ledger | enforcement |
| Compute trust scores (single writer to trust.db) | trust | analysis |
| Compute HV fingerprints, sign with ed25519 | hv-radar | analysis |
| Run the bless broker (nonce, dbus, rate limit, biometric) | bless-broker | enforcement |
| Re-run tests independently in a side-scope (commitment #3) | proof-carrying | analysis |
| Generate ProofCertificates from kernel-witnessed state | proof-carrying | analysis |
| Run the harness-state watcher (skein + carrion subprocess) | harness-state-watcher | observation |
| Watchdog: heartbeat loss → restart + auto-freeze (commitment #7) | self | enforcement |

## Unix socket protocol

`/run/user/<uid>/castellan.sock` (or `$XDG_RUNTIME_DIR/castellan.sock`). Newline-delimited JSON. Examples:

```
-> {"op": "spawn", "harness": "claude", "project": "/home/john/Work/foo", "tier": 2}
<- {"ok": true, "session": "uuid", "scope": "castellan-uuid.scope"}
-> {"op": "freeze", "session": "uuid"}
<- {"ok": true, "frozen": true}
-> {"op": "undo", "session": "uuid", "mode": "dry-run"}
<- {"ok": true, "changes": [...]}
-> {"op": "trust", "project": "/home/john/Work/foo", "action": "explain"}
<- {"ok": true, "score": 62, "tier": 2, "events": [...]}
-> {"op": "bless", "action": "request", "want": "egress", "reason": "..."}
<- {"ok": true, "nonce": "..."}
```

## Single-writer-per-session

Each session has a mutex in the daemon's `DaemonState`. Writes to `trust.db`, the event spine, and the blob store are serialized per session. Different sessions run concurrently (different mutexes). This prevents:
- tier-change-mid-session hazards (a tier change during an ongoing proof computation)
- sentinel-vs-undo races (sentinel fires while undo is reverting)
- concurrent proof writes (two proofs for the same session)

## Watchdog (commitment #7)

- systemd `Type=notify` + `WatchdogSec=10s`. The daemon sends `sd_notify(WATCHDOG=1)` every 5s.
- Heartbeat loss → systemd restarts the daemon AND runs `castellan-freeze all` as an `ExecStartPost`/restart hook.
- Landlock + cgroup persist without the daemon (kernel-enforced), so enforcement survives daemon death. Fail-closed: agents are frozen on daemon loss, not freed.

## Lifecycle

- `castellan-daemon start` — daemonizes, opens socket, starts watchers.
- `castellan-daemon stop` — freezes all sessions, closes socket, exits.
- `castellan-daemon status` — socket query: running sessions, trust tiers, daemon tier.
- systemd user unit `castellan-daemon.service` in `~/.config/systemd/user/`.

## Degrade modes

- Daemon absent: `castellan-*` CLI shims print "castellan daemon not running; install castellan or run `castellan-daemon start`." No crash. Omarchy's `cmd-present` philosophy.
- Daemon present but overlayfs unavailable: undo returns "not available (overlayfs required)"; ledger falls back to inotify; envelope still works.
- Daemon present but Landlock unavailable: envelope returns "Landlock ABI insufficient; running in audit-only mode"; launch refuses in enforce mode.

## Antagonism survivors

- A11 (event flooding DoS): closed — per-session rate limit on ingest.
- C7 (daemon crash): closed — watchdog + auto-freeze + kernel persistence.

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
