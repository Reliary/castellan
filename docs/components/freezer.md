# Freezer

The panic button. Freezes every running agent session at the kernel level via cgroup v2 freezer. Frozen processes cannot run, cannot handle signals, cannot make progress — until thawed.

## Mechanism

cgroup v2 exposes a `cgroup.freeze` file per cgroup. Writing `1` freezes all processes in the cgroup. Writing `0` thaws. The freeze is kernel-instant — frozen processes are descheduled and cannot run even to handle a signal. This is stronger than SIGSTOP (which can race with signal handlers).

Each castellan session runs in a systemd user scope `castellan-<uuid>.scope`. The freezer file lives at `/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/castellan-<uuid>.scope/cgroup.freeze`.

## The critical-path issue (commitment #1)

In a systemd user scope, the user owns the cgroup files. An agent running as the user can write `cgroup.freeze=0` to thaw itself. **If the agent can self-thaw, the panic button is theater.**

Solutions, in order of preference:

1. **systemd cgroup delegation to the daemon.** `StartTransientUnit` with `Delegate=yes` and the daemon as the managing process. The daemon owns the freezer file; the agent process does not have write access. This is the clean solution and works on any systemd user manager.
2. **setuid thaw helper.** A tiny setuid-root binary `castellan-thaw` that writes the freezer file on behalf of the daemon. The agent cannot call it directly (it requires a daemon-issued nonce). Fallback when delegation is unavailable.
3. **PID-tracking fallback (degrade tier 3).** No cgroup delegation → fall back to SIGSTOP on all PIDs in the session. Races with signal handlers acknowledged. Documented as a degraded mode.

Detection: `castellan-freezer detect-delegation` returns which tier is available. The daemon refuses to enter enforce mode unless tier 1 or 2 is available.

## Time-bounded freeze (auto-escalate to kill)

A frozen agent holds terminal PTYs and cgroup resources. A user who freezes and walks away leaves the system in a stuck state. Mitigation:

- **5-minute timeout:** if no human action within 5 minutes of freezing, the daemon auto-escalates from freeze to kill (SIGKILL all PIDs in the scope, then clean up the scope).
- **Notification:** the freeze notification includes a countdown and "Review / Thaw / Kill now" actions.
- **Thaw requires deliberate double-confirm:** pressing Super+Escape again, or clicking the notification's Thaw button. Anti-fatfinger.

## Surfaces

- **Hyprland global keybind:** Super+Escape → `castellan-freeze toggle` (freezes all sessions if any running, thaws if frozen).
- **Top-bar icon in the Omarchy agents panel:** red when any session is frozen, click to thaw (prompts fp-toggle biometric if available), right-click for session list.
- **Sentinel auto-freeze:** only deterministic canary-credential hits (see canary-credentials.md). Sentinel regime detection does NOT auto-freeze (D4).
- **Daemon watchdog (commitment #7):** daemon heartbeat loss → systemd restarts daemon AND auto-freezes all scopes. Fail-closed.
- **Lock-screen freeze (optional Omarchy setting):** `omarchy toggle freeze-on-lock` freezes agents when the screen locks. Cute, very DHH.

## Terminal-cooperative status line

When frozen, the agent's terminal shows a status line: `FROZEN — Super+Escape to thaw, auto-kill in 4:32`. Implemented via the terminal's existing status-line mechanism (omarchy terminals support this). Non-frozen sessions show nothing.

## fp-toggle biometric thaw

Thawing requires fp-toggle biometric if a fingerprint reader is present. `castellan-freeze thaw` calls `fp-toggle-internal verify` (already built and shipped). If no reader, falls back to a manual Y/N prompt via the notification.

## Antagonism survivors

- A3 (self-thaw): closed by commitment #1 (daemon owns freezer).
- A11 (event flooding DoS): closed — freezer is a single file write, not event-driven.
- C7 (daemon crash): closed by commitment #7 — freeze persists without daemon (kernel-enforced), watchdog restarts daemon and re-freezes on heartbeat loss.

## Dependencies

- `castellan-core` (SessionId)
- `castellan-daemon` (scope ownership, watchdog)
- `nix` crate (cgroup file I/O)
- `zbus` (systemd `StartTransientUnit`, `Delegate=yes`)
- Owned primitive: `fp-toggle` (BUILT, shipped) for biometric thaw.

## Status

Greenfield (scope delegation + freezer ownership). P0 critical-path. Smallest PR to upstream omarchy.
