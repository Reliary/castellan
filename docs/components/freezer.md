# Freezer

The panic button. Freezes every running agent session at the kernel level via cgroup v2 freezer. Frozen processes cannot run, cannot handle signals, cannot make progress until thawed.

## Mechanism

cgroup v2 exposes a `cgroup.freeze` file per cgroup. Writing `1` freezes all processes in the cgroup. Writing `0` thaws. The freeze is kernel-instant: frozen processes are descheduled and cannot run even to handle a signal. This is stronger than SIGSTOP (which can race with signal handlers).

Each castellan session runs in a systemd user scope `castellan-<uuid>.scope`. The freezer file lives at `/sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/castellan.slice/<uuid>.scope/cgroup.freeze`.

## The critical-path issue (commitment #1)

In a systemd user scope, the user owns the cgroup files. An agent running as the user can write `cgroup.freeze=0` to thaw itself. **If the agent can self-thaw, the panic button is theater.**

How castellan closes it: the envelope denies the agent write access to cgroupfs (Landlock write roots exclude `/sys`; measured live, `EPERM` on a direct `cgroup.freeze` write from inside an enforced session). The daemon is the only path that freezes or thaws sessions it manages, and agent callers are refused at the socket (`agent_allowed` in `crates/castellan-daemon/src/lib.rs`). An *unconfined* same-uid process outside any session can still write `cgroup.freeze` — it is the user's own kernel state and the user's own machine; that is the trust model, not a gap (see THREAT_MODEL C14 for the launch-path boundary).

Earlier drafts of this doc described a `Delegate=yes` / setuid-helper / SIGSTOP degrade tier ladder with a `castellan-freezer detect-delegation` probe. None of that was built; the closure above is what shipped.

## Freeze lifetime

**Default: freeze is indefinite.** Nothing kills a frozen session unless the operator asked for it — a countdown to kill is surprise data loss.

**Opt-in auto-kill:** `castellan freeze <sid> --kill-after-m N` schedules a SIGKILL of the frozen scope N minutes out (P21.4). The deadline is absolute, persisted on the session row, and survives a daemon restart. Thawing before the deadline cancels it. On firing, the daemon SIGKILLs the scope, removes it, and writes an `auto_kill` spine row. No flag means no timer, ever.

## The FROZEN banner

When a session freezes, the daemon writes `FROZEN — thaw with castellan thaw <sid>` (plus `(auto-kill in M:SS)` when a deadline is set) to the session's pty, `wall`-style. The daemon must do it: the supervisor and its threads run *inside* the session scope, and a frozen cgroup deschedules every process in it, so nothing in-scope can print while frozen. Found live on the exercise box; the in-scope banner thread never emitted a line.

## Surfaces — built here

- **Daemon watchdog (launcher):** daemon heartbeat loss → after a 5s grace the launcher supervisor freezes its session via the pre-opened scope fd. For sessions started with `castellan launch` (THREAT_MODEL C43 covers the terminal-death case, closed in P20).
- **`ExecStopPost` freeze-all:** the daemon unit freezes every session scope on any unit stop (`castellan freeze --daemonless`, daemonless cgroupfs path).
- **`castellan freeze --daemonless` / `thaw --daemonless`:** cgroupfs direct, no daemon, no tty gate. The daemonless verbs cannot freeze from inside an envelope (Landlock denies cgroupfs access; an enveloped caller sees no scopes at all — K18 in `test/shell.d/p21-desktop.sh`).
- **Desktop oneshot units:** `castellan-freeze.service` / `castellan-thaw.service` (written by `castellan service install`) run the daemonless verbs, so a Hyprland keybind or a panel button can freeze/thaw with no daemon round trip.
- **`castellan watch`:** follows freeze/bless transitions, desktop notification when `notify-send` is present, stdout otherwise (P21.3).
- **Sentinel auto-freeze:** deterministic canary-credential hits freeze the attributed session (P15: sender attribution at accept time; trip → freeze + spine row).

## Surfaces — contrib (in `contrib/omarchy/`)

- **Hyprland global keybind:** Super+Escape → `systemctl --user start castellan-freeze.service` (freeze), Super+Shift+Escape → `castellan-thaw.service`. Snippet in `contrib/omarchy/README.md`.
- **Quickshell panel:** `contrib/omarchy/panel.qml` reads `castellan status --json` and offers a freeze/thaw toggle.

## Surfaces — designed, not built

- **fp-toggle biometric thaw** (fingerprint reader gate on thawing).
- **Thaw double-confirm** (anti-fatfinger re-press).
- **Lock-screen freeze** (`omarchy toggle freeze-on-lock`).
- **Terminal status-line integration** beyond the banner line above (a persistent status segment managed by the terminal).

## Antagonism survivors

- A3 (self-thaw): closed by the envelope's cgroupfs write denial plus the daemon's agent-caller refusal.
- A11 (event flooding DoS): closed: freezer is a single file write, not event-driven.
- C7 (daemon crash): closed by the launcher watchdog plus the unit's `ExecStopPost` freeze-all; freeze is kernel state and persists without the daemon.

## Dependencies

- `castellan-core` (SessionId)
- `castellan-freezer` (cgroup file I/O, scope lifecycle)
- `castellan-daemon` (scope ownership, deadline timer, banner writer)
- `castellan-cli` (launch supervisor watchdog, daemonless verbs, oneshot units)

## Status

Built (P0 substrate through P21.4/P21.5). The QML toggle, keybind, and terminal banner ship as contrib/desktop artifacts described above; biometric and lock-screen integration remain designed. See THREAT_MODEL C42 (tty witness), C43 (supervisor survival, closed), and P21.4/P21.5 in docs/plans/p21-usability.md.
