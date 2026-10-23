# M0 — Omarchy TUI probe

Date: 2026-10-23. Target: Omarchy 4.0.4 VM (kernel `7.2.5-3-omarchy`, Hyprland), castellan `v0.5.2` installed as a user service. Method: run the real Claude 2.1.309 and Codex 0.163.0 TUIs in a pty, directly and under `castellan launch`, from a real desktop terminal (`uwsm-app` → `xdg-terminal-exec`) and from an ssh session. Observations only; no product changes.

This document was corrected after an antagonism pass re-measured its own claims. The retractions are listed in [Corrections](#corrections) and each corrected value supersedes the original.

## Verdict

The pty layer holds, with one unexplained exception (Codex resize deltas). Raw mode, alternate screen, mouse-mode enable, bracketed paste, `Ctrl+C`, `Ctrl+Z`, exit codes and signal-death codes behave the same under containment as without it. A launch from a desktop terminal and a launch from an ssh session both work, including across the `systemd-run` cgroup hop.

M0 did **not** answer the question the integration depends on: whether a real authenticated agent completes a real task. The VM has no agent credentials, so no model turn was exercised. The login path is also blocked by the egress allowlist (blocker 2). Treat this as *the terminal layer is viable*, not *the integration is viable*.

Three issues block Milestone 1:

1. Omarchy's mise wrapper cannot run inside the envelope: its first act is a write to `~/.local/share/mise`, which the envelope denies.
2. A cold project forces the strict profile (undo + network limited); Claude's login host is not in the derived allowlist, so login fails with `ERR_PROXY_TUNNEL`.
3. `undo` does not cover harness state. Writes to `~/.claude` and `~/.claude.json` are real and survive `undo`. The drift detector runs only when the human kills or undoes a session, never on a natural exit, and it neither quarantines nor notifies, contrary to `THREAT_MODEL` C3.

The pre-registered kill criterion ("kill the integration if raw mode or state persistence breaks") did not fire. That is weaker than it sounds: "state persistence works" is the hole in blocker 3, not a win — the agent works inside the envelope precisely because its state directory is a real, non-undoable write root.

## What was measured

Claude and Codex, baseline vs contained, in a pty. Contained runs were made inside a systemd user scope when the ssh session was outside `user@.service`, which exercises the hop.

| Observation | Claude baseline | Claude contained | Codex baseline | Codex contained |
|---|---|---|---|---|
| TUI starts in a desktop pty | yes | yes | yes | yes |
| starts from an ssh session (hop taken) | — | yes | yes | yes, with `TERM` set |
| alternate screen | no (inline UI) | no | yes | yes |
| mouse mode enabled | no | no | yes | yes |
| bracketed paste enabled | yes | yes | yes | yes |
| cursor hidden | yes | yes | yes | yes |
| resize produces output | 4693 B | 4693 B | 814 B | 120 B (unexplained) |
| paste bytes accepted (ISIG mode) | yes | yes | n/a | n/a |
| `Ctrl+C` reaches the process | SIGINT | SIGINT | byte | byte |
| `Ctrl+Z` (ISIG mode) | SIGTSTP handler fired | SIGTSTP handler fired | n/a | n/a |
| exit code 0 / 7 / 42 | — | 0 / 7 / 42 | — | — |
| signal death (`SIGTERM`/`SIGKILL`) | — | 143 / 137 | — | — |

Agent identity and state:

- Contained sessions run with `Seccomp: 2`, `NoNewPrivs: 1`.
- Agent process group and session equal the launcher's; the agent inherits the session pty (`/dev/pts/*`), `isatty(0)` is true, `tcgetattr` and `TIOCGWINSZ` succeed, `fd0` flags are `0x2` (`O_RDWR`, `O_NONBLOCK` clear).
- `SIGTERM`/`SIGKILL` statuses are translated exactly (`143`, `137`).

## Blockers

### 1. First-run mise install is denied (hard blocker)

`~/.local/bin/claude` is a wrapper:

```bash
export MISE_MINIMUM_RELEASE_AGE=0
mise use -g --quiet "claude" || exit 1
exec mise x "claude" -- "claude" "$@"
```

Under the envelope, `mise use -g` writes `~/.config/mise` and `~/.local/share/mise` and fails:

```
mise ERROR Failed to install aqua:anthropics/claude-code@latest: Permission denied (os error 13)
```

Invoking the resolved binary (`mise which claude` → `~/.local/share/mise/installs/claude/latest/claude`) starts the TUI normally. An Omarchy integration must resolve the mise shim to the real binary and preinstall lazy tools at opt-in time (`mise install --include-lazy`), or the first launch always fails.

### 2. Cold project forces strict profile, and Claude's login host is not allowed (hard blocker)

A project with no trust history launches with:

```
castellan: this project is untrusted — strict profile on: writes confined, undo on, network limited
castellan: network: only these hosts are reachable: api.anthropic.com
```

Claude's login flow contacts `platform.claude.com` and fails:

```
Unable to connect to Anthropic services
Failed to connect to platform.claude.com: ERR_PROXY_TUNNEL
```

With `--allow-host platform.claude.com --allow-host claude.ai --allow-host console.anthropic.com`, the TUI reaches the theme picker and onboarding. `brand_hosts("claude")` contains only `api.anthropic.com`, so the zero-config cold start does not hold for Claude's real login path. Codex already includes `auth.openai.com`.

### 3. Harness-state drift is detected late, reported silently, and never acted on (design/policy blocker)

Inside an `--undo` session on the demo project:

```
ALLOW /home/omarchy/.claude/m0/x
ALLOW /home/omarchy/.claude.json
DENY  /home/omarchy/.pi/m0/x
DENY  /home/omarchy/.codex/m0/x
```

Harness state directories are write roots by design (the harness must function), and the overlay covers only the project. Measured end to end in one pty: a write to `~/.claude/__u3` was real during the session, `castellan undo` discarded the project changes, and the harness-state file **survived**.

The detector is weaker than the documentation implies:

- `end_audit()` — the only place a `harness_drift` row is emitted — is called from exactly two paths, `kill` and `auto_kill`. A session whose agent exits on its own never reaches it.
- Measured on a natural exit: 6 `fs_write` rows, **0 `harness_drift` rows**, both immediately and after `status` pruned the session.
- `response_tier("harness_drift")` is `Silent`, and `castellan watch` polls session status and pending blessings, not the spine. Even when a row is written, no human surface shows it.
- The verdict string is `quarantine`, but nothing moves, deletes, or blocks the file. `castellan-memory` has a `QuarantineFiles` verb that is not wired to this path.

`THREAT_MODEL` C3 says "notify + quarantine pending human approval". What exists is a spine row written at kill time. For an Omarchy integration this matters most: a hook written into `~/.claude/settings.json` is the persistence vector the envelope cannot block, and the claimed detector currently records it only if the human kills the session.

A second defect surfaced while measuring this: each spawned session starts an `audit-watch` thread and takes a baseline, and a natural exit leaves both in place. Five short sessions moved the daemon from 55 to 65 threads (25 → 30 `audit-watch`) and `status` pruning did not reclaim them. A long-lived desktop daemon accumulates one thread and one baseline per session.

## Secondary findings

### 4. Codex fails under the envelope when `TERM` is unset (environment-specific, reproducible)

Measured twice in each arm:

| Condition | Result |
|---|---|
| Codex baseline, `TERM` unset | 3819 B, starts, no error |
| Codex baseline, `TERM=xterm-256color` | 3835 B, starts, no error |
| Codex contained, `TERM` unset | 820 B, no alternate screen, `Error: Resource temporarily unavailable (os error 11)` |
| Codex contained, `TERM=xterm-256color` | 2687 B, alternate screen, mouse mode, no error |
| Claude contained, `TERM` unset | 3321 B, starts normally |

So the `EAGAIN` is not an ssh or hop problem, and not a non-blocking fd. It is Codex's no-`TERM` path hitting something the envelope denies or that the broker interferes with. A desktop terminal always sets `TERM`, so Omarchy launches are unaffected; an agent started by a service or a cron-like context without `TERM` would fail. Claude is unaffected.

Codex's resize delta under containment is 120 B against a baseline of 814 B. Both runs are at the same sign-in screen. This was not investigated; it is recorded as an unexplained difference, not as a breakage.

### 5. The desktop freeze oneshot exits nonzero on a malformed drill scope

`castellan freeze --daemonless` reported `froze 18 sessions, 1 failed` when exactly one `castellan-drill-<nonce>.scope.scope` directory existed (19 directories total). The mechanism is in the code, not inferred: the drill builds a session name that already ends in `.scope` and `create_session` appends another; `freeze_all_local` strips trailing `.scope` matches with `trim_end_matches`, which removes **both**, then `set_freeze` re-adds one, so it writes to `castellan-drill-<nonce>.scope` while the real directory is `…scope.scope` — ENOENT. The earlier `3 failed` reading corresponds to three such directories.

The targeted session still froze and thawed correctly. The consequences are that the keybind unit reports failure, and a daemonless freeze writes no spine row, so a keybind freeze is invisible to `watch` and to certificates.

### 6. Exit and signal pass-through is correct

`0 → 0`, `7 → 7`, `42 → 42`, `SIGTERM → 143`, `SIGKILL → 137`, under both direct and contained execution.

## Corrections

The first version of this document contained five errors. Each was re-measured before being changed.

1. **"Starts from an ssh pty (no user scope): fails (`Resource temporarily unavailable`)" — retracted.** The failing runs had no pty at all: they were `ssh` without `-tt` under `systemd-run --scope`, so stdin was not a terminal. A real ssh pty works: `ssh -tt` lands in `session-7.scope`, the launcher takes the hop, and Claude reaches the theme picker with no tunnel error. Codex over the same path works with `TERM` set. The correct statement is that the hop preserves the controlling terminal (`isatty(0)=true`, flags `0x2`, `TIOCGWINSZ` OK).
2. **"…leaves fd 0 non-blocking" — retracted.** `fd0` flags were `0x2` in the contained agent, in the baseline, and after the hop. `O_NONBLOCK` was never set. The `EAGAIN` came from Codex with `TERM` unset.
3. **"Ctrl+Z handler did not fire under containment" — retracted.** In a clean ISIG test, baseline and contained both delivered `SIGTSTP` to the handler (`GOT_TSTP=True` in both). The earlier `False` was an artifact of the first probe (raw mode, where `^Z` is a byte, not a signal; and in that same test both arms reported the byte).
4. **"byte-identical between baseline and contained" — corrected.** True for Claude (`4693 B` in both). False for Codex resize (`814 B` vs `120 B`), which is now recorded as unexplained rather than as parity.
5. **"The watcher records `harness_drift`" — sharpened.** The watcher takes a baseline at spawn; drift is diffed only inside `end_audit`, which runs only from `kill` and `auto_kill`. A natural exit produces zero drift rows, and the thread and baseline leak. This makes blocker 3 stronger than originally written, not weaker.

## What M0 did not prove

- No agent credentials exist in the VM (`~/.claude/.credentials.json`, `~/.codex/auth.json` absent), so no authenticated conversation, history persistence, or token refresh was exercised. A real turn is the only test that decides viability.
- Mouse events were not observed in either mode (synthetic sequences are not a reliable instrument); the TUIs enable mouse mode in both.
- Freeze was verified on a ticking shell and via status, not on a live model stream.
- The agent seat PR (#15087) was not involved; this probe is castellan-only.

## Decision

Do not kill the integration: the terminal layer is sound and the hop is not a blocker. Do not start Milestone 1 either. The next work, in order:

1. Resolve the mise shim and preinstall lazy tools at opt-in; never invoke the wrapper under the envelope.
2. Audit `brand_hosts` per provider against the agent's real login flow (Claude needs its auth host; confirm the rest), and get real credentials into the VM so M0's actual question can be answered.
3. Fix harness-state drift to match C3 or narrow the claim: emit on every session end (including natural exit), surface it in `watch`, and either quarantine or stop claiming quarantine. Fix the per-session thread and baseline leak at the same time.
4. Decide the cold-project default: forcing undo and network limits is defensible for a security tool and hostile as a drop-in for Omarchy. Either seed trust with a visible prompt, or make the first contained launch an explicit review-mode choice.
5. Fix the double-`.scope` drill naming (and the trim/re-add mismatch in `freeze_all_local`), and make `freeze --daemonless` write a spine row.
6. Handle `TERM` unset under the envelope, or document that agents launched without `TERM` (Codex specifically) fail closed.

Reproduction: the probes are the commands in this document. A desktop-terminal run uses `uwsm-app -- xdg-terminal-exec` inside the guest; an ssh run must use `ssh -tt` or supply a pty, and must set `TERM`, or the result says nothing about terminal behaviour.
