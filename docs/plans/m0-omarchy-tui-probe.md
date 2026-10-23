# M0 — Omarchy TUI probe

Date: 2026-10-23. Target: Omarchy 4.0.4 VM (kernel `7.2.5-3-omarchy`, Hyprland), castellan `v0.5.2` installed as a user service. Method: run the real Claude and Codex TUIs in a pty, directly and under `castellan launch`, from both an ssh pty and a real desktop terminal spawned by `uwsm-app`/`xdg-terminal-exec`. Observations only; no product changes.

## Verdict

The pty plumbing holds. Raw mode, alternate screen, mouse-mode enable, bracketed paste, resize (`SIGWINCH`), `Ctrl+C`, exit codes and signal-death codes are byte-identical between baseline and contained runs once the launch happens from a desktop terminal.

The integration is nevertheless **blocked before Milestone 1** by three non-pty issues, all measured below:

1. Omarchy's mise wrapper cannot run inside the envelope: its first act is a write to `~/.local/share/mise`, which the envelope denies.
2. A cold project forces the strict profile (undo + network limited); Claude's login host is not in the derived allowlist, so the real login flow fails with `ERR_PROXY_TUNNEL`.
3. `undo` does not cover harness state. Writes to `~/.claude` and `~/.claude.json` are real, survive `undo`, and the watcher records `harness_drift` but does not quarantine or notify, contrary to `THREAT_MODEL` C3.

The pre-registered kill criterion ("kill the integration if raw mode or state persistence breaks") did **not** fire: raw mode works, and state persistence works. The blockers are policy and packaging, not the terminal.

## What was measured

| Observation | Claude baseline | Claude contained | Codex baseline | Codex contained |
|---|---|---|---|---|
| TUI starts in a desktop pty | yes | yes | yes | yes |
| alternate screen | no (inline UI) | no | yes | yes |
| mouse mode enabled | no | no | yes | yes |
| bracketed paste enabled | yes | yes | yes | yes |
| cursor hidden | yes | yes | yes | yes |
| resize produces output | 4693 B | 4693 B | 814 B | 120 B |
| paste bytes accepted (ISIG mode) | yes | yes | n/a | n/a |
| `Ctrl+C` reaches the process | byte | byte | byte | byte |
| `Ctrl+Z` (ISIG mode) | handler fired | **handler did not fire** | n/a | n/a |
| exit code 0 / 7 / 42 | — | 0 / 7 / 42 | — | — |
| signal death (`SIGTERM`/`SIGKILL`) | — | 143 / 137 | — | — |
| starts from ssh pty (no user scope) | — | fails (`Resource temporarily unavailable`) | — | fails |
| starts from desktop pty (user scope) | — | yes | — | yes |

Agent identity and state:

- Contained sessions run with `Seccomp: 2`, `NoNewPrivs: 1`.
- Agent process group and session equal the launcher's; the agent inherits the session pty (`/dev/pts/*`).
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

Invoking the resolved binary (`mise which claude` → `~/.local/share/mise/installs/claude/latest/claude`) starts the TUI normally. So an Omarchy integration must resolve the mise shim to the real binary and preinstall lazy tools at opt-in time (`mise install --include-lazy`), or the first launch always fails.

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

With `--allow-host platform.claude.com --allow-host claude.ai --allow-host console.anthropic.com`, the TUI reaches the theme picker and onboarding. `brand_hosts("claude")` currently contains only `api.anthropic.com`, so the "zero-config cold start" claim does not hold for Claude's real login path. Codex already includes `auth.openai.com`, so this is Claude-specific, but every provider will need its auth host checked.

### 3. `undo` does not cover harness state, and the watcher does not quarantine (design/policy blocker)

Inside an `--undo` session:

```
ALLOW /home/omarchy/.claude/m0/x
ALLOW /home/omarchy/.claude.json
DENY  /home/omarchy/.pi/m0/x
DENY  /home/omarchy/.codex/m0/x
```

After the session and `castellan undo`, the project write is discarded but `.claude/m0/x` and `.claude/settings.json.m0probe` are still present in the real filesystem. Harness state dirs are write roots by design (the harness must function), and the overlay only covers the project.

The audit watcher did record the drift:

```
{"kind":"harness_drift","path":"  /home/omarchy/.claude/m0/x","verdict":"quarantine"}
{"kind":"harness_drift","path":"  /home/omarchy/.claude/settings.json.m0probe","verdict":"quarantine"}
```

but nothing was quarantined and no user notification was sent. `THREAT_MODEL` C3 says "notify + quarantine pending human approval". The code emits a spine row and logs a line; `castellan-memory` has a `QuarantineFiles` verb that is not wired to this path. For an Omarchy integration this is the important gap: a hook written into `~/.claude/settings.json` is exactly the persistence vector the envelope cannot block, and the claimed detector currently only writes a row.

## Secondary findings

### 4. `Ctrl+Z` is not delivered to the agent

With `SIGTSTP` handled inside the child, baseline delivered the handler; contained did not. The agent shares the supervisor's process group, and terminal-generated `SIGTSTP` is not forwarded. `Ctrl+C` does reach the agent. Job control (`Ctrl+Z`, `fg`, `bg`) therefore diverges for contained agents. For a full-screen TUI this is rarely used, but it is a behavioural difference that should be documented or fixed by forwarding `SIGTSTP` to the agent.

### 5. The desktop freeze oneshot can fail

`castellan-freeze.service` ran while stale drill scopes existed:

```
castellan freeze --daemonless
froze 10 sessions, 3 failed
rc=1
```

The failures are malformed scope directories left by the drill suite: `castellan-drill-<nonce>.scope.scope` — the drill builds a session name ending in `.scope` and the freezer appends another. The targeted session still froze, and thaw restored it, but the unit exits nonzero, so the keybind reports failure. The daemonless path also writes no spine row, so a keybind freeze is invisible to `watch` and to certificates.

### 6. Exit and signal pass-through is correct

`0 → 0`, `7 → 7`, `42 → 42`, `SIGTERM → 143`, `SIGKILL → 137`, under both direct and contained execution.

## What M0 did not prove

- No agent credentials exist in the VM (`~/.claude/.credentials.json`, `~/.codex/auth.json` absent), so no authenticated conversation, history persistence, or token refresh was exercised. History/token files are covered by the state-dir write test, not by a real model turn.
- Mouse events were not observed in either mode (synthetic sequences are not a reliable instrument); the TUIs do enable mouse mode in both.
- Freeze was verified on a ticking shell and via status, not on a live model stream.
- The agent seat PR (#15087) was not involved; this probe is castellan-only.

## Decision

Do not kill the integration: the terminal layer is sound. Do not start Milestone 1 either. The next work, in order, is:

1. Resolve the mise shim and preinstall lazy tools at opt-in; never invoke the wrapper under the envelope.
2. Audit `brand_hosts` per provider against the agent's real login flow (Claude needs its auth host; confirm the rest).
3. Decide the harness-state story: implement the quarantine/notification C3 claims, or narrow the documentation and the integration's promise to "project writes are undoable; harness state is watched, not reverted".
4. Decide the cold-project default: forcing undo + network limits is defensible for a security tool and hostile as a drop-in for Omarchy. Either seed trust explicitly with a visible prompt, or make the first contained launch an explicit "review mode" choice.
5. Fix the drill double-`.scope` naming and make `freeze --daemonless` write a spine row.
6. Forward `SIGTSTP` or document that job control is unavailable.

Reproduction: the probes are the commands in this document run from a real desktop pty (`uwsm-app -- xdg-terminal-exec`) in the Omarchy VM; an ssh pty is not equivalent because the launcher must already be inside `user@.service` to avoid the `systemd-run` hop.
