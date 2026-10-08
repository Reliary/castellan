# P21 — usability: cold start, visibility, freeze UX, desktop controls, docs truth

Status: **frozen** (2026-10-08). Goals, in priority order: maximal security, minimal friction, maximal utility. Every phase passes its K-gates on both boxes before the next phase is committed. Per-phase PRs onto `quattro`, starting with 21.1.

## 0. What this phase set is and is not

Usable for a person who is not the author, without weakening a single wall. The critical path becomes:

```
castellan preflight
castellan service install
castellan launch -- claude
```

…zero file edits, no daemon hand-start, no allowlist hand-edit for the default harnesses.

**Not in scope:** read-side confinement (reads are `/` by the C14 launch-path threat model), systemd-run --user hop removal (message polish only; a real fix is a separate phase), fleet sync, GUI tray beyond the Quickshell contrib, macOS/Windows (Landlock/seccomp/cgroup don't exist there).

## 1. Findings that shaped the design (measured in source, 2026-10-08)

- **F1 (keystone).** The P12 egress proxy strips `authorization`/`x-api-key`/`api-key`/`proxy-authorization` on *every* request (`crates/castellan-proxy/src/lib.rs:353`), and the launcher wires `HTTPS_PROXY` into every session that has a proxy (`crates/castellan-cli/src/main.rs:782`) — which is every session, independent of keyring emptiness. With an empty keyring (fresh user), the agent's own credentials are stripped and nothing is injected → provider 401. No suite ever asserted provider reachability (zero `401`/`reach` hits across `test/shell.d/`); the crate only pins strip (`lib.rs:703`). Zero-config cannot exist until strip is conditional.
- **F2.** OAuth-first agents (OAuth at first run: `cursor-agent`, `codex`, `claude` /login) authenticate via body-parameter token exchange — `POST /oauth/token` — which the strip list does not touch. Browser-PKCE is host-side: `xdg-open` either execs the browser (env-proxy ignored by Chromium; system proxy settings only) or goes via the session bus which the broker denies. So browser login works; the CLI's token exchange passes through the MITM with the session CA trusted via `SSL_CERT_FILE`. The strip blocks the *post-login* `Authorization: Bearer` API calls — exactly what conditional strip fixes.
- **F3.** Derivation provenance is clean if and only if sources are: env the launcher shell already holds (`*_BASE_URL`, `OLLAMA_HOST` — in-envelope agents cannot set the launcher's env; `spawn` is human-gated), and tight brand defaults (exact canonical API hosts, no wildcards). `settings.json` and other harness config files live under `.claude`/`write` roots (`policy lib.rs:58`) and are agent-writable → excluded as sources.
- **F4.** The F18/C42 tty witness denies *any* no-tty global op. So a Hyprland keybind/panel cannot use the plain `castellan freeze` path; they must use the P20 daemonless path (`castellan freeze --daemonless`, cgroupfs direct, no daemon, no tty gate — `cli/main.rs:41-44`, `lifecycle.rs:235`). Daemonless ops do not write spine rows (no daemon).
- **F5.** Auto-kill-on-freeze as a default (freezer.md as written) is surprise data loss; it contradicts "maximal utility." Cut. Opt-in only.
- **F6.** Auto-starting a transient daemon from `launch` would bypass the unit's `ExecStopPost` freeze chain (daemon-down → every scope freezes). Message-only instead.

## 2. Security reconciliation

Conditional strip introduces exactly one new capability: an agent holding any credential it read (reads are `/`, the standing residual) can authenticate to an **allowlisted** host with it. Under the tier-0/1 floor the allowlist is the model vendor, so in-session exfil via this path has nowhere to go that the vendor could not already see. A planted canary still detects the exfil *attempt*; the keyring remains strictly stronger for static keys (the real credential never enters the envelope). This trades a small bounded delta for OAuth-first agents being possible at all — without it, the tool is unusable for the most common agents, which is the worst security outcome of all.

New THREAT_MODEL row **F-STRIP** (pass-through residual): mitigations = bind every host that matters in the keyring; canaries detect use; egress floor scopes the destination. New row for the oneshot desktop units: equal-power argument (any same-uid process can already write `cgroup.freeze`; in-envelope agents stay blocked from the bus by the broker; `deny_system_bus` default).

## 3. Phases, gates

### P21.1 — Cold start works

- Conditional strip in `crates/castellan-proxy` (`rewrite_request`): keyring entry for host → strip STRIP-list + inject bound credential (unchanged); no entry → pass the agent's own headers through; `cred=none` spine row already exists.
- Allowlist derivation, applied only when `--net-restrict` and no explicit list: precedence flag > `CASTELLAN_EGRESS_ALLOW_HOSTS` > `egress.toml` `[llm]` > derived(env `*_BASE_URL`/`OLLAMA_HOST` → tight brand defaults, exact hosts only). `CASTELLAN_EGRESS_DEFAULTS=0` disables the brand defaults. Derived set recorded in the launch banner (loud: hosts, source) and as `egress_derived` spine rows (host + source).
- `settings.json` (and any agent-writable config) excluded from derivation; rationale in `crates/castellan-egress-prep/README.md` and THREAT_MODEL.
- Failure-message audit: daemon-down → `castellan service install`; preflight-fail → `castellan doctor`; derivation-empty (restrict, no derive, empty list) → explicit refusal message; unknown-harness → hint.

K1 — Fresh-ish state (empty egress.toml, empty keyring), `launch -- claude` + `nc`/`curl` reaches api.anthropic.com (or the env-derived host) without a config edit; banner names the derived host.
K2 — Explicit `--allow-host` overrides all derivation.
K3 — `CASTELLAN_EGRESS_DEFAULTS=0` → egress stays deny-all under `--net-restrict` (p11/b8 rerun).
K3b — Stub upstream test, both directions: no keyring entry → stub sees the agent's own `Authorization: Bearer TEST` header intact; entry present → stub sees the injected value and the agent's header absent. Asserted in the proxy crate and in p12 (K6 rewritten).
K4 — Derivation unit tests: env URL parse (http/https host, port), brand map exactness (no `*.openai.com`-style wildcards), settings.json exclusion, off-switch, dedupe, precedence order.
K5 — Fake-OAuth flow: body-parameter token exchange (`POST /oauth/token`-style) arrives with body intact; settings.json poison probe leaves the derived list untouched.

### P21.2 — Journey + release e2e

- `test/shell.d/i0-journey.sh`: extracts the README Quickstart fenced block and executes it verbatim against clean state on .227 (PATH-shim for `claude`); legs: preflight → service install → init → launch → status → freeze/thaw → diff → keep → cert → verify → gc → uninstall; plus the conditional-strip pass-through leg (stub upstream) and the state-survival legs (daemon restart → `keep` still works; session kill → `cert` still works).
- Friction metric: wall-clock per phase + user-typed command count, printed, and recorded in the PR description (measured, no invented target).
- `test/release-e2e.sh <tarball>`: untar, verify both binaries + perms + sha256, run the journey from the tarball.

K6 — Journey green from source and from tarball.
K7 — Corrupt one README quickstart line → journey fails (labelled: syntax-level drift protection, not semantic).
K8 — Survival legs green.

### P21.3 — Visibility

- `castellan watch`: polls `status` + active session spines every ~2s; prints transitions (frozen, thawed, canary-trip, bless-pending, auto-kill-if-flag); calls `notify-send` when present (presence-checked path), stdout otherwise; `--user-unit` writes a watcher unit (reusing P20 unit patterns).
- `castellan bless show` gets a pretty table (id, want, reason, session, how to approve/reject) — the pretty view becomes the default for humans.
- `castellan status --json` emits the raw daemon response for scripting (panel).
- `service install` prints the desktop keybind instructions, `castellan watch --user-unit`, and `castellan bless show` hints.

K9 — Mock `notify-send` in PATH records exactly one call on a freeze transition.
K10 — Planted pending bless visible via pretty `bless show`.
K11 — `status --json` parses as JSON and round-trips.

### P21.4 — Freeze UX

- Freeze default: frozen-forever (no timer). `castellan freeze <sid> --kill-after-m=N` opts into a daemon-side timer: frozen-since map → SIGKILL scope pids + scope cleanup + `auto_kill` spine event (with reason) at the deadline; thaw cancels; daemon restart rehydrates frozen state (timer restarts from then — documented in THREAT_MODEL).
- Freeze banner: supervisor prints `FROZEN — thaw with castellan thaw <sid>` (+`, auto-kill in Nd Nh Nm (daemon clock)` when a flag deadline is set) to the session stdout; prints `session ended (auto-killed)` on auto-kill. Written on the freeze transition and on thaw.
- `castellan watch` renders the frozen state and any countdown.

K12 — `--kill-after-m=1` fires: scope dead, spawn row present, event written.
K13 — Thaw before deadline cancels the kill.
K14 — Daemon restart with frozen session → timer still fires (timer-from-rest restart documented).
K15 — Banner text captured on stdout.
K16 — No flag → no timer, ever (negative control: frozen session stays frozen past the window).

### P21.5 — Desktop controls + onboarding

- `service install` writes `castellan-freeze.service` / `castellan-thaw.service` **oneshot** user units that call `castellan freeze --daemonless` / `castellan thaw --daemonless` (no new trust gate; an enveloped agent can't write cgroup state (F12), and an escaped process needs no proxy to do so).
- `contrib/omarchy/`: Hyprland keybind snippet (`bind = SUPER, Escape, exec, systemctl --user start castellan-freeze.service`); minimal Quickshell panel that renders `systemctl --user`/spine state via `castellan status --json`.
- Static shell completions: `castellan completions <bash|zsh|fish>` (hand-written single script, updated when verbs change; verb-gate constants updated).
- `uninstall`/`uninstall` path removes the oneshot units, watcher unit, and completions it installed.

K17 — `systemctl --user start castellan-freeze.service` from a non-tty caller freezes.
K18 — An in-envelope agent still cannot reach systemctl (broker `deny_system_bus` + `deny_deputy_sockets`; p13 rerun).
K19 — Thaw unit restores the session.
K20 — p20 G5 (devpts/fresh-pty harness) rerun unchanged → still green.
K21 — `bash -n`, `zsh -n`, `fish -n` accept the completion scripts; `--help` for each verb is complete.
K22 — Uninstall removes all installed artifacts (dry run asserted on a scratch runtime).

### P21.6 — Docs truth

- `docs/components/freezer.md`: desktop section split into **built here / contrib / designed-not-built** (QML toggle, top-bar icon, fp-toggle biometric, double-confirm thaw are the latter).
- `docs/components/egress-proxy.md`: strip wording becomes conditional ("no keyring entry for the host: the agent's own auth passes through").
- `docs/components/daemon.md`: allowlist-source precedence documented.
- `docs/ROADMAP.md`: Phase 0 gets a **Status** line (core built; QML/keybind/fp-toggle are contrib/design).
- `docs/THREAT_MODEL.md`: F-STRIP row; oneshot equal-power row; daemonless-ops-write-no-spine-rows note.

K23 — Every freezer.md claim maps to a file path or a "designed" label; doc-truth + link + leak gates green; the README verbs/preflight counts updated in the same commit as any verb addition.

## 4. Standing gates (every phase)

All existing suites green (p0, b8(19/19), p11, p12(25/25), p13, p14, p15, p17, p18, p19×2, p20(34/0)), workspace 230+ tests, clippy `-D warnings` (rustc 1.99), test-ratchet floor ≥ 230 (bumped on new test additions), digit/qualifier/leak checks on any touched docs, CI 19/19 on both boxes (dev + .227).

## 5. Order and PRs

21.1 → 21.2 → 21.3 → 21.4 → 21.5 → 21.6; one PR per phase onto `quattro`. 21.1 is the critical path (without it, zero-config cannot work); 21.2 is the regression net for everything after it.
