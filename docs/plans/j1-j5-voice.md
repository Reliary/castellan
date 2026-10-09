# J1–J5 — plain-English output and discoverability

Status: **frozen** (2026-10-09). Five phases, one PR each onto `quattro`.
Goal: reduce human cognitive load in everything castellan prints. The
lexicon policy is the **hybrid**: plain-English prose in messages and
help; command names and canonical nouns (session, freeze, keyring,
canary, bless, harness, confined) stay, glossed once in `init` output.

## Frozen register rules

- `castellan: ` prefix, lowercase clause, no trailing period; `—`
  introduces the specific detail.
- Internal phase/finding codes (P8, P9.1, P12, B8, E-e, E-h, F12, N5,
  C43 …) never appear in user-visible strings. Log lines keep event
  names (`egress_inject`, `canary_trip`, `harness_drift`) — those are
  the documented event vocabulary, not codes.
- JSON keys are API and stay (`nonce_hint`, `kill_at`, …); prose calls
  them "approval code", "kill-after".
- Terms glossed once in `init` output: keyring = saved API keys,
  canary = decoy credential, harness = agent type, egress = network
  access, bless = approval, confined = kernel rules active.

## Gate-surface map (every reword names its suite update, same commit)

| String | Greped by | Action |
|---|---|---|
| `forcing enforce+undo+net-restrict` | p6-floor.sh:91 | reword + update grep |
| `trust tier <= 1` | p11:166,236 | reword + update grep |
| `egress restricted` | p11:146,167 | reword + update grep |
| `consumed expansion grant` | p11:231 | reword + update grep |
| `tier floor active` (daemon) | p11:147 fallback | keep or reword together |
| scopes message | p21-desktop:114 | reword + update grep |
| `launched` | p21-desktop:68 | reword to `started` + update that harness |
| `FROZEN` | p21-freeze-ux:159, watch tests | **keep as-is** (the banner word) |
| `HINT` | p21-visibility:108 | → `CODE` + update suite, same commit |
| `session frozen` (notify summary) | p21-visibility:94 | **keep as-is** |
| ` pids  `, `{id}: frozen/thawed`, `WOULD-DENY`, `PASS/FAIL`, `UNREACHABLE`, `castellan bless approve`, session-id regex, README `^castellan status` | many | **must not change** |

## J1 — truth fixes (worst first)

1. Daemon reports `keyring_entries` (u64) in the spawn profile.
2. Launcher line becomes keyring-aware:
   - empty: `castellan: network proxy on 127.0.0.1:N — no saved credentials; your agent's own auth passes through`
   - N>0: `castellan: network proxy on 127.0.0.1:N — injecting {N} saved credential(s) for their hosts; other auth passes through`
3. Daemon log 475: `no keyring at {path} — sessions use their own auth`.
4. README:41 item 10 wording: "With no keyring entries the proxy passes the agent's own auth through; save credentials in the keyring to inject them instead."
5. Gates: p12 gains a message leg both directions (empty keyring vs bound); i0-journey green; doc-truth green.

## J2 — discoverability

- New usage lines: `diff|undo|keep`, `siblings`, `campaign`, `bless show`, and enrich `launch` with `[--net-restrict] [--allow-host HOST]`.
- Extend `test/doc-truth-verbs.py`: also assert every match-arm verb appears in help (currently advertised→arm only). Seeded negative control: delete a usage line → red.

## J3 — restart path

- `castellan service restart` (stop → start; reloads the keyring, which
  loads once at daemon start). Implemented as `systemctl --user restart`
  plus the daemon-process fallback, same shape as stop.
- `init` closing line: `edit these, then: castellan service restart`.
- 3 completion scripts + usage line updated.
- Gate: p18 leg — edit keyring → restart → journal shows
  `keyring loaded (1 credential`.

## J4 — jargon sweep

Message rewrites (final table, frozen):

| Before | After |
|---|---|
| `trust tier <= 1 — forcing enforce+undo+net-restrict (fail-closed)` | `this project is untrusted — strict profile on: writes confined, undo on, network limited` |
| `no trust history — forcing undo for this first session (keep or undo to earn the default)` | `first session here — undo is on; keep or undo once to earn your own default` |
| `egress restricted to loopback + N host(s): ...` | `network: only these hosts are reachable: ...` |
| `egress restricted to loopback only — the agent will not reach its LLM API` | `network: nothing off this machine is reachable — the agent cannot reach its LLM API` |
| `declare one with --allow-host HOST, CASTELLAN_EGRESS_ALLOW_HOSTS, or egress.toml [llm] hosts` | `add it with --allow-host HOST or in egress.toml` |
| `N of these were derived for harness ... (no allowlist declared) — pin them ...` | `N came from {harness}'s default endpoint — make it permanent with --allow-host` |
| `consumed expansion grant(s): egress` | `using your one-shot approval: network access` |
| `daemon set the destination policy (net-restrict)` | `the daemon enabled network limits for this session` |
| `AUDIT MODE — observation only, no containment (--no-enforce)` | `DEBUG MODE — writes are logged, nothing is blocked (--no-enforce)` |
| `... , enforced, undoable launched` | `... started — confined, undo on` |
| `project ... contains $HOME — agent writes reach shell rc/.ssh/.git-hooks (P13 E-h)` | `the project is your home directory — agent writes can reach shell startup files and .ssh keys` |
| `sudo -n succeeds (NOPASSWD) — session uid boundary does not imply unprivileged (P13 E-e)` | `sudo runs without a password — an agent here can become root, which defeats the sandbox` |
| `no session scopes to freeze` / `froze N session scope(s), M failed` | `no running sessions to freeze` / `froze N sessions, M failed` |
| `watching N session(s), M bless request(s) pending` | `watching N sessions — M approval request(s) pending` |
| `watchdog armed (grace 5s)` | `daemon-loss watchdog on` |
| `HINT … APPROVE WITH` (bless show header) | `CODE … APPROVE WITH` |

Help one-liners: strip `(P8)`, `(P9.1, report-only)` → `(report only)`,
`(P12)` → plain, `HV fingerprint + anomaly flag (opt-in)` → `project
fingerprint + anomaly warning (experimental, advisory)`, `permissive-
case delta` → `what a stricter sandbox would have blocked`, etc.

Discipline: for every affected suite, run BEFORE the grep update and
record red, then update the grep and record green. Both recorded in the
PR.

## J5 — glossary + README

- Fix 6 false glossary entries to THREAT_MODEL reality: seccomp (is a
  denylist default-ALLOW; chmod/utime deliberately not blocked), Freezer
  (not daemon-owned; closed by Landlock write denial), Enforce/Audit
  (enforce is the default; audit is debug), Bless broker (drop the
  fp-toggle requirement sentence), Hint plane / Sentinel (advisory
  built state), Watcher (drop "quarantine pending approval" — it emits a
  spine row + log).
- Add: derived host, egress allowlist, pass-through, kill-after.
- README: phase alphabet on the front page → feature names; codes stay
  in ROADMAP.
- Gates: doc-truth strings (`The default is enforced`, `castellan
  status` line, 6 checks) intact; verbs, link, leak checks green.

## Standing gates (every phase)

All suites green on both boxes (p0, b8, p6, p11, p12, p13, p14, p15,
p17, p18, p19, p20, p21-freeze-ux, p21-desktop, p21-visibility,
i0-journey), workspace 243+ tests, clippy `-D warnings`, ratchet bump on
new tests, digit/qualifier/leak checks on touched docs, CI 19/19.

## Order

J1 → J2 → J3 → J4 → J5. One PR per phase onto `quattro`.
