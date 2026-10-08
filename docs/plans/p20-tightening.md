# P20 — Tightening: control-plane survives restart, C43 closed, install hygiene

Frozen plan. Written before any code. Kill gates are pre-registered: a gate
that cannot go red is theatre and is removed, not weakened.

## Findings (two antagonism rounds; F1-F9 = self-attack on PR #22, F10-F17 = attack on this plan)

| # | Finding | Evidence |
|---|---|---|
| F1 | Doctor tautology `live_scopes().is_empty() \|\| true` always PASS | lifecycle.rs:524 |
| F2 | Daemon restart = total control-plane amnesia: registry insert only at spawn, trusted_ttys only at spawn, persist_session lacks launcher_tty/started_at; freeze resolves via registry.ids() | daemon lib.rs:2925/3019/3201/748 |
| F3 | C43 is two links: supervisor dies with tty (no SIGHUP ignore) AND watchdog eprintlns BEFORE the freeze write (EIO panic on closed pty defeats freeze) | CLI main.rs:1094 vs :1101 |
| F4 | service install with manual daemon running → singleton exit 3 → Restart=on-failure restart loop forever | lifecycle.rs install path |
| F5 | preflight-fail / no user manager → unit left enabled half-state | lifecycle.rs install path |
| F6 | Uninstall E2E never ran against a real live session | p18-lifecycle.sh |
| F7 | Unit written to shell XDG_CONFIG_HOME, systemctl --user reads manager env — invisible unit (measured on .227) | p18 run log |
| F8 | broker signal_target_pid `_ => None => Allow` fail-open | broker lib.rs:840,939 |
| F9 | PRE-EXISTING: session-scoped human ops compare caller_tty == launcher_tty (minor only, no inode); BlessApprove same | daemon human_tty_ok:739, bless:704 |
| F10 | Watchdog grace 5s vs restart round-trip (RestartSec=2 + ExecStartPre preflight) — must measure; restart > grace = freeze on every restart | plan-attack |
| F11 | Singleton thrash: unit vs manual daemon bind-fight, no StartLimit* → infinite 2s loop | plan-attack |
| F12 | Daemonless freeze verb surface: enveloped agent blocked by Landlock /sys write (EPERM proven), unconfined same-uid already equal power — safe WITH reasoning in code | plan-attack |
| F13 | Rehydration witness-forgery via state JSON poisoning: state write already equals cgroup write power — accepted residual, documented, NOT hashed | plan-attack |
| F14 | F9 must cover BlessApprove or it is half-closed | plan-attack |
| F15 | Rehydration + panic=abort: notes/audits maps not rehydrated → unwrap risk on keep/undo of rehydrated session → daemon abort loop | plan-attack |
| F16 | Silent skip of corrupt JSON re-creates amnesia — must be counted + doctor drift check | plan-attack |
| F17 | Field units stale on ship — doctor must regenerate-and-diff | plan-attack |

## Fixes

**P20.1 — control-plane survives restart (F2, F9, F14, F15, F16)**
1. persist_session stores launcher_tty, launcher_tty_ino (spawn-time witnessed inode), started_at.
2. Daemon::new() rehydrates: read sessions/*.json → validate session field matches filename (else skip = fail-closed) → build Session → registry insert; re-witness trusted_ttys with the PERSISTED inode (never current — naive re-witness reintroduces recycled-minor attack). Log "N rehydrated, M skipped". Rehydrate AuditWatcher (baseline = restart-time, documented).
3. Session-scoped human ops AND BlessApprove verify inode, not minor alone (closes F9/F14).
4. G1b: no-panic battery — every human op against a rehydrated session returns error/success, never abort.
5. Accepted residual R-POISON: state-dir write by unconfined same-uid = equal power to cgroup write; recorded in THREAT_MODEL, not hashed.

**P20.2 — C43 fully closed (F3, F10, F11)**
6. Supervisor SIG_IGN SIGHUP (keeps TERM); all supervisor-path logging EIO/EPIPE-safe (`let _ = writeln!`); freeze-write BEFORE log.
7. Unit: ExecStopPost=<cli> freeze --daemonless (iterates castellan.slice/*.scope, cgroup.freeze=1; no registry; F12 reasoning in code comment); StartLimitBurst/StartLimitIntervalSec (F11); freeze on ANY stop (fail-closed; systemctl restart freezes fleet, rehydrate+thaw restores — documented).
8. Measure restart round-trip on .227; assert < watchdog grace (G11); adjust grace/RestartSec if needed.

**P20.3 — install hygiene (F4, F5, F7, F1, F8, F17)**
9. service install: refuse if socket answers (F4); post-write `systemctl --user cat` visibility check (F7); enable --now failure → rollback disable+delete (F5); `--no-start` flag for staging.
10. Doctor: falsifiable checks (registry-vs-cgroupfs drift F16; daemon active + sessions on disk + zero scopes = FAIL; unit regenerate-and-diff F17; ExecStart/ExecStopPost paths exist).
11. broker: signal-target None → Deny + pinned test (F8).
12. service logs: journalctl exit 4 (no entries) → success with 0 lines.

**P20.4 — acceptance (.227)**
13. G1 harness: long-lived pty (script + fifo held open, restart from second ssh, freeze inside original script).
14. P18: live-session uninstall e2e (real agent, real overlay); unit content asserts ExecStopPost present.
15. P19 re-run ×2.

## Kill gates (pre-registered)

- G1: restart → status lists session, freeze/thaw from original launcher tty work
- G1b: no-panic battery — zero aborts across freeze/thaw/kill/status/adopt/keep/undo/cert on rehydrated sessions
- G2: corrupt JSON → daemon starts, session skipped AND counted (log line + doctor drift does not false-fail)
- G3: p19 ARM A and ARM B both pass, twice
- G4: systemctl stop → all scopes frozen; start → thaw works (via rehydrate)
- G5: recycled-minor pty and BlessApprove from non-launcher tty → denied
- G6: install with manual daemon → refused, no unit left, retry counter 0
- G7: install with no user manager → nonzero exit, zero leftover artifacts
- G8: planted drift (registry empty + scope present) → doctor FAIL; stale unit (missing ExecStopPost) → doctor FAIL; healthy → PASS
- G9: unknown signal nr → Deny (pinned test)
- G10: live-session uninstall e2e — agent dead, scope gone, overlay gone, keyring gone, unit/socket gone
- G11: measured daemon restart round-trip < watchdog grace

Ratchet: bump floor for new tests. Clippy 0. Leak scan. Both-box suites green.

## Amendment F18 (added after G5's first run failed — 2026-10-08)

G5 (recycled pty minor must not inherit launcher rights) FAILED against
the first P20 build: the inode-bound gate accepted both freezes from a
recycled `/dev/pts/1`. Measurement: devpts assigns a **stable inode per
minor** (`/dev/pts/1` inode 4 across close/reopen on 7.1.8, by
construction) — so B7's "inode defeats tty recycling" premise (2026-09-01)
was inert, and P20's first fix inherited it. The per-open identity that
DOES change is the kernel session id (fresh per `script`/pty invocation;
verified 2360319 vs 2360325).

Fix: witness is now `(tty_nr, launcher_sid)` end to end — CLI sends
`launcher_sid`, spawn persists it, rehydration re-witnesses from it,
session-scoped ops + BlessApprove + global ops compare it,
`caller_still_current` re-verifies it. `tty_inode` removed (dead, false
premise). Post-fix: G5 green (denied), G1 green (original tty still
controls — also proves the hop preserves the session id).

## Execution record (final)

| Gate | Result |
|---|---|
| G1 restart+original-tty control | PASS (p20) |
| G1b no-panic battery | PASS (daemon start timestamp unchanged) |
| G2 corrupt rows skipped+counted | PASS (skipped 2 in journal) |
| G3 p19 ARM A+B ×2 | PASS (5/0, 5/0) |
| G4 stop freezes / start thaws | PASS (ExecStopPost observed) |
| G5 recycled minor denied | **FAIL first (found F18) → PASS after sid fix**; status control still works |
| G6 install vs manual daemon refused | PASS |
| G7 no-manager rollback | PASS (rc≠0, zero artifacts) |
| G8 doctor stale-unit + drift + healthy | PASS |
| G9 unknown signal nr denies | PASS (control: revert → 2 tests red) |
| G10 live-session uninstall e2e | PASS (p18 27/0) |
| G11 restart round-trip | PASS (222-253ms « 10s; note: unit restarts freeze deterministically via ExecStopPost anyway) |

Suites on final binaries: p20 34/0, p18 27/0, p19 5/0 ×2 (.227);
p0 15/0, p11 12/0, p3 5/0, p4 5/0, p6 6/0 (dev box). A/B against 4e504eb
(pre-P20): p11's drive_low/K4 harness ran ON the recycled-minor spoof
(baseline passed only because minor-equality allowed it) — both rewritten
to single-pty invocation; p1/p2/p9 fail IDENTICALLY on baseline and
current (pre-existing environment/harness issues, recorded not chased).
Workspace 230 tests, clippy 0, doc-truth + verb gates green.

Harness bugs found while gating (mine, not product): pkill -f self-match
via ssh one-liner; `printf %s` without newline deadlocking `read` in the
fifo driver; backgrounded fifo write holding the capture pipe (stdio
detach + timeout); stale socket file making `-S` checks lie; session
state accumulating across runs breaking exact-count journal asserts.
