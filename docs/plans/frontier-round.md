# Frontier Round: R12–R19 + B3/B4 (2026-08-28)

The red/blue/purple exercise (docs/ATTACK_EXERCISE.md) proved the
scripted residuals. This round attacks the surface a FRONTIER agent
would find that our scripts missed: the unauthenticated daemon socket
and the timer-delayed escape. The agent's structural advantages:
read roots = / (it can read our source and docs), same-user socket
access, and the ability to reason about the defense.

## Verified socket surface (read from source, lib.rs)

`handle_conn` (lib.rs:271) parses JSON and dispatches — zero
peer-credential checks in the entire crate (no SO_PEERCRED/ucred
anywhere). The bless nonce is the only authenticated op.

### Agent-reachable, unauthenticated (confirmed)

- **R12 self-keep**: `UndoCommit` (lib.rs:302) — bypasses the human
  gate, farms `clean_session` + `proof_passed`
- **R13 self-thaw**: `Thaw` (lib.rs:296) — reverses the panic button
- **R14 self-spawn**: `Spawn` (lib.rs:291) — enforce/undo/net default
  false (lib.rs:103-107); tier >= 2 means no P6 forcing (lib.rs:1987)
  -> unconfined process
- **R16 direct trust farming**: `TrustSignal` (lib.rs:310, handler
  1042) — apply ANY signal to ANY project: `proof_passed` (+10)
  repeatedly on own project, or `canary_hit` (-50, floor 0) on a
  competitor's project to force-fail-closed
- **R17 evidence poisoning**: `Note` (lib.rs:299) — arbitrary spine
  events; fake `fs_write` records corrupt trace/cert/replay evidence
- **R18 sabotage**: `Kill` (lib.rs:297) on other sessions; `Adopt`
  (lib.rs:294) moves arbitrary pids
- **R19 canary oracle**: `CanaryRegister` (lib.rs:303) returns the
  canary secrets + honeypot port to the caller — the agent learns
  exactly which bytes to strip, no file-reading needed

### Confirmed closed

- `BlessApprove` (lib.rs:316) — nonce is in-memory only, never on
  disk (R2 blue-win, verified live)

### Cosmetic

- Duplicated match arm `"vuln_introduced"` (lib.rs:1051-1052)

## B3 — caller classification (closes R12-R14, R16-R19)

- `SO_PEERCRED` on each connection -> caller pid -> read
  `/proc/<pid>/cgroup` -> **agent** if the pid sits in any
  `user@N.service/castellan-*.scope` session cgroup, **human**
  otherwise. Deterministic, no tokens, no new secrets (the cgroup
  membership IS the identity — the one thing the envelope can't let
  the agent shed).
- Op classes:
  - **agent-allowed**: Status, TrustScore, Cert, Radar,
    MemoryRecall/Status, Siblings, DrillStatus, ChannelsStatus,
    HoneypotPort, UndoDiff, Campaign
  - **human-only**: Spawn, Thaw, Kill, UndoCommit, UndoDiscard,
    TrustSignal, Note, CanaryRegister, BlessApprove/Reject/Request,
    Adopt, DrillRun, ChannelsRun
  - **nonce-authed**: BlessApprove (already)
- Rejection -> `forged_socket_op` trust event (negative) + spine
  record.
- `TrustSignal` additionally: positive signals accepted only from
  internal call paths (keep/cert), i.e., human-only at the socket.
- Kill criterion: cgroup-membership classification must not break
  legitimate flows (drills spawn child sessions inside scopes — the
  drill runner may need an exemption list); document, don't weaken.

## B4 — timer escape (R15, unverified)

- Live-verify the timer gap first: `systemd-run --user
  --on-calendar=...` creates a timer now (MainPID=0 -> skipped by
  both census and B2), fires later -> process outside any envelope,
  outside any window, unattributable.
- Fix: seccomp blocks `timer_create`/`timerfd_create` in enforced
  sessions; B2 sweep extends to timer units created during the window.

## Build order

1. B3 (biggest hole, pure Rust, ~150 lines)
2. R15 live-verify
3. B4
4. Red-team re-run (R12-R19 all must show BLUE)
5. Docs (THREAT_MODEL, ATTACK_EXERCISE, ROADMAP)
