# B6 — Enforcement-first hardening plan

Status: PLANNED (not built). Derived from R22b Part A2 (C29 defensive
audits, D2/D3/D4) and the antagonism pass over the audits' converge-point
fix ("socket auth deny-by-default with daemon-minted tokens").
Branch: p10-b6 (to be created from quattro).

## 0. Origin

Three independent defensive audits (D2, D3, D4 — nube/GLM-5.2, full
source disclosure, zero harm) converged on the same core findings:

| # | Finding | Status |
|---|---------|--------|
| F1 | `classify_caller` fails OPEN (any /proc read failure → Human); D4 won Human dispatch via pure fork/reap race from inside the scope | VERIFIED LIVE |
| F2 | Child-pid cgroup migration (write child pid to `castellan.slice/cgroup.procs`) escapes scope; invisible to kill_all/freeze/census | VERIFIED |
| F3 | C10 escape (systemd-run → app.slice) flips C25 identity to Human; discriminator probe dispatched a human-only op | VERIFIED |
| F4 | `--undo` not interposed: overlay at scratch path, harness chdirs to canonical project; writes land on real fs | VERIFIED |
| F5 | Unwired real credential (`nube-api`) inside the envelope; exfil trips zero detectors | VERIFIED |
| F6 | Freezer ownership separation (commitment #1) not implemented; agent-uid owns its `cgroup.freeze` (self-thaw) | VERIFIED |
| F7 | seccomp is a denylist with default-ALLOW, not the documented allowlist; chmod/chown/utime unblocked | VERIFIED (source) |
| F8 | `bless_request` returns the nonce to the socket caller | VERIFIED |
| F9 | Default launch applies NO envelope (audit mode); no exploit needed | VERIFIED |
| F10 | Docs-vs-code honesty gaps: A3 "closed", A4 "allowlist", B4 "ed25519 fleet signing" (no such code) | VERIFIED |

## 1. Antagonism over the proposed fix — dead bodies

The audits' converge-point fix was "socket auth deny-by-default +
daemon-minted per-session tokens". Antagonism killed or reordered it:

### A1. Tokens-as-stated are underspecified — distribution is
isomorphic to the nonce problem. After `launch`, the CLI execs away;
there is NO human-side process to hold a token. The token cannot live
in agent-visible env (inherited), stdout (same terminal), or any file
(read roots = `/`, same uid). The only agent-unreadable stores are:
daemon memory, the human's brain (per-op nonces — UX disaster), or
KERNEL TTY OWNERSHIP (the /proc/<pid>/stat tty_nr field, settable only
via TIOCSCTTY which fails EPERM/EBUSY on an owned tty). KILLED:
"daemon-minted per-session tokens" as a standalone fix. REPLACED BY:
tty-ownership identity (phase 4) + fail-closed classification.

### A2. Priority inversion — armoring the door while the house is open.
F9: default sessions apply no envelope. Fixing socket identity while
audit-mode is the default is polishing the lock on an open door.
REORDERED: default-flip to enforce (fs) is phase 1.

### A3. The structural knot — same-uid daemon = advisory defender.
D4: daemon SIGKILLable by the agent. D2: /run/user/1001/systemd/private
is agent-uid owned → the agent can dbus StopUnit the daemon; unix
sockets are NOT Landlock-coverable (D6 census: OPEN). Restart=always
bounds downtime; daemon absence is itself observable. Nothing more is
buildable here without a second uid — DOCUMENT AS RESIDUAL. Corollary:
stop armoring the deputy, SHRINK it. TrustSignal/Note/CanaryRegister
have zero legitimate socket callers — delete from dispatch entirely.
The self-applied envelope at exec is the only kernel-hard enforcement;
the daemon is the observer. The architecture already says this; the
daemon just accumulated powers.

### A4. Self-thaw needs one probe before any design: can Landlock deny
writes to cgroupfs? If landlock_add_rule accepts a cgroupfs dir fd,
self-thaw closes under enforce (phase 2 probe). If EINVAL/EXDEV,
self-thaw is unfixable in the unprivileged same-uid design — document
as residual (panic button is advisory against a same-uid adversary in
audit mode; kernel-hard in enforce mode only if the probe passes).

### A5. seccomp "allowlist" claim — a real allowlist for arbitrary
node/python harnesses is high break-risk (probe killed similar bets).
Honest re-label NOW (denylist), add chmod/chown/utime to the denylist.
Allowlist deferred until a harness-scoped probe proves it survivable.

## 2. The plan (ordered)

### Phase 1 — Default-flip to enforce (fs) + seccomp additions + docs re-label

The single highest-value change: no session launches without the fs
envelope.

- `launch` default: `--enforce` becomes the default for ALL tiers.
  A new `--no-enforce` flag (audit mode) exists for debugging only and
  prints a loud banner to stderr: "AUDIT MODE — observation only, no
  containment".
- NET STAYS OPT-IN. Rationale (documented): Landlock ABI4 net rules
  are port-scoped; allowing LLM-API 443 allows exfil-443. Forcing
  --net breaks the agent's core function (model calls). Residual:
  443 exfil under enforce; covered by canary/honeypot detection, not
  prevention. C10a unchanged.
- P6 trust forcing unchanged: tiers 0-1 still force undo+net
  fail-closed (breaking a proven-bad agent's model calls is desired).
- seccomp denylist additions: chmod/fchmod/fchmodat/chown/fchown/
  fchownat/lchown/utime/utimes/utimensat/futimesat.
- Docs re-label (THREAT_MODEL A4, ARCHITECTURE commitment #8): state
  "denylist, default-ALLOW" truthfully; the allowlist claim is removed
  until built and probed.
- Kill criterion: P1 acceptance suite green (envelope tests), P0-P9
  regressions green, and a manual audit-mode launch shows the banner.
  Antagonism check: default-flip must not break the R22b lab runner
  (which passes no flags) — the runner now gets enforce for free.

### Phase 2 — Undo interposition + cgroupfs-Landlock probe

- Probe (30 min, probe-first rule): landlock_add_rule with a cgroupfs
  dir fd — PathBeneath { allowed_access: WRITE_FILE|REMOVE_FILE|
  REMOVE_DIR|MAKE_* }, parent = the session scope dir. Record verdict
  in this doc (pass → implement deny; fail → document residual).
- Undo interposition fix (F4): write roots become the OVERLAY MERGED
  path; the canonical project path is REMOVED from write roots under
  enforce. The launcher chdirs into the merged view (main.rs:463
  already does — the bug is the policy root, policy lib.rs:137).
  Under enforce, Landlock then denies canonical-path writes while
  allowing overlay writes → undo becomes real. Audit mode: still
  bypassable (no Landlock) — acceptable only because phase 1 made
  enforce the default.
- Kill criterion: launch --undo --enforce, write a file in the project,
  verify upper/ contains it and the canonical tree is untouched;
  undo discards it; keep commits it. Extend the p2 acceptance script.

### Phase 3 — Deputy shrink

Pure attack-surface deletion, no UX cost:

- REMOVE from socket dispatch (internal call paths only):
  TrustSignal, Note, CanaryRegister. These have zero legitimate
  socket callers; today they are the R16/R17/R19 attack surface.
- bless_request: the nonce goes to the daemon's journal + a
  `castellan bless show` verb (human terminal), NEVER into the socket
  response. The socket response says "nonce issued — check journal/
  bless show".
- Every rejected human-only op from an Agent-classified caller logs a
  spine event + forged_socket_op trust signal EVEN when the op carries
  no session id (D4 used session-less Thaw{None} precisely because
  unattributed ops leave no trace).
- Kill criterion: red-team R16/R17/R19 scripts now get "unknown op";
  bless flow still completes end-to-end via bless show.

### Phase 4 — Identity: fail-closed classify + tty ownership

For the remaining human-only ops (Thaw, Kill, UndoCommit, UndoDiscard,
Spawn, Adopt, BlessApprove, drills):

- classify_caller: unreadable /proc/<pid>/cgroup → REJECT (fail
  closed). F1 closed.
- Re-verify at dispatch time: pid + /proc/<pid>/stat starttime
  (defends pid reuse), re-read cgroup at op time (defends classify-
  then-escape TOCTOU).
- TTY ownership: at launch, the daemon records the launcher CLI's
  kernel tty_nr (from /proc). Human-only ops require the caller's
  tty_nr to match the session's recorded tty_nr (kernel field; not
  forgeable without TIOCSCTTY, which fails EPERM/EBUSY on owned ttys —
  verified earlier in B5 analysis). Agent harnesses inherit the same
  tty BUT are already excluded by cgroup classification — tty is the
  second factor, cgroup the first.
- Cross-terminal bootstrap: DECISION (b) PENDING — either
  launch-terminal-only (strict, zero new machinery) or bless-bootstrap
  (one nonce approval enrolls a tty for the session's lifetime;
  reuses the existing nonce machinery).
- Kill criterion: D4's race script replayed → all attempts rejected,
  zero dispatches; D3's discriminator probe (escaped unit calling
  bless_reject) → rejected as untrusted caller; legit flow (launch
  from terminal A, keep from terminal A) → works.

### Phase 5 — Lab + docs

- Lab config: allow todowrite for the lab user (D1/D5 aborted on the
  "*"=ask auto-reject).
- No real credentials inside the envelope: move nube-api out of the
  lab home (env-var or a root-owned path), or wire it as a canary.
  The lab must model the deployment rule: any agent-readable
  credential is either canary-wired or absent.
- THREAT_MODEL: A3 re-labelled (self-thaw NOT closed — probe verdict
  recorded); C10×C25 composition documented (D3); new residuals
  section entries: dbus-StopUnit on the daemon (A3 knot), 443-exfil
  under enforce (phase 1 rationale), audit-mode-is-debug-only.
- ARCHITECTURE: commitment #1 marked NOT IMPLEMENTED (with probe
  verdict); commitment #8 re-labelled denylist; ed25519 fleet signing
  removed from docs or marked DESIGN-ONLY (D4-F10).

### Phase 6 — Validation (the stack as a stack)

- Red-team full replay: R1-R21 + NEW entries — R20-D4 (fork/reap
  race), R20-D3 (escaped-unit discriminator), R23 (child-pid
  migration), R24 (dbus-StopUnit daemon kill — expected RED,
  documented residual), R25 (canonical-path write under --undo
  --enforce — must be denied).
- All acceptance suites P0-P9 green.
- D′-round: re-run the defensive-reframe audit (3 sessions) against
  the fixed build. Kill criterion: none of the fixed findings (F1-F4,
  F6-F9) re-verified; NEW findings are possible and get recorded
  honestly — the criterion is "the fixed set stays fixed", not "no
  findings".

## 3. Open decisions (blocking phase 4, non-blocking for 1-3)

- (a) ENFORCE-BY-DEFAULT confirmed by user — changes UX for every
  session including the user's own pi/opencode workflows. [PENDING]
- (b) tty bootstrap vs launch-terminal-only. [PENDING]
- (c) seccomp allowlist: honest-denylist now (this plan) vs probe
  allowlist first. [PENDING — plan assumes honest-denylist]

## 4. Explicitly deferred / killed

- Daemon-minted per-session tokens as a standalone identity fix
  (A1 — distribution is unsolvable without tty/brain/journal root).
- Protecting the daemon from dbus StopUnit same-uid (A3 — needs a
  second uid; unprivileged form factor forbids; Restart=always +
  observability documented).
- Real seccomp allowlist (A5 — deferred until probed).
- Anything that grows the daemon's trusted path. The direction of
  this whole plan is SHRINK: fewer socket ops, fewer powers, more
  kernel.
