# Post-V3 chapters — plan (2026-09-05)

Where the project stands: the kernel core is validated against every adversary we
could field (R22/R22b, D′-round, B6/B7, 6/6 refusal sweep); the behavioral layer
(trust/campaign/memory/radar) has never seen a real LLM work session; distribution
to omarchy is untouched. This plan covers six chapters plus riders. Each chapter
carries a kill criterion; failure is recorded, not softened.

Ordering: **1 → 2 → 3**, with 4 as a cheap parallel pass, 5 probe-gated, 6 last.

---

## Chapter 1 — B8: the syscall broker (seccomp user-notification)

The one new primitive that closes both structural holes at once:
- **Egress:** Landlock ABI4 net rules are port-scoped and TCP-only (C10a: UDP,
  DNS, unix sockets, inherited fds OPEN). A supervisor outside the seccomp
  filter can read the actual `sockaddr` and decide per destination.
- **T4 escape:** `systemd-run` reaches the user manager over a unix socket that
  neither Landlock nor classic-BPF seccomp can filter. The broker can: unix
  `sockaddr_un` paths are readable from the tracee.

### B8.0 — Probe (gates the whole chapter)
Demonstrate on the live kernels (7.0.3 dev, 7.1.8 on .227):
1. `seccomp(SECCOMP_SET_MODE_FILTER, NEW_LISTENER)` returns a listener fd.
2. Supervisor receives `connect()` notifications and reads the tracee's
   `sockaddr` via `process_vm_readv`.
3. Response with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (allow) and `-EPERM`
   (deny) both take effect.
4. Measured per-notification overhead.

**Kill criterion:** any of 1–3 fails → chapter killed, C10a stays the honest
inventory. **Cost:** one probe binary (`crates/castellan-envelope/examples/`).

### B8.1 — Egress broker
Intercept `socket`/`connect`/`sendto` for `AF_INET`/`AF_INET6`; policy per trust
tier (tier 0–1: honeypot port only; tier 2+: LLM provider + registries + git
hosts; tier 3+: broader; tier 4: per-domain bless). TOCTOU-safe shape: for
`connect`, the supervisor opens the socket itself and injects the fd
(`SECCOMP_IOCTL_NOTIF_ADDFD`) so the validated destination is the connected one.
Canary bytes in outbound buffers still trip the honeypot wire (unchanged).

**Kill criterion:** D6 channel census rerun reads **DENIED** for UDP send, DNS
query, and direct-443; `git`/`npm`/`cargo`/LLM API survive a full dogfood hour
under enforce with zero false blocks.

### B8.2 — systemd socket block (T4 structural close)
Deny `connect` to the user manager's private socket
(`$XDG_RUNTIME_DIR/systemd/private`, `/run/systemd/private`) and the user bus
where it routes to systemd. Harness notification traffic that legitimately uses
the bus must be measured before denying — false-block data decides scope.

**Kill criterion:** `systemd-run --user` fails EPERM from inside an enforced
session; census confirms zero escaped units; the harness still functions
(measured false-block count reported honestly).

### B8.3 — Periodic live census
Today the orphan census runs only at kill. Sweep every N seconds during active
sessions; escaped processes → freeze + spine event immediately.

**Kill criterion:** an injected escape is caught mid-session within 2 sweeps;
zero false positives across the dogfood hour (short-lived subprocesses are the
false-positive risk).

### B8.4 — Composed validation
Full acceptance sweep (p0–p4, p9-stack, v3-corpus) + D6 rerun + THREAT_MODEL
C10/C10a/C25/C26 updates with dated results. Honest residuals recorded.

---

## Chapter 2 — Real-session program (external validity)

The pre-registered V3 criteria were measured on a scripted corpus; the honest
gap is real LLM sessions. The C34 friction fixes (TMPDIR, utime,
CARGO_TARGET_DIR) make dogfooding viable.

### R1 — Dogfood
Launch our own development sessions through `castellan launch` on this repo and
on .227; accumulate ≥40 real spines (kept + reverted). No new code unless the
friction blocks the session — friction findings are first-class deliverables.

### R2 — Re-evaluate on real spines
Rerun the pre-registered criteria: trust kept-vs-reverted marginals (demote to
gate-mechanism if no separation), K2 radar FP on real benign sessions
(advisory-forever already), campaign silence on benign weeks, memory recall
usage. Record everything.

### R3 — Cross-machine
Repeat a smaller batch on .227 (kernel 7.1.8). The only prior cross-kernel data
is the portability pass; this extends it to the behavioral layer.

**Kill criterion:** trust fails to separate on real sessions → demote per
pre-registration. **Honesty:** cooperative agent, single user, small N; no
adversarial claims. Findings are descriptive, not significance claims.

---

## Chapter 3 — Omarchy PR 1 (freeze)

The panic button is built, portable across two kernels, and deliberately
daemon-free. The original purpose of the project.

- C1: `omarchy-freeze` bash shim (cmd-present degradation, `omarchy-` prefix,
  bash 5 conventions), Quickshell QML panel entry, Hyprland keybind Super+Escape.
- C2: discussion issue on basecamp/omarchy per upstream-strategy.md — lead with
  the freeze demo and the crash-diagnosis prompt-injection disclosure, not
  security claims.
- C3: acceptance — 5 concurrent sessions, 3 harness brands, zero self-thaw,
  <50ms, no daemon crash (rerun on 7.0.3 and 7.1.8).

**Kill criterion:** PR rejected/ignored → keep standalone, record the feedback
verbatim; maintainer feedback is incorporated before any PR 2.

---

## Chapter 4 — Formal methods (cheap parallel pass)

### F1 — TLA+ session lifecycle + trust loop
Spec the daemon state machine (spawn/join/freeze/kill/adopt/keep/undo/census)
and the trust tier transitions. Invariants: freeze is terminal until thaw; no
session has a live agent after kill; census covers every escaped unit; tier
follows score except C14 holds; no orphan beyond kill.

**Kill criterion:** TLC finds ≥1 real bug (fix it) or reports none found
(honest, still valuable).

### F2 — Kani/property tests on `castellan-policy`
Prove or find counterexamples for: write-root/hard-deny disjointness, symlink
escape in `contains_path`, deny-list completeness on canonicalized paths.

**Kill criterion:** a counterexample is a real bug — fix it; a passing proof is
recorded with the tool version.

---

## Chapter 5 — Signed evidence / transparency log (probe-gated)

### S0 — Antagonism probe (gates the chapter)
Can a same-uid agent read the daemon's signing key? Read roots are `/`; ptrace
is seccomp-blocked inside sessions but Yama ptrace_scope on the host decides
`/proc/<daemon>/mem`. Probe honestly. If unclosable, the honest claim is
"signatures defend against cross-machine fabrication and post-hoc edits by
other users, not against the agent's own uid."

### S1 — Hash-chained spines
Chain every spine entry (`prev_hash`); the daemon holds the tip in memory and
writes it into the certificate. Tamper detection without a signature.

### S2 — Ed25519 cert signing + Merkle log
Sign each certificate; append leaves to a Merkle log with signed tree heads; a
`castellan verify <cert>` verb. Design-only in C9 becomes real.

**Kill criterion:** a simulated tamper (edited spine, edited cert) is detected;
the S0 probe result is documented either way.

---

## Chapter 6 — Publish

After real-session data: write the composition up honestly (architecture, kill
records — radar demoted, seq-engine killed, R3 found-then-closed, refusal sweep
falsified the weak-prompt hypothesis) and submit for external review. No
savings/security claims beyond the recorded measurements.

---

## Riders (do with the chapter that touches the file)

- **V4:** convert `p8-drills.sh` Koch drills to plain regression tests.
- **V5:** audit-on-change — daemon-touching changes re-run v3-corpus + p0/p1/p2/
  p9-stack before merge (documented as process, then CI if feasible).
- **Doc overstatements (found 2026-09-05):**
  - `egress-proxy.md` claims "loopback only via Landlock TCP rules" — Landlock
    net rules are port-scoped, not address-scoped. Rewrite to the honest
    mechanism once B8.1 exists.
  - `THREAT_MODEL.md` line ~139 says processes can read "the signing key" — C9
    is design-only, no key exists. Correct the status.
