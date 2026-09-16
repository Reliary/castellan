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

### B8.1 RESULTS (2026-09-05) — plan revised by measurement

The ADDFD connect shape above is **falsified**. `SECCOMP_IOCTL_NOTIF_ADDFD` with
`ADDFD_FLAG_SEND` returns the injected fd *number* as the tracee's `connect()`
return value and leaves the tracee's **own** socket fd unconnected. Any program
that ignores `connect`'s return and keeps writing to its fd then gets `ENOTCONN`
— i.e. essentially all of them. Reproduced in
`crates/castellan-broker/examples/broker_fd_identity.rs` (result:
`FD-IDENTITY-BROKEN` before the fix). ADDFD suits open-style syscalls that
*return* a new fd; `connect` is not one.

Revised allow path: **`CONTINUE`**. The kernel re-reads arguments from tracee
memory, so a racing thread that rewrites the `sockaddr` after our check can
redirect an allowed connect. This is the kernel's documented limitation and it
is stated plainly in the crate docs: the broker is a **detection and denial
layer against a non-racing agent, not a hard boundary against a malicious actor
with a racing-thread exploit.** The hard boundary remains Landlock + classic
seccomp.

Consequence: **no helper process is needed.** The supervisor performs no network
I/O (allowed hostnames are resolved before the filter is installed), so it never
notifies itself. `castellan-broker` is now ~400 lines lighter.

### B8.2 — systemd socket block (T4 structural close) — SHIPPED, claim corrected
Deny `connect` to BOTH routes to the systemd user manager: the private
socket (`$XDG_RUNTIME_DIR/systemd/private`, `/run/systemd/private`, the cgroup
socket) AND the session bus (`$XDG_RUNTIME_DIR/bus`).

The first B8.2 cut denied only the private socket and claimed T4 was closed.
**That was false.** `org.freedesktop.systemd1` is also exported on the session
bus, and `StartTransientUnit` over the bus launches an arbitrary command as a
transient unit outside the session cgroup and the envelope. `systemd-run` falls
back to the bus when the private socket is denied — so denying only the private
socket closed nothing. Verified live 2026-09-15: a `busctl StartTransientUnit`
call from inside an enforced session wrote a marker file on the host. After
denying the bus: no job, no marker, on both kernels.

**Result (2026-09-15):** `castellan-broker` wired into `castellan launch`; the
supervisor installs the notif filter and forks the agent, which then applies the
envelope. `test/shell.d/b8-broker.sh` → **9/9 on kernel 7.0.3** (both manager
routes denied, ordinary unix + loopback + git survive); cross-kernel
verification on **7.1.8** (.227) matches. With `--net`, public TCP `1.2.3.4:443`
→ `PUB_DENIED` by destination. The B8.1 kill criterion's UDP/DNS clause is
**open**: `restrict_ip` denies UDP to a public resolver as a connect target, but
the original criterion (a full D6 rerun under a dogfood hour) has not been run;
recorded here rather than claimed.

**Residual:** a harness that legitimately needs the desktop session bus
(portal dialogs, tray integration) is denied it under enforce. Recorded, not
hidden; re-allowable per session with `deny_user_bus=false`. False-block cost
against real harnesses is the B8.4 measurement.

MET (2026-09-15): both routes to the manager fail from inside an enforced
session. Census-observability is moot for the broker-denied path — the escape
never launches a unit — and is kept as defense in depth. Harness false-block
measurement is folded into B8.4.

### B8.3 — Periodic live census — SHAPE REVISED (auto-kill rejected)
Today the orphan census runs only at kill. The plan was to sweep every N
seconds and freeze/kill on a hit.

**Gate probe first** (`crates/castellan-freezer/examples/census_fp.rs`,
2026-09-15): the census predicate is *ppid == user manager AND cgroup not under
castellan.slice AND starttime >= session_start*. At kill time the agent is the
only such process, so the blast radius is moot. Run the SAME predicate during a
live session and it matches every legitimate user app opened since spawn —
konsole (`app-org.kde.konsole-*.scope`), firefox (`app-*.service`), pipewire,
kwin all live under `/user.slice` with the user manager as parent. A periodic
auto-kill census would kill the user's own applications. **The auto-kill shape
fails the zero-FP bar as specified and is rejected.**

What is FP-safe: the escape shape is a *transient `run-*.service`* (or a timer),
not an `app-*.scope`. B8.3's detection is narrowed to that shape and is
report/freeze, not blanket kill. `systemd-run` is also now denied at the source
by the B8.2 broker bus+socket denial, so B8.3 is defense in depth, not the
primary bound.

### B8.4 — Composed validation — SWEEP RUN (2026-09-15)
Full acceptance sweep on kernel 7.0.3 after the broker landed in the launch
path:

| Suite | Result |
|---|---|
| p0-freeze | 15/15 |
| p1-envelope | 13/13 |
| p2-undo | 17/17 |
| p3-trust | 5/5 |
| p4-certificates | 5/5 |
| p8-drills | 7/7 |
| p9-stack | pass |
| b8-broker | 9/9 |
| unit tests | 131 |

Cross-kernel (7.1.8 on .227): b8-broker route blocking verified
(T4_BLOCKED, bus blocked, no over-block), matching 7.0.3.

**Not run / open:** the D6 channel-census rerun under a full dogfood hour
(the B8.1 UDP/DNS kill criterion), and `v3-corpus.sh` (its pre-registered
criteria were already evaluated 2026-09-02; re-running after a broker change is
a real-session-program task, not a B8 gate). `p9-policycheck.sh` fails 1/6
without its `/tmp/opencode/scan-proj` fixture (missing fixture, not a broker
regression — verified: 5/6 with the fixture, and policycheck runs clean against
the live repo).

THREAT_MODEL C35/C36 added; C10a remains the honest egress inventory (the broker
narrows it under `--net`, but the full census rerun is pending).

---

## Chapter 2 — Real-session program (external validity)

The pre-registered V3 criteria were measured on a scripted corpus; the honest
gap is real LLM sessions. The C34 friction fixes (TMPDIR, utime,
CARGO_TARGET_DIR) make dogfooding viable.

### R1 — Dogfood — FIRST BATCH DONE (2026-09-16)
12 real Pi + deepseek-v4-flash sessions through the full stack (enforce+undo,
tier-gated), on a lab project with per-task hidden acceptance tests that decide
keep/revert mechanically. Harness: `test/corpus/real-corpus.sh` (one pty per
trial for the B7 witnessed-tty rule; planted bugs for fix-tasks).

The first attempt at this exposed a real composition bug rather than producing
data: the tier-floor forced `net`, the B8.2 broker turned that into a real IP
restriction, and a tier-0 project's agent could not reach its API — no edits,
auto-revert, trust stays 0, unrecoverable deadlock. Four of twelve trials were
bricked by this, not failed. Fixed (`5dd19a3`): net is not forced at any tier
(enforce+undo remain the floor). A second bug rode along: the CLI read the
honeypot port from the wrong JSON field, so `--net` silently no-opped.

### R2 — Re-evaluate on real spines — FIRST RESULTS
| Criterion | Scripted V3 | Real sessions (n=12) | Verdict |
|---|---|---|---|
| K1 trust marginals | PASS | **PASS** — kept +1.0 each (n=10), reverted −30/−29 (n=2), correct signs both arms, ledger rows present | survives real data |
| K2 radar FP | 47% (post-fix) | **70%** (7/10 kept flagged, leave-one-out with the real Prototype math) | advisory-forever confirmed; real sessions are *worse* than the scripted corpus |
| K3 campaign | PASS (scripted) | **FAIL, corrected** — two isolated reverts 8 kept sessions apart were reported as two 1-session "campaigns". Minimum run is now 2 consecutive bad sessions | detector fixed; re-measure next batch |
| K4 memory recall | PASS (scripted) | **fixed** — the tty gate contradicted its own comment and blocked read-only recall for humans outside the launching terminal | read ops removed from the gate |

K1 is the headline: the pre-registered trust criterion holds on real LLM
sessions, not just scripted ones. K2 is honestly dead as a detector (V3
demoted it; real data makes it worse). K3 and K4 were real bugs found by the
corpus doing its job.

New probe: `crates/castellan-radar/examples/radar_loo.rs` — leave-one-out radar
measurement. The daemon folds kept sessions into the project prototype, so
querying a kept session against the live prototype compares it with itself
(cosine ≈ 1.0 by construction). The probe removes that bias.

### R3 — Cross-machine
Repeat a smaller batch on .227 (kernel 7.1.8). The only prior cross-kernel data
is the portability pass; this extends it to the behavioral layer.

**Kill criterion:** trust fails to separate on real sessions → demote per
pre-registration. **Honesty:** cooperative agent, single user, small N (12); no
adversarial claims. Findings are descriptive, not significance claims. The
corpus is one model on one project shape — not a fleet measurement.

**Still open:** the corpus is 12 sessions, one model, one project. The next
batch should grow N, vary the project shape, and re-measure K3 after the
minimum-run fix. Nothing here is adversarial-validated.

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
