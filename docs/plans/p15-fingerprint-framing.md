# P15 — Agent-visible defense: fingerprintability audit + cross-session canary framing

Status: FROZEN (2026-10-01) — probes measure before any fix
Branch: `escape-sweep`
Predecessor: P14 (C39, gaps within the controls). P15 asks the Kerckhoffs
question the user raised: **the source is public, so (a) what tells the
agent it is inside castellan, and (b) does any defense secretly depend
on the agent NOT knowing?** No security through obscurity — but a
defense that *claims* indistinguishability and fails it is a false
claim, not an obscurity gap.

## H1 (attack, class "agent fakes") — cross-session canary framing

Code path (read before probe): `castellan-canary::handle_conn`
attributes a trip to the session that OWNS the secret in the registry;
the connection is plain TCP loopback, so the *sender* is never
identified. `Request::HoneypotPort` is in `agent_allowed` (daemon
lib.rs:138) and sibling session state is readable (C14, reads are `/`).

Attack: session A reads session B's canary file
(`<state>/castellan/sessions/<B>/canary/credentials`) or the shared
ledger `<state>/castellan/canary.jsonl`, asks the daemon for the
honeypot port, and sends B's secret to 127.0.0.1:<port> (loopback
allowed; NO_PROXY includes 127.0.0.1). Expected pre-fix: honeypot
trips, freezes **B**, writes `canary_trip` on B's spine, −50 trust on
B. That is a forged trust signal and an availability kill against an
innocent session — threat class 2, and worse than C14's confidentiality
stance because it attacks integrity.

Probe: two sessions (A attacker, B victim), measure freeze state of
both + B's spine content. Pre-fix must show B frozen (else H1 dead).

### Fix (frozen shape)

Attribute the trip by **sender**, resolved at accept:
`peer_addr().port` → `/proc/net/tcp` (local=honeypot port,
remote=peer port, state ESTABLISHED) → socket inode → walk
`/proc/*/fd` (daemon is ancestor of sessions; YAMA ptrace_scope=1
allows descendants) → pid → `/proc/<pid>/cgroup` → session scope.

Rules:
- sender resolved to session S → **freeze S, trip S** (owner or not;
  sender ≠ owner IS the framing signature → separate event kind
  `canary_framing`, still freezes the sender).
- sender resolved to a non-session pid (daemon itself = the D2 drill,
  human shell) → owner attribution (preserves drill + human manual test).
- sender unresolved (fast-close race) → **freeze nobody**, emit
  `canary_unattributed` globally; owner freeze would re-enable framing
  via send+close.

Kill criteria (pre-registered):
- K1: post-fix, A framing B → A frozen or unattributed, **B not
  frozen**, B spine has no `canary_trip`.
- K2: post-fix, honest self-use (session uses OWN canary) → session
  frozen, `canary_trip` present (owner path intact).
- K3: D2 drill green (drill sender = daemon pid → owner path).
- K4: p13 (17/0), p14 (8/0), b8 (19/19) unchanged.
- K5: any resolution failure on the honest path (K2) → resolver is the
  bug, not the rule; report as failed, do not soften.

## H2 (secrecy audit) — the canary inversion claims are false today

`docs/components/canary-credentials.md` claims "The agent cannot
distinguish real key from canary by reading — both look like
valid-format keys." Measured counterexamples in source: plant dir is
`session_scratch.join("canary")` (name), `hosts.yml` contains
`user: castellan-canary` (literal marker), and the ledger
`<state>/castellan/canary.jsonl` holds every secret → session mapping,
readable (reads are `/`). So reading DOES distinguish — three ways.

Fix: rename plant dir to a neutral name; neutral username in hosts.yml;
rename ledger to a neutral filename (update load path + docs + tests).
The secret VALUES stay readable — that is structural (same uid, reads
`/`, and the ledger must survive restarts on a disk the agent can read;
a memory-only key would break restart survival). Document as residual:
a sophisticated in-envelope agent can identify canaries and avoid them;
the canary catches naive/prompt-injected exfil, which is the population
it was built for. Correct the doc's absolute claim to match.

## H3 (inventory) — what identifies castellan to the agent

Enumerate live from inside a session, classify each as
identification (accepted — no-obscurity) vs secrecy-dependent (must
not exist / must be fixed). Known candidates: `CASTELLAN_SESSION` env,
TMPDIR path, cgroup slice name, supervisor cmdline in /proc, daemon
socket name in /proc/net/unix, proxy CA cert subject, EPERM
denylist-signature vs public source, launcher messages, canary markers
(H2), honeypot port RPC (H1 makes it harmless).

Pass condition: every secrecy-dependent item is either fixed (H1/H2)
or explicitly listed as a residual with a reason; nothing else in the
enforcement path reads as anonymity-dependent.

## Scope exclusions

No change to reads-are-`/` (documented governing residual; Landlock
cannot express "allow / except subtree"). No change to rate limits or
F4c timing (known-to-attacker residuals already recorded — public
source made them known the day it shipped). No new deps. No LLM.

## Verification

probe script `test/shell.d/p15-fingerprint.sh` (H1 two-session attack +
H3 inventory) pre-fix (records expected red: B framed) and post-fix
(H1 green per K1–K3); workspace tests; clippy; p13/p14/b8; drift gate;
drill (D2) via daemon drill op; docs updated (canary-credentials claim
correction, THREAT_MODEL C41, this plan's execution record).

## Execution record

### Pre-run amendments (2026-10-01, before any fix code)

1. **H1 gains a second vector (proxy tunnel).** The H3 inventory measured
   `PROXY_FORCED_LOOPBACK_CONNECT=HTTP/1.1 200` — the session proxy
   tunnels CONNECT to `127.0.0.1:<honeypot>` (its `allowed()` returns
   true for loopback under the session policy). A tunnel makes the
   honeypot-side connection originate from the **daemon's pid** (proxy
   threads live in the daemon) → sender attribution would resolve to
   NonSession → owner attribution → B framed *through* the fix. Added
   **F2**: `ProxyConfig.deny_ports` (set to the honeypot port at spawn)
   checked in `handle_conn` immediately after `parse_connect`, before
   `allowed()` — deny does not depend on `restrict`, so it holds in
   both proxy postures. p12's K3c CONNECTs a session-chosen upstream
   port (≠ honeypot), unaffected.
2. **Decoy dir self-labels too (`sessions/<sid>/decoy/` + generated
   `decoy_*.c` filenames) — deferred, not fixed.** Consequence class
   differs from the canary markers: a reader who spots the decoy avoids
   a trap they were never obligated to enter (evasion of a sting, no
   false accusation of an innocent); the canary markers sat on top of a
   cross-session *framing* path (freezes the wrong session). Renaming
   also couples to `p9-stack.sh` (hardcoded path) and the decoy crate's
   filename generation. Recorded as C41c residual with a one-line fix
   shape; steelman tolerance applied per the 2026-10-01 decision
   ("operate within steelman tolerance").

### Probe-first discipline

The probe asserts K1/K2/H2 as **gates** (they were pass-through STATE
lines on the first run). Negative control: gates must go RED against
the unmodified code (expected: victim_freeze=1 victim_trips=1, marker
strings present), then GREEN after the fix — same pattern as p14's
seeded drift-gate red.

### Pre-registered results

- H3 inventory (first full run): identification surfaces measured —
  `CASTELLAN_SESSION` env, TMPDIR path, cgroup slice name, launcher
  cmdline in ancestors, `castellan.sock` in `/proc/net/unix`,
  `castellan*` in `/proc/*/comm`, `Seccomp: 2 NoNewPrivs: 1`,
  io_uring EPERM signature (vs host OK), CA cert does **not** name the
  tool. All classified identification = accepted (no-obscurity).
- H1 pre-fix: **RED confirmed** — `victim_freeze=1 victim_trips=1
  attacker_freeze=0 attacker_trips=0` (B framed, A walks free).
- H2 pre-fix: markers present (`canary/` path, `castellan-canary`
  username, `canary.jsonl` ledger) — gates red by construction.
- FORGERY_RPC_CANARY_REGISTER: `human-only op (agent caller)` — R7
  holds, no new surface.
- K2 pre-fix: `self_freeze=1 self_trips=1` — honest path green (the
  control that attribution must not break).

### Post-fix results (2026-10-01)

- **Negative control honored:** K1/H2 gates ran RED against unmodified
  code first (`K1: VICTIM FRAMED (freeze=1 trips=1)`, both marker gates
  red), plus the vacuity catch — the first `castellan-canary` gate
  passed without reading hosts.yml; the probe now reads the file and
  fails if the check itself does not run.
- **K1 green:** `victim_freeze=0 victim_trips=0 attacker_freeze=1
  attacker_trips=1` — victim clean, sender frozen with `canary_framing`.
- **K2 green:** honest self-use still trips and freezes (freeze=1,
  trips=1) — attribution cost no detection.
- **H2 green:** plant dir carries no marker, hosts.yml carries no
  marker, ledger filename carries no marker (legacy `canary.jsonl`
  migrated in place; `legacy_canary_ledger_is_migrated` unit test).
- **H3 inventory:** identification accepted; forgery RPC refused
  (`human-only op`); forced proxy CONNECT measured `200` pre-fix (the
  F2 amendment trigger) and the fix denies the honeypot port before
  `allowed()`.
- **Drill 6/6** (D2's hit-latency fix, negative-controlled against
  pre-P15 by stash; census passes with the real `XDG_RUNTIME_DIR` —
  an override breaks systemd-run's bus and is a harness artifact).
- **Verification tally:** workspace 208, clippy 0, deny x4, drift PASS
  (+selftest 5/5), p0 15/0 (bare), p1 13/0, p2 17/0 (pty), p3 5/0,
  p4 5/0, p6 6/0, p9-stack 12/12 (pty), p11-tier 12/0 (both contexts),
  p11-crosskernel 4/0 (BIN_DIR), p12 25/25, p13 17/0, p14 8/0,
  p15 10/0, b8 19/19, v3-corpus 7/7 (pty), drills 6/6.
- **Suite-vs-gate drift repaired (pre-existing, R7-era — C40g):**
  witness nested-pty patterns (p9/v3/p2), spawn-rate retries (v3,
  p11-tier), v3 K2 reconciled with `ee91d25`'s own "advisory-forever"
  verdict, run-context documented (p0 bare; p2/p9/v3 under a pty).
- **Honest limits kept:** fast-close unattributed sender (nobody
  frozen), decoy self-labels deferred (C40f), ledger values readable
  (C40c).
