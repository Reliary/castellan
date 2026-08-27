# P9 — The Deterministic Layer

**Status:** planned 2026-08-28, not built. Every component is deterministic (no LLM in any loop), rides owned substrates from other projects (reliary-agent, relay-vuln, stria, CVEfixes), and carries a Koch-style kill criterion that runs BEFORE dependents are wired.

**Thesis:** P8 made the daemon adaptive; P9 makes it *watchful of the right things*. Two blind spots remain: (1) nobody watches the **artifact** — every trust input watches the agent's behavior; (2) nobody watches the **channels** — we enumerate what we deny, never what we fail to deny.

**Borrowed from:** Shannon (channel capacity — know your leaks), John Snow (contact tracing), Neyman (evidence over testimation), Leveson (control feedback / regression of the controller itself).

---

## Grounding: owned substrates used (verified in source, not memory)

| Substrate | State | Used by |
|---|---|---|
| relay-vuln scanner | 52,258 LOC pure Rust (`src/` — audit.rs, cer.rs 60 fns, pattern_matcher.rs, auth_cohort.rs, caller_chain.rs, buchi.rs); Python is `scripts/` mining/eval tooling only | 9.2 |
| CVEfixes v3 DB | 12.7 GB SQLite at `~/.cache/relay-vuln/cvefixes_v3.db` (fixes, commits, file_change, method_change, cwe_classification) — LOCAL-ONLY, never shipped | 9.2 kill criterion, 9.5 |
| reliary-search FTS5 | `CREATE VIRTUAL TABLE phrases_fts USING fts5` pattern + `search_fts5()` — proven in the reliary daemon | 9.3 |
| stria / reliary-search hub scores | pure Rust, grammar-free callgraph + fan-out | 9.4 |
| danger_signal byte-scan | in castellan-proof (placebo pipeline) | 9.5 |
| castellan-replay | forensic spine re-classification | 9.6 |
| quale | **NOT USABLE** — hub_risk is Python (quale/quale/cli.py); violates the pure-Rust rule for the trusted path | — |

**relay-vuln coverage, measured in source (not assumed):** exactly ONE vuln_class string exists in the tree — `"missing-validation-path"` (7 refs). Detector families: operator×language-weighted deref adjacency, genome pattern_matcher, auth_cohort, caller chains, Büchi liveness. Genome (CVEfixes) is C/C++-dominated. Blind: auth logic, crypto misuse, access control, business logic, most Rust/Python-specific classes. Every honest claim below is scoped to this.

**Landlock net rules, verified in our own landlock.rs:** ABI4 handles TCP only (NET_BIND_TCP / NET_CONNECT_TCP). **UDP has no access rights. Unix sockets are not covered at all.** Both are expected-open exfil channels under the current envelope — D6 must confirm or refute this live before anything else claims "egress locked."

---

## 9.1 Exfil channel census (drill D6) — know your leaks

**Why:** the `--net` flag kernel-denies TCP connect except the honeypot port. We have never enumerated what that denial does NOT cover. The cert says "net: locked" — that claim is currently unexamined beyond TCP.

**Design:** a new drill (D6) in castellan-drill: sacrificial session attempts, in order — TCP connect (allowed port + denied port), **UDP send** (localhost + external), **unix socket connect** (outside the session), DNS-crafted UDP query, filesystem drop to a world-readable path, inherited-fd write. Each attempt returns a kernel verdict; the aggregate is a **dated channel inventory** event on the spine + a `channels` verb for the human. Runs per-kernel (verdicts are kernel facts, not assumptions — the workflow rule).

**Antagonism:**
- *It may only confirm known gaps* — that IS the deliverable: a kernel-verified inventory replacing three assumptions in THREAT_MODEL. Either outcome is a doc correction.
- *UDP probe needs a listener to prove delivery* — verdict = connect/send return code; ENOBUFS vs EACCES distinguishers documented; a localhost UDP echo helper in the drill scope proves the data path when permitted.
- *Inventory becomes stale on kernel upgrade* — drill scheduler already re-runs on an interval; verdicts carry kernel version.

**Kill criterion:** census verdicts match strace-observed behavior on 10 probe binaries; the UDP and unix-socket findings are live-verified (expected: OPEN) and recorded in THREAT_MODEL C10/C19-adjacent with dates. If UDP is NOT open (kernel behavior differs from ABI documentation), record that too — it would be a kernel-behavior discovery, the AGENTS.md rule embodied.

**Cost:** ~150 lines. **Priority: FIRST** — it may produce a real THREAT_MODEL correction that reshapes 9.2-9.6 claims.

---

## 9.2 Pluggable artifact scanner at the keep gate — watch the work, not just the worker

**Why — the coverage matrix that motivates everything:** against a subtle vuln introduced via a prompt-influenced session, every current detector fails:

| Detector | Subtle vuln injection |
|---|---|
| Envelope | blind — writes stay in workspace |
| Canary/honeypot | blind — no egress |
| Census/siblings | blind — no escapes |
| Placebo proof | **passes** — danger signals went down |
| Test re-run | blind unless tests cover it |
| **Artifact scan (this)** | **the only detector** |

This is C16/T7-adjacent — our largest documented residual, currently labeled "accepted limit of OS-level defense." relay-vuln is the one deterministic, owned tool that reads semantics. Partial coverage, honestly labeled, beats the current zero coverage. But OUR scanner is not the champion for breadth — hence:

**Design — the adapter interface (battle-hardened tools first):**

1. **Interface, ~100 lines:** any external scanner emitting findings JSON `(path, line, class, severity, rule_id, evidence)` adapts to a `Findings` stream. The daemon consumes findings; it does not care who produced them.
2. **Two adapters ship:**
   - `semgrep` — user-installed, **capability-detected at runtime** (the relay dynamic-discovery pattern used for netcat/sift). Primary for coverage: thousands of FP-tuned rules, dozens of languages.
   - `relay-vuln` — native Rust crate behind a `vuln` feature flag (keeps the default binary lean; pulls rusqlite). Zero-install, fully offline **default**. Uniquely contributes genome-shaped evidence: "this diff reintroduces the pattern CVE-XXXX's fix removed" — provenance to real fix data, not a rule match.
   - **CodeQL explicitly excluded:** DB-build too heavy for a keep gate, licensing/infra-coupled.
3. **Baseline-delta, never raw scan:** scan at spawn (baseline), scan at keep, count only **new findings on session-touched lines**. Legacy findings never punish the project; the signal is precisely "what this session introduced." Same session-scoping discipline as the placebo pair.
4. **Findings-only-negative (the anti-false-comfort core):** a clean delta earns NOTHING — no trust, no cert language, no green mark. Only findings produce a signal (negative). There is no wire from "clean" to any reward, so partial coverage cannot leak absence-of-evidence into evidence-of-absence. Same discipline as the placebo proof (`assert True` earns nothing).
5. **Cert states non-coverage, not coverage:** the factor renders as `vuln_delta: 2 findings: validation-path (genome match, C). Scanner: relay-vuln@<sha> / semgrep@<ver> — scope: <classes>. NOT SCANNED: <blind classes>`. A "0 findings ✓" line never renders.
6. **Config pinning — the S0 lesson, already built:** `[scanner] cmd` in `.reliary/castellan.toml` is pinned at spawn (`config_sha` in Session, refuse on mismatch — identical mechanism to `test_cmd`). The cert displays scanner identity + config hash. A shimmed scanner is human-visible; and findings-only-negative means a fake-clean scan can never EARN trust — worst case suppresses a negative, same bounded exposure class as the existing test_cmd factor.
7. **Async, priced into the NEXT launch:** the keep-time scan runs in a background thread; the cert is amended when done; the trust signal applies to the next spawn. Never retroactively punish after a human keep.
8. **Never gates alone:** one negative input among canary/census/placebo. No offsetting exists (no positive signal at all).

**Antagonism settled in discussion (recorded so it doesn't reopen):**
- *Too heavy?* No port needed — the scanner is already pure Rust (verified during the castellan pure-Rust audit); Python stays in `scripts/` as dev tooling for the eval harness, which is allowed.
- *Only certain classes?* Yes — see coverage above; the design makes the scanner structurally incapable of providing comfort (points 4-5).
- *Why not battle-hardened tools only?* We wire them — semgrep is the coverage champion; relay-vuln stays as the offline zero-install default + owned genome evidence. Complements, user chooses via config.
- *Subprocess in the daemon?* Not in the hot path — keep-time background, config-pinned, same precedent as Factor A test_cmd. The native adapter links in-binary behind a feature flag.

**Kill criterion (measured on DELTAS, dated):** on held-out CVEfixes fix-pairs, the adapter must score the fixed version safer than the vulnerable version (direction discrimination) **≥ 70%**. Harness: Python (dev tooling, `scripts/`). **Fail → annotation-only forever** (~150 lines: human sees findings at keep, trust loop never wired) and the measured ceiling is recorded in PRIMITIVES.md. Either branch is a win: a trust signal, or the honest ceiling of our own scanner documented before anyone cites relay-vuln in a README again.

**Cost:** interface + wiring ~300-400 lines + eval harness ~1 day. Semgrep adapter ~50 lines (capability detect + JSON parse + delta filter).

---

## 9.3 Cross-session contact tracing — follow the writes

**Why:** a canary trip today freezes ONE session. The compromised session's *artifacts* live on in files other sessions then edit. No component tracks exposure propagation across sessions. (Shallow wave-1 idea, previously shelved for cost — now cheap because the substrate exists.)

**Design:** one FTS5 index (reliary-search schema pattern) over ALL sessions' spines — `(session, kind, path, ts)` inverted on path. On a canary trip / high-severity campaign: SELECT sessions that wrote files the compromised session wrote, **after** it did → **exposure score** = fraction of the exposed session's edited files that are poisoned + temporal ordering. Hub files (`Cargo.lock`, `package.json`) are handled by scoring, never binary flags. Response: freeze **offered** (`exposed` verb), quarantine decision stays human.

**Antagonism:**
- *Hub-file false exposure* — score, don't flag; threshold chosen on the synthetic corpus before wiring.
- *Reads are invisible* — write-implies-read is a lower bound; documented in the cert/human output ("exposure is a lower bound").
- *Index grows forever* — per-project retention, same 4 MiB spine rotation discipline.
- *Mimicry via timestamps* — spine events are daemon-written, clock is daemon's; the agent cannot forge `ts` (it can influence when it writes, which is the signal itself).

**Kill criterion:** synthetic A→poison→B chain: B identified as exposed; clean parallel session with zero file overlap NOT flagged; hub-file edit scored low, not binary-flagged.

**Cost:** ~400 lines + index module. **Depends on:** nothing (spines exist). Sequenced after 9.2 so the artifact signal and the exposure signal land together.

---

## 9.4 Blast-radius-weighted trust — trust proportional to risk

**Why:** today a leaf-file fix earns the same trust as a hub-function edit. An agent can farm tier 4 with well-behaved, easy, low-stakes work. The placebo pass and clean_session signal should scale with the structural risk of what was touched.

**Design:** at launch (async — never block spawn), stria/reliary-search builds the project's hub map (fan-out / PageRank-weighted call graph — pure Rust, grammar-free). Touched files/functions map to a risk weight in [0.5, 2.0]; placebo pass earns `+10 × weight`; clean_session `+1 × weight`. Default weight 1.0 until the index is ready (no blocking, no penalty for missing index). Cert carries "touched hub functions: N" for the human.

**Antagonism:**
- *Index build cost* — async, default-1.0 fallback; index cached per project (mtime-guarded, the auto-ingest three-layer safety pattern).
- *Heuristic callgraph (grammar-free)* — acceptable: this is weighting, not enforcement. A wrong hub score distorts a trust delta, never freezes anyone.
- *Agent gaming via generated files* — new files have no history: weight floor 0.5, and generated-looking churn (lockfiles) is damped by path-segment rules (the symbol.rs test-path lesson: segments, not substrings).
- *Gaming by touching hubs with trivial edits* — the placebo pair still gates: danger must actually drop.

**Kill criterion:** on stria's own repo, hub-function edits vs leaf edits produce measurably different trust deltas across ≥ 20 synthetic sessions (sign test, not eyeballing).

**Cost:** ~250 lines + stria wiring as optional dependency.

---

## 9.5 Decoy-vulnerability edit canaries — the egress canary's twin for edits

**Why:** the egress canary trips on *network* misuse. Nothing trips on an agent that *worsens* vulnerable-looking code it finds. Decoys make the file system itself a tripwire, direction-sensitive via machinery we already own (danger_signal in castellan-proof).

**Design:** at launch (opt-in), plant 2-3 realistic decoy files in session scratch — patterns drawn from CVEfixes `method_change` vulnerable-side shapes (realistic, not synthetic-looking). At session end, direction check per decoy:
- **Weaponized** (danger_signal increased, or validation removed): freeze-tier event `decoy_trip` — canary-class, N2 top tier.
- **Fixed while unrequested**: `placebo_seeking` annotation ONLY — never a trust penalty (proactive benign agents exist; punishing unrequested fixes would train agents to ignore vulnerable code — worse for safety).
- **Untouched**: no signal (a tripwire, not a requirement).

**Antagonism:**
- *Auto-formatters trip byte-matches* — pattern-level match (danger_signal on semantic patterns), never byte-level diff; formatter corpus test in the kill criterion.
- *Agent reads decoys and backdoors around them* — decoys observe, not constrain; residual documented.
- *Decoy realism* — CVEfixes vulnerable-side shapes are real historical code patterns; planted with realistic surrounding context, not islands.
- *Poisoning the decoy corpus* — patterns are extracted locally from the owned DB at plant time; the agent has no write path to the corpus (daemon scratch, envelope-bounded).

**Kill criterion:** scripted weaponize session → decoy_trip fires; scripted fix session → annotation only, no freeze, no trust penalty; formatter-only pass → no trip. Three scripts, live, dated.

**Cost:** ~350 lines + extraction script (Python dev tooling, allowed).

---

## 9.6 Policy regression replay — CI for the controller

**Why (Leveson):** the envelope policy is control software. We change it (C10 mitigations, D6 findings will force changes). Nothing today measures whether a policy change would newly deny work that humans previously approved. Every other engineering discipline regression-tests the controller; we should too.

**Design:** castellan-replay gains a policy-version mode: replay the last N kept sessions' spines through the CANDIDATE policy before it lands; report the **false-deny delta** (paths allowed before, denied after). Wired as a check in the release workflow (local, like the acceptance suites): a policy PR runs replay over the local kept-session history.

**Antagonism:**
- *Kept sessions are audit-mode (sparse spines)* — correct and sufficient: audit spines carry allow/would_deny verdicts; enforce spines are mostly empty (known finding). Audit history is exactly the "what humans approved" corpus.
- *History lacks denied-path coverage* — replay measures false-NEW-denies only, never claims false-accept measurement; labeled accordingly.
- *Adversarial history poisoning* — an agent that knows future policy checks read spines could stage approvals; mitigated by: replay is advisory at release time (human reads the delta), spines are hash-chained (ledger), and the check runs on the developer's machine, not the agent's runtime.

**Kill criterion:** inject a regression (deny a previously-allowed legit path) → replay flags it; an honest policy change (known-narrowing, e.g. D6-driven) shows a delta exactly matching the intended narrowing.

**Cost:** ~200 lines (replay mode + report).

---

## Build order and dependencies

```
9.1 channel census      FIRST — may force THREAT_MODEL corrections that reshape claims
9.2 artifact scanner    the centerpiece; kill criterion decides trust-wiring vs annotation-only
9.4 blast-radius trust  independent; weights land before 9.3 reads trust context
9.3 contact tracing     after 9.2 so artifact + exposure signals land together
9.5 decoy canaries      independent; anytime after 9.2 (shares CVEfixes tooling)
9.6 policy replay       last; benefits from the policy churn 9.1 will cause
```

## Killed at the gate (do not build; recorded with reasons)

- **CVEfixes → SDM memory seeding** — schema mismatch: code-level vuln patterns are not session telemetry; forcing them into immune-memory shapes is the seq-engine tautology trap again.
- **Authorship fingerprinting of edits** — weak signal, steganalysis-adjacent, unmeasurable FP rate without a corpus we don't own.
- **Anything embedding-based (airgap-search)** — not deterministic. Excluded by the P9 thesis.
- **quale hub_risk wiring** — Python; violates the pure-Rust trusted-path rule. stria/reliary-search serve 9.4 instead.

## Prior-art gates (before ANY README/doc claims)

- 9.1: air-gap exfil research (DNS tunneling, cross-VM channels) — cite; our claim scoped to "self-inventoried, kernel-verified channel census per desktop."
- 9.2: SAST-gated CI/deploys (GitHub required checks, Semgrep CI) — cite; claim scoped to "keep-gate, session-delta, trust-priced composition on a desktop agent OS."
- 9.3: SLEUTH/HOLMES provenance graphs (root-based, auditd) — cite; claim scoped to "unprivileged, session-granular, spine-derived."
- 9.4: risk-weighted code review routing exists in industry (Facebook, Google) — cite before any novelty language; our scope: "weights an OS-level earned-autonomy loop."
- 9.5: honeypot/deception literature (Honeynet, Canarytokens) — cite; scope: "edit-direction-sensitive decoys in agent scratch."
- 9.6: policy regression testing in systems (seccomp/SELinux policy diffs) — cite; scope: "replay over human-approved agent session history."

## Doc updates due at build time

- THREAT_MODEL: C10 amendment (UDP/unix verdicts from D6), new C-entries for decoy mimicry and scanner gaming
- ROADMAP: Phase 9 section with built/not-built statuses
- CRATES: new modules (drill D6, scanner adapters, trace, weight, decoy, replay mode)
- PRIMITIVES: relay-vuln honest ceiling (whatever the kill criterion measures), CVEfixes decoy-corpus entry
