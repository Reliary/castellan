# P8 — The Immune Daemon v2: Adaptive

**Status:** planned 2026-08-27, not yet built. Branch target: `p8-immune-v2` off `p7-adversary-hardening`.
**Theme:** science transfers from owned primitives — every component rides machinery we already built in another project, is deterministic (no LLM in any loop — the killed-ideas ledger demands it), and carries a Koch-style kill criterion that runs *before* dependents are built.

**Grounding verified in source this session:**
- `engfield` — true Kanerva SDM in Rust: `sdm.rs` (65K locations, i16 counter per bit, activation radius, min-activations), `hash.rs` (Address, hamming_distance), plus recorder/retriever/scoring (~60K total working code)
- `structural-stack/core` — `mellin_alpha` log-log power-law regression + HDC hex-cosine (12K)
- `faers-radar` — pharmacovigilance *domain framing* (374 LOC drug-event phrase mining); the disproportionality math (PRR/ROR/EBGM) does NOT exist there — it is fresh code
- `whisper.cpp` + `Chatterbox-TTS-Server` — STT/TTS experience; the castellan envelope already denies `/dev/snd*` class devices to agents (P1 device-node policy)
- `castellan-radar` (P5) — session→HV encoding exists and is reused as the memory address encoder

**Killed during ideation (do not resurrect):**
| Idea | Death certificate |
|---|---|
| Shadow-session mirror comparator | Message-level comparison → dies against documented 2.7× provider variance (WORKFLOW_RULES precedent) |
| HRR/holographic memory via `hologram` repo | `hologram` is a quale-enriched repo-map generator, not associative memory — premise false |
| Hebbian co-occurrence expectations | seq-engine probe 2026-08-27: 78% within-event tautologies; dead stays dead |
| Visible-deterrence / transparent rules | 5-tool-system data: informed agents fight restrictions harder (+69–113% cost) |
| Riveter-style attention arbitrage transfers | +12.7% FAIL precedent |

---

## 8.0 — Live-fire drill suite (prerequisite: it is the antigen training set)

**Science:** Metchnikov (immunity as active process), Feynman ("first principle: you must not fool yourself"), chaos engineering, breach-and-attack simulation. Our defenses are currently *self-reported*: nothing post-shipping verifies census, honeypot, floor, or freezer still work. Prior art that MUST be cited (survey gate before any README claim): SafeBreach, AttackIQ, Cymulate (BAS for enterprise infra). Claim scope: BAS for personal-desktop agent confinement against kernel-witnessed defenses.

**New crate:** `castellan-drill` (~600 lines).

**Drill registry (anti-mimicry core rule):** drills are discriminated by a daemon-held nonce registry + sacrificial cgroup scopes `castellan-drill-<nonce8>`. **Names are never trusted.** Nothing in the system may skip/ignore units named like drills; the census is name-agnostic (time-window + ppid + out-of-scope). A real escape naming itself `castellan-drill-*` gains nothing.

**The five drills:**

| id | attack (in sacrificial scope) | must-happen | spine event |
|---|---|---|---|
| D1 | `systemd-run --user` escape spawn | orphan census finds + kills it | `drill_census` |
| D2 | honeypot probe with a *registered drill-canary secret* | trip fires, drill scope freezes | `drill_honeypot` |
| D3 | forged bless nonce (`bless_approve` with garbage nonce) | `forged_nonce` recorded, no grant | `drill_bless` |
| D4 | write to a hard-denied path (`~/.ssh/…`) from drill envelope | Landlock deny (EACCES) | `drill_envelope` |
| D5 | freeze→thaw roundtrip on drill scope | state transitions within latency budget (≤500ms each way) | `drill_freeze` |

Each result: `(attack, expected, observed, pass/fail, latency_ms)`. Any fail → `drill_failed` spine event + human alarm (terminal bell via CLI status; the alarm channel itself is passive — no auto-freeze of real sessions, N2 low-tier routing).

**Scheduler:** daemon thread, default 1 cycle/hour, jittered ±10min (fixed schedule = attacker-syncable window; jitter documented as best-effort). Config: `[drill] interval_min`, `enabled=false` default-on? **Decision: enabled=true default** — the daemon should defend itself out of the box; opt-out documented.

**Drill-sourced incidents feed 8.1:** every drill that *fires correctly* also writes a synthetic incident into the immune memory (expected shape + response + success outcome). Every drill *failure* writes an incident with outcome=failure and response=alarm_human — the memory learns what defense-breakdown looks like too.

**Kill criterion (Koch):** inject each of 5 real regressions — (a) census disabled at call site, (b) honeypot port closed, (c) bless floor bypass, (d) Landlock rule dropped from policy, (e) freezer muted — drill cycle must fail loudly for each; then 20 clean cycles → zero false alarms. A self-test that cannot fail is not a test; if any injected regression passes silently, 8.0 itself is killed and redesigned.

**Tests:** unit (registry nonce lifecycle, mimicry rejection — a real-trip-shaped probe during a drill window must NOT be counted as drill or ignored), integration (all five drills against a live daemon), the five-regression injection suite as a shell acceptance script `test/shell.d/p8-drills.sh`.

---

## 8.1 — Kanerva-immune memory (the daemon that remembers attacks)

**Science:** Kanerva SDM (content-addressable, fragment→whole convergence), Burnet clonal selection. **The property nobody uses in agent security:** cue with a *partial* observation (40% of a known attack's telemetry) and the same locations activate, recalling the response — degraded, approximate, associative recognition.

**New crate:** `castellan-memory` (~700 lines + ~400 vendored).

**Vendoring:** copy `engfield/src/sdm.rs` + `hash.rs` into `castellan-memory/src/sdm/` with attribution header ("vendored from engfield, MIT, 2026"). Path-deps outside the workspace break CI; vendoring is the established pattern (radar vendored sensor-hdc machinery).

**Memory model:**
- **Address** = event-shape HV, 10,000 bits (reuse `castellan-radar`'s session→HV encoder: event → token HV → bundle). For incidents, the encoded sequence is the *attack telemetry window* (spine slice from first anomalous event to trip), not a whole session.
- **Payload** = response HV: binding of enumerated response verbs with context — verbs: `freeze, freeze_all, quarantine_files, alarm_human, log_only` (mirrors the N2 routing table; memory output vocabulary = policy vocabulary by construction, so recall can never invent an action outside the routing table).
- **Regions:** two, distinguished by role-binding in the address: `ROLE:incident ⊛ shape` and `ROLE:self ⊛ shape`. Self-region written only on human `keep` (tolerance — Burnet's negative selection; an input matching self does not fire, regardless of incident similarity).
- **Outcome tallies:** side table keyed by address-hash: `{attempts, successes}` — a recalled countermeasure that historically failed (`freeze` attempted, attack proceeded) loses counterweight. This is how the memory unlearns without deleting.

**Write paths (daemon-only, kernel-witnessed or drill-sourced):**
1. drill results (8.0) — synthetic incidents, continuous
2. real incidents: canary trip, envelope escape, census catch, campaign high-severity, forged nonce
3. tolerance: human keep → self-region write

The agent has **no write path** — the socket op refuses (`memory_write` is not an exposed op; incident writes happen inside daemon event handlers only). Poisoning-by-agent is structurally impossible; poisoning-by-drill-bug is bounded by D-series pass/fail sanity.

**Recall path:** `memory_recall(fragment_hv) -> { response_verb, confidence, activations }` where confidence = (counter magnitude at converged locations) / (locations activated), activations must ≥ `MIN_ACTIVATIONS`. **Routing: low-tier only (N2).** Memory output annotates the spine event + cert ("similar to known incident shape, confidence 0.7; historical response freeze (3/3 success)") and NEVER auto-freezes. Escalation to high-tier is a human decision after evidence accumulates.

**Cold start:** first drill cycle = ~20–40 synthetic incidents across the 5 drill families (each cycle writes 5). The THREAT_MODEL A1–A11/B/C vectors each get a scripted synthetic telemetry fixture in `castellan-drill/fixtures/` — the threat model document becomes executable training data.

**Kill criterion:** fragment cues at 30/50/70% of the event set retrieve the correct response verb: ≥60% top-1 at 50% retention (above the 20% chance floor for 5 verbs); 20 clean session HVs → zero recalls above threshold. Fail → ships off-by-default advisory (`[memory] enabled=false`) or is removed entirely — decided by how it fails (convergence failure = remove; threshold-only = default-off).

**Antagonism:**
- *Confabulation* (confident wrong recall) → advisory-only + confidence in cert + outcome tallies discount failed responses
- *Concept drift* (new harness, new event kinds) → address encoder is versioned; encoder bump = fresh memory (documented, not migrated)
- *Superposition crowding* (SDM critical distance — too many incidents merge) → incidents are few (dozens, not millions); capacity is ~65K locations with 10K-bit addresses — collision probability negligible at our scale; monitored via activation-count stats in `memory_status`
- *Mimicry* (attack shaped like self) → self-region check runs BEFORE incident recall; near-self cues are suppressed (tolerance dominates) — and this is exactly the biological trade-off, documented as residual: a patient attacker that survives many kept sessions slowly enters self. Mitigation: canary/census/kernel-witnessed detectors (innate immunity) are NOT tolerance-gated — memory is a second opinion, never an override

**Daemon ops:** `memory_status` (locations used, activations histogram, last-write), `memory_recall` (debug/forensics). **CLI:** `castellan memory` (status).

---

## 8.2 — Scale-invariant campaign signatures (the slow-drip killer)

**Science:** Mellin (1937) — scale invariance. **Threat:** T1 slow-drip — the same attack stretched over 3 weeks defeats every per-session and windowed detector we have. Under scale transform, a 3-hour attack and its 3-week dilation are *the same object*.

**Honest math framing (no overstating):** event streams are discrete; we do NOT compute a continuous Mellin transform. Discrete log-binned profile comparison = sampling the Mellin-domain magnitude (log-time sampling is the discrete Mellin analogue). The plan says exactly this in code comments and docs.

**Design (~300 lines, extends `castellan-campaign`):**
1. Campaign = ordered session-event-count vectors (from the existing maximal-run detector)
2. Session-index axis normalized to [0,1], event counts into fixed log-bins (8 bins, powers of 2: 1,2,4,…128+ events/session)
3. Signature = (a) power-law exponent α via log-log regression (the `mellin_alpha` formula family — ~30 lines fresh, no dep needed), (b) HDC bundle of the normalized binned profile (reuse radar bundling)
4. Comparison: cosine over bundled profiles; α as a cheap pre-filter (|Δα| > 1.0 → different family without HV math)

**Dilation invariance mechanism:** stretching a campaign by k inserts interpolated sessions; in normalized log-binned space the profile shape is preserved (interpolation spreads mass across adjacent bins — tolerance built into the >0.8 threshold, verified by the kill criterion, not assumed).

**Kill criterion:** synthetic campaign at 1×/5×/25× dilation of the same underlying shape → cross-dilation signature cosine > 0.8; ≥3 distinct campaign families (probe-exfil, poison-edit, credential-crawl from THREAT_MODEL) → pairwise < 0.5. Binning artifacts destroy separation → **honest kill**, recorded in PRIMITIVES.md next to seq-engine. This criterion runs on day one, before any daemon wiring — probe first, build second (the seq-engine lesson, institutionalized).

**CLI:** `castellan campaigns --signatures` (list with α + fingerprint), `castellan match-campaign <ref-hash>` (similarity to historical campaigns). Daemon: campaigns op extended, advisory-only (N2 low tier — a signature match alone never freezes).

---

## 8.3 — The Acoustic Channel (kernel-guaranteed human exclusivity)

**Science:** channel separation (air-gap doctrine) + nonce challenge-response + spoken informed consent. **The core property:** the envelope denies the agent `/dev/snd*` and `/dev/video*` (P1 device policy) — **the agent can neither hear nor speak**. The human voice is therefore a channel the agent is *physically* excluded from, by the kernel, not by policy. No one else ships this for agent control.

**Pure-Rust mandate handling (critical decision):** STT/TTS are ML-native. Default workspace builds stay pure Rust — the ML is a **feature flag**: `--features voice` pulls `whisper-rs` (whisper.cpp FFI) + a TTS backend (espeak-ng FFI or piper). Without the flag: the acoustic protocol degrades to terminal nonce (current bless v1 behavior). The *security core* — device denial, nonce protocol, grammar matcher — is pure Rust and testable without any audio hardware. Prior-art survey gate: voice authentication/biometrics is a mature field; the claim is scoped to **kernel-enforced acoustic channel separation between human and agent** — not "voice auth is new."

**Protocol (bless-v2):**
1. `castellan bless request --want <x> --reason "…"` → daemon **freezes the requesting session** (it's blocked on approval anyway — this closes the a-social-engineering window where the agent acts while the human decides)
2. Daemon speaks (TTS, daemon-owned device access — daemon is outside any envelope): *"Session s18cfb requests network access to fetch docs. If this surprises you, say nothing. Approve code: seven four one nine."* Context is spoken, never agent-composed text
3. Human speaks the code → daemon mic capture → whisper under constrained grammar (digits + yes/no/freeze vocabulary, Levenshtein ≤ 1, two-tolerance: one retry on mismatch)
4. Match → existing one-shot grant machinery executes; session unfreezes
5. **Panic phrase:** "freeze everything" → freeze-all + census + alarm (exact-grammar match only, high threshold, also available as `castellan freeze --all` for keybinding)

**Residuals (documented in THREAT_MODEL, not hidden):**
- *Human social engineering* — agent persuades human to repeat the daemon's code. Mitigated by spoken context + surprise-warning phrasing; never eliminated (residual class C-human, pre-existing)
- *Physical channel leak* — speaker→room→recorder→agent? Agent has no mic; a colluding human recording is the same as social engineering (C-human)
- *Always-on mic privacy* — capture opens only during an active bless window (default), push-to-listen keybinding noted for omarchy integration; no ambient storage; audio processed in-memory, never persisted
- *Whisper false accepts* — nonce grammar is 4 digits from a closed set; with Levenshtein ≤1 and two-attempt limit the false-accept space is tiny; measured, not assumed

**Kill criteria:** 100 nonce trials → zero false accepts (grammar + distance + retry budget); live-verified agent synthesis failure (enforced sandbox opens `/dev/snd/*` → EACCES, spine `envelope` event); end-to-end bless-v2 latency < 3s on CPU small model; unit-tested grammar matcher without hardware (CI-safe).

**Build order inside 8.3:** (a) device-denial live verification + regression test, (b) pure-Rust protocol state machine + grammar matcher, (c) feature-gated whisper/TTS backend, (d) hardware-marked acceptance script `test/shell.d/p8-voice.sh` (local-only, like p0/p1 suites).

---

## 8.4 — Pharmacovigilance for agent fleets (DuMouchel for daemons)

**Science:** Finney (disproportionality), DuMouchel 1999 (empirical-Bayes signal detection in spontaneous reports). **The insight:** trust signals ARE spontaneous reports — noisy, biased, under-reported, confounded. The pharma field spent 60 years building exactly the statistical machinery for this data shape, and it has never been applied to agent telemetry.

**Transfers (each is a fresh ~50–150 line implementation of a published formula — cite the primary source in each doc comment):**

| Pharma concept | Agent-safety translation |
|---|---|
| Drug-event 2×2 table, PRR, ROR (+CI, Haldane-Anscombe correction) | (signal-class × context) contingency over trust events; is `audit_mismatch` reporting elevated for harness-version H? |
| EBGM (DuMouchel mixture) | shrinkage-adjusted signal score that separates "3 events, background 0.001" from "3 events, background 2.9" — the alarm-fatigue killer |
| Depletion-of-suspects | a dominant `canary_hit` masks weaker real signals in the same window — recompute the table excluding the dominant signal to unmask |
| Notoriety bias | post-incident reporting spike (everything looks suspicious right after a real trip) |
| Weber effect | signal-reporting peaks at deployment novelty, decays — expected curve for a new harness version, not drift |
| Stratified analysis (Mantel-Haenszel) | harness version / project / tier as strata — an apparent agent signal that is really a Claude-update confounder |

**New crate:** `castellan-pharmaco` (~400 lines). Input: trust.db events ledger (owned schema). Output: `castellan signals` — table of (signal-class, context) with PRR, ROR-CI, EBGM, masked-by annotations, stratum breakdown.

**Fleet honesty (the no-overstating rule, applied hard):** one desktop is not a reporting system — dozens of sessions cannot support EBGM. This component ships as **methodology + estimator correctness + simulated-corpus validation**, explicitly labeled "evidence pending fleet" and gated on the deferred ed25519 fleet-sync layer. It does not gate anything, feed trust, or appear in certs until fleet volume exists.

**Kill criterion (methodology-level, runs before wiring):** estimator unit tests against *published worked examples* (standard pharma PRR/ROR textbook cases with known answers, cited); a known-injected confounder into a simulated 10K-event corpus is correctly de-confounded by stratification; injected masked signal is recovered by depletion correction. Any estimator failure → fix or kill before a single daemon line is wired.

---

## Sequencing, effort, gates

| phase | builds on | new code | gate before next phase |
|---|---|---|---|
| 8.0 drills | P0–P7 (all live) | ~600 | Koch 5/5 regression catches + 20 clean cycles |
| 8.1 memory | 8.0 (antigen supply), radar encoder, engfield SDM | ~700 + 400 vendored | fragment-recall criterion |
| 8.3 acoustic | P1 device policy, bless v1 grants | ~500 (+feature-gated ML) | device denial live-verified + grammar false-accept = 0 |
| 8.2 mellin | campaign detector, radar bundling | ~300 | day-one dilation probe (kill before build if it fails) |
| 8.4 pharmaco | trust.db | ~400 | published-example estimator tests |

8.2's probe is deliberately cheap and runs *before* 8.3 could be skipped-to — probe-first is institutional policy since seq-engine. Total: ~2,900 lines + vendored SDM, five kill criteria, each capable of killing its component honestly.

**Prior-art survey gates (before any README/docs claims — no-overstating rule):**
- 8.0: BAS vendors (SafeBreach/AttackIQ/Cymulate) — claim scoped to desktop agent confinement, kernel-witnessed
- 8.1: SDM/associative-memory in IDS academic literature; fragment-recall defense
- 8.2: scale-invariant detection (vision/time-series) — claim scoped to discrete campaign telemetry
- 8.3: voice authentication field — claim scoped to kernel-enforced human/agent channel separation
- 8.4: DuMouchel-lineage + any security-domain disproportionality work (survey may find prior transfer — if found, we cite and demote to composition)

**Doc updates due at build time:** ROADMAP P8 section, THREAT_MODEL C-series additions (drill mimicry, acoustic residuals, self-region tolerance erosion), PRIMITIVES (engfield vendoring note + any kills), CRATES dep graph, glossary (SDM region, Mellin binning, EBGM).

**Everything is deterministic. No LLM in any loop.** That is the design covenant, and it is why nothing here is expected to die the way every interception idea died.
