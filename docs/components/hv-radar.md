# HV radar

Hypervector fingerprints of session action streams, computed by the daemon, signed per-machine, synced across the fleet. Local outlier detection first (privacy: detection is local); fleet outlier detection second (catches coordinated compromise across machines that local cannot see).

## Why HDC and not a learned model

- Owned: sensor-hdc (BUILT, 286 LOC, zero-dep) + cortex-rs (BUILT, ~3000 LOC, Hebbian + tier-promotion) + structural-core (BUILT, shared HV primitives). The whole stack is ours.
- Deterministic: no training, no stochastic gates. HV binding/bundling is integer math. Matches the determinism directive.
- Compact: 10K-bit bipolar = 1.25KB packed per session. Fleet sync is cheap.
- One-way-ish (soft claim — D7): random projection reduces leakage. NOT a cryptographic guarantee, documented honestly. The agent cannot reconstruct file contents from an HV, but a determined attacker with enough HVs + known vocab could approximate inversion. Soft claim only.

## Encoding

Per session, the daemon encodes the kernel-witnessed event stream:
1. **Tokenize** each event: `(type, target_bucket, op_class, outcome)`. target_bucket = path depth + extension class (not the raw path — privacy). op_class = read/write/exec/net/deny. outcome = ok/fail/deny.
2. **Token → HV:** each token maps to a random 10K-bit bipolar HV via `token_to_hv` (cortex-rs, DefaultHasher-seeded).
3. **Positional binding:** bind each token HV with its position-in-stream HV (XOR/permutation).
4. **Bundle:** majority-vote sum all bound HVs into one session HV (1.25KB packed).

## Local outlier detection

Per project, the daemon maintains a **prototype HV** (Hebbian accumulation, cortex-rs style: bundle all past session HVs, weighted by tier-promotion). A new session's HV is compared via cosine similarity:
- cosine(session_HV, project_prototype) > 0.5 → normal.
- cosine < 0.5 → anomaly flag (advisory; feeds sentinel hint layer, does NOT auto-freeze — D4).

The prototype promotes over time (cortex-rs tier-promotion: 10+ recalled sessions promote episodic → semantic → consolidated). A project with 50 verified sessions has a strong prototype; a new session that looks unlike any of them stands out.

## Fleet outlier detection (Phase 5, opt-in)

The fleet layer catches what local cannot: a coordinated compromise hitting multiple machines' same-project sessions simultaneously (e.g., a malicious dependency update that makes every machine's agent behave the same weird way). One machine's local sentinel might dismiss it as "the project just changed"; ten machines' HVs all shifting the same way at the same time is a strong signal.

Mechanism:
- Each machine's daemon signs its session HVs + project prototype with its per-machine ed25519 key (commitment #9, key outside any envelope).
- HVs + signatures sync via Omarchy's existing usage-sync-folder mechanism (the same one the agents panel uses to merge usage across machines).
- A machine joining the fleet computes cross-machine cosine: "my session HV vs every other machine's prototype for this project." Low mean-cosine to all prototypes = fleet outlier.
- The fleet exchange is HVs + labels only, never file contents, never event logs. ~1.25KB per session.

## What's NOT claimed

- Not a cryptographic privacy guarantee (D7). Soft claim: reduces leakage, defeats casual reconstruction.
- Not a security guarantee. Radar is hint-layer + analysis-layer; it does not enforce.
- Not a replacement for the sentinel. Radar is the slow/fleet half; sentinel (if enabled) is the fast/local half. They're complementary.

## Antagonism survivors

- B4 (agent forges HVs): closed — daemon computes HVs from kernel events, signs them; agent cannot sign.
- C-variant (malicious machine ships bad HVs): closed — ed25519 signature verification at fleet sync; untrusted machines are dropped.

## Residual risks

- The soft privacy claim (D7): a determined attacker with enough HVs + known vocab could approximate inversion. Documented. Mitigation: HVs are session-level, not file-level; the vocab is event-types not file contents; and fleet sync is opt-in.
- False positives on legitimately novel work: a project doing something genuinely new will trigger local anomaly. This is why radar is advisory, not enforcing.

## Kill criterion (Phase 5)

Radar must reproduce a known-injected session as an outlier on ≥ 1 machine before any fleet claim. Without this, radar stays local-only and advisory.

## Dependencies

- `castellan-core` (SessionId, Event)
- `castellan-ledger` (kernel-witnessed event stream)
- `castellan-daemon` (signing key, fleet sync)
- Owned primitives: `sensor-hdc` (BUILT), `cortex-rs` (BUILT), `structural-core` (BUILT), `engfield` (BUILT, SDM priors).
- `ed25519-dalek` (signing).

## Status

Built (P5) and measured (V3, 2026-09-02): the kill criterion fired. On the V3
real-session corpus (20 benign sessions through the real launch path), radar's
local FP rate was **9/19 benign sessions flagged (47%)** against the
pre-registered ≤1/20 criterion — test/v3-corpus.sh, K2. The distribution is
bimodal: sparse sessions (1–2 spine events) whose token mix matches the
prototype score ~0.895; equally benign sessions with slightly different event
mixes score 0.478–0.614, below the 0.60 threshold. The threshold cannot be
fixed by tuning: the overlap between benign classes is intrinsic to
order-agnostic bundling of tiny event streams.

**Verdict: advisory-forever.** Radar stays local-only, report-only (N2: radar
anomaly logs silently, never freezes), and its anomaly output must not be
used as a gating signal anywhere. No fleet claim. The pre-registered ROADMAP
kill criterion is met in the honest direction.
