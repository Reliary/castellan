# Benchmark methodology

Castellan uses cert-evals as the methodological foundation. cert-evals is built, tested, and provides three things we need: **interleaved paired trials** (controls for the 2.7x LLM stochastic variance), **mandatory placebo control** (controls for gaming and false-positive trust signals), and **byte-reproducible SHA-256 certificates** (auditability). Verdicts are CAUSAL_IMPROVEMENT / NO_CAUSAL_EFFECT / etc., not hand-waved percentages.

## Why this methodology and not ad-hoc

The user directives are explicit:
- baseline and gate conditions must run **interleaved in the same session batch** (never sequential, never historical baselines) to control for 2.7x LLM variance from provider-side factors (cache state, load)
- weighted cost = input + 4× output tokens (output tokens cost ~2-4x more and are generated linearly) — though DeepSeek V4 Flash is 1:2, so use model-aware WC via `weighted_cost()` helper, never hardcoded
- no savings/percentage claims until results are stable and repeatable
- placebo control is mandatory for any causal claim

cert-evals implements all four. We use it unchanged.

## Per-phase kill metrics

### Phase 0 (freeze)
- **Metric:** functional — 5 concurrent sessions across 3 harness brands, zero self-thaw attempts succeed, latency < 50ms, no daemon crash on session exit.
- **Method:** not a benchmark; a deterministic acceptance test run in `test/shell.d/`.
- **No claims:** none. P0 makes no security claims.

### Phase 1 (envelope, audit mode)
- **Metric:** false-block rate on a legit Omarchy-workload corpus.
- **Corpus:** run Omarchy's own acceptance-test-like scenarios (config refresh, theme switch, package install, migration apply, hyprland edit) under audit mode; count Landlock denials on legitimate operations.
- **Kill criterion:** false-block rate < 2%. If it does not pass, Phase 1 ships audit-only indefinitely; enforce-default is deferred. No exceptions.
- **Benchmark shape:** not LLM-driven — these are deterministic shell scenarios, so interleaving isn't required. The metric is the denial count on a fixed corpus.

### Phase 2 (undo + canary)
- **Undo metric:** 20 test sessions with concurrent user edits to unrelated files; undo must reverse 100% of kernel-witnessed writes with zero collateral damage.
- **Canary metric:** 0% trip rate on 20 legit sessions; 100% trip rate on 20 sessions that attempt to use a planted canary.
- **Method:** deterministic acceptance tests, not LLM benchmarks.

### Phase 3 (trust)
- **Metric:** monotonic relationship between trust tier and user-revert outcomes on a labelled corpus.
- **Corpus:** 100 sessions labelled kept vs reverted by the user (we dogfood on our own machines to assemble this).
- **Kill criterion:** monotonic relationship (Spearman ρ > 0.3 between tier and keep-rate). If absent, trust is demoted to advisory-only — expansion gates stay at manual approval, no auto-tiering.
- **Method:** not interleaved LLM trials — this is a labelled-corpus evaluation. Interleaving applies when comparing LLM-driven conditions, not when evaluating a deterministic scoring function against labels.

### Phase 4 (proof-carrying)
- **Metric:** ProofCertificate classification accuracy on known-bad and known-good session pairs.
- **Corpus:** 20 known-bad sessions (agent removed validation, broke completeness, or wrote a fake test) + 20 known-good sessions. Constructed by us, labelled, committed to the repo as a benchmark corpus.
- **Kill criterion:** known-bad sessions classified NOT-EVIDENTIAL or WEAK; known-good classified STRONG or MODERATE. False-negative rate on known-bad < 20%. We accept relay-vuln is grammar-free and not perfect — the proof is honestly labeled "best-effort detection," not "proven safe."
- **Method:** deterministic — the corpus is fixed, the classifier is deterministic, so no interleaving needed.

### Phase 5 (radar + sentinel)
- **Radar kill criterion:** reproduces a known-injected session as an outlier on ≥ 1 machine before any fleet claim.
- **Sentinel kill criterion:** AUROC > 0.7 on a real (non-synthetic) labelled corpus. If absent, sentinel stays off-by-default and advisory-only forever. We do NOT cite the synthetic AUROC 1.0.

## What we never claim without benchmark backing

- Any percentage savings on tokens, time, or cost.
- Any security guarantee ("proven safe," "cannot be bypassed," "100% detection").
- Any AUROC without a real labelled corpus.
- Any improvement over baseline without interleaved trials and placebo control.

## What we DO claim, and how

- Functional acceptance: "freeze works on N harnesses with zero self-thaw" — deterministic test, no variance.
- Best-effort detection: "relay-vuln flags X% of known-bad sessions, with Y% false-negative rate, on this labelled corpus" — honest numbers, labelled corpus, no generalization claim.
- Causal improvement (when applicable): via cert-evals verdicts (CAUSAL_IMPROVEMENT / NO_CAUSAL_EFFECT), interleaved, placebo-controlled, SHA-256 cert.
- Residual risks: documented in THREAT_MODEL.md, repeated in any PR description that touches the relevant surface.

## LLM-driven benchmarks (when we need them)

For benchmarks that compare agent behavior with and without castellan (e.g., "does enforced envelope change task success rate?"), we use:
- **Interleaved paired trials** in a single session batch (cert-evals).
- **Model-aware weighted cost** via `weighted_cost()` from `scripts/bench_lib.py` — never hardcoded 4×. DeepSeek V4 Flash is 1:2 input:output; other models differ.
- **300s+ turn timeouts** for multi-turn benchmarks (accumulated conversation + test outputs need more than the 120s single-turn default).
- **Single accumulated multi-turn session** per condition, not independent single-turn calls — IR compression, sift, and conv-window only exercise under accumulated history.
- **Kill the old daemon before starting a fresh binary** — stale daemon with different cache-key schema causes collision bugs.
- **Check `/tmp/reliary_proxy.jsonl` for SSE stream-ended errors** before attributing outlier tokens to castellan — broken streams produce 0-token outputs that look like compression wins but are actually failures.

## Corpus we need to build before P1 can ship

A "legit Omarchy workload corpus" — deterministic shell scenarios exercising the operations an agent legitimately does on an Omarchy machine:
- refresh a config (hypr/hyprland.lua, waybar, quickshell)
- switch theme
- install a package (pacman + AUR paths)
- apply a migration
- edit a Hyprland binding
- write to ~/.local/bin
- run a build in ~/Work/<project>
- read system state (ls /etc, read configs)

Run each under audit mode; count denials. This corpus is committed to the repo as `test/corpus/legit-omarchy-workload/` and is the Phase 1 kill-metric input.
