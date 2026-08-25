# Sentinel

The regime-detection hint component. **Off-by-default. Advisory-only.** Detects behavioral anomalies in the live event stream via z-score on windowed means. Does NOT auto-freeze (D4). Feeds trust (decrement) and notifications only.

## Why off-by-default

sensor-regime's AUROC 1.0 is on **synthetic data (3 seeds)**. There is no real labelled corpus. Claiming AUROC would violate the honesty directives. Sentinel ships off-by-default; it must show AUROC > 0.7 on a real labelled corpus before it can even be toggled on by users, and it stays advisory-only (no enforcement) forever unless a separate decision record promotes it.

## Mechanism (when enabled)

- The daemon feeds the kernel-witnessed event stream (per session) to a sensor-regime RegimeDetector.
- Stream features: write rate (writes/min), sudo attempts, new network destinations, config-dir touch attempts, envelope-escape attempts.
- z-score on windowed means against a fixed baseline (the project's historical norm, learned during normal use).
- Sustained deviation (z > threshold) → regime switch detected.

## What it does on detection

- **Notify:** "Session `<uuid>` behavior off-distribution (write rate 4x baseline). Review?"
- **Decrement trust:** −5 per sustained deviation.
- **Tag the event spine:** `source: sentinel, type: regime_anomaly`.
- **NOT auto-freeze** (D4). Only deterministic canary hits auto-freeze.

## Why not auto-freeze

The honest answer: we don't have the labelled corpus to tune the threshold. Auto-freezing on a synthetic-tuned threshold would either freeze too many legit sessions (false positive) or miss real attacks (false negative). Without real data, the only honest choice is advisory. The canary-credential trigger is deterministic and high-specificity, so it CAN auto-freeze. Sentinel is probabilistic and unvalidated, so it CANNOT.

## Antagonism survivors

- D4 (sentinel auto-freeze killed): closed — demoted to hint, no auto-freeze.

## Residual risks

- False positives on legitimately intense work (a big refactor has a high write rate). Advisory-only limits the harm.
- No real-corpus validation yet. The Phase 5 kill criterion (AUROC > 0.7 on real labeled corpus) gates any expansion.

## Dependencies

- `castellan-ledger` (event stream)
- `castellan-trust` (decrement on detection)
- Owned primitive: `sensor-regime` (BUILT, synthetic-only — honestly labeled).
- NOT used: `constellation-drift` (KILL), `half-life` (KILL).

## Status

Wired from owned primitive. Off-by-default. Phase 5, hint plane. Must pass AUROC > 0.7 on real labelled corpus or stays off forever.
