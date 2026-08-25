# Trust

Per-project, deterministic trust score gating ONLY envelope expansion (egress unlock, config-dir writes). Never gates the envelope floor. Cold start at tier 2 (full-auto within workspace). Ceiling at tier 5. Always-on deny-list regardless of tier (commitment #6).

## Why this design and not the obvious one

The obvious design: "trust gates how much the agent can do." Killed by D5 — cold-start gating punishes power users and conflicts with Omarchy's ethos. The hardened design: "the envelope is always on (the floor); trust gates only the ceiling (expansion)." Power users get full-auto within the workspace from day one. Safety is the kernel floor; trust is the ceiling.

## Scoring

Per-project EWMA in [0, 100]. Events feed it from the kernel-witnessed event spine and the daemon-verified proof pipeline. **No time-decay** — half-life is KILLed (D2). Cortex-rs tier-promotion (recall-based: 10+ recalls promote episodic → semantic → consolidated) is the decay substitute if one is needed; v0 ships without decay.

### Positive signals (hard to game)
- **+10** placebo-controlled proof passed: a real fix dropped danger_signal more than a neutral placeholder, AND the daemon independently re-ran the pre-existing test suite and it still passes. Two-factor. This is the only positive signal that raises tier. See proof-carrying.md.
- **+1** clean session (no reverts, no envelope-escape attempts, no canary hits, non-empty ledger).

### Negative signals (dominant — trust is negative-dominant)
- **−30** user reverted the session (`castellan undo <session>` invoked).
- **−20** envelope-escape attempt detected (Landlock/seccomp denial logged).
- **−50** canary credential hit (auto-freeze triggered).
- **−10** audit-trail-vs-kernel-truth mismatch (agent claimed X, kernel witnessed Y).
- **−∞ (hard floor 0)** bless-broker forged nonce attempt (session killed, project frozen at tier 0 pending human review).

### Anti-gaming
- Tests added or modified by the session don't count toward the positive signal (only pre-existing tests, daemon-re-run).
- Sybil defense: trust is per-project; sessions must have a non-empty kernel-witnessed ledger; ceiling per time-window (cannot jump tiers in one day).
- Slow-drip: residual (D7/A8) — ceiling + deny-list means worst-case = egress unlock, not escape. Egress proxy restricts reach even when unlocked.

## Tier → envelope profile mapping

| Tier | Score | Workspace | Egress | Config-dir writes | System config |
|---|---|---|---|---|---|
| 0 | 0-19 | full-auto | none | none (plan-only mode) | none |
| 1 | 20-49 | full-auto | none | via bless broker | none |
| 2 | 50-79 | full-auto | via proxy (allowlist) | via bless broker | none |
| 3 | 80-99 | full-auto | broader allowlist | auto-approved (kernel-logged) | via bless biometric |
| 4 | 100 | full-auto | broad | auto-approved | via bless biometric |

Always-on deny-list (commitment #6) regardless of tier: `~/.ssh`, `~/.gnupg`, `.desktop` files, shell rc files.

## Cold start

New project: tier 2 (50). Full-auto within workspace, no egress, config-dir via bless. Power users keep full-auto within workspace from the first session. The floor is the safety; the ceiling is earned.

## "Why am I tier 2?" — fully reconstructible

`castellan-trust explain <project>` prints the full event ledger that produced the current score: every positive and negative signal, with timestamps, session UUIDs, and the kernel-witnessed evidence. Audit-grade. No black box.

## Storage

Single-writer SQLite at `~/.local/state/castellan/trust.db`. Owned by the daemon. Per-project keyed by realpath blake3. Schema:

```
projects(realpath_hash TEXT PK, score REAL, tier INT, last_event_ts INT)
events(id INTEGER PK, realpath_hash TEXT, ts INT, session_uuid TEXT, signal TEXT, delta REAL, evidence_json TEXT)
```

## Sync (Phase 5, opt-in)

Trust can sync across machines via Omarchy's existing usage-sync-folder mechanism. Syncs only the score + tier + event deltas, not file contents. Useful for "my laptop trusts what my desktop trusts."

## Antagonism survivors

- A5 (fake tests): closed — placebo control + daemon re-run + pre-existing-only.
- A6 (fake placebo): closed — two-factor (danger-drop + existing-tests-still-pass).
- A7 (Sybil): closed — per-project, non-empty-ledger, ceiling per window.
- A8 (slow-drip): residual, mitigated by ceiling + deny-list + egress proxy.
- D2 (half-life killed): closed — no time-decay, cortex-rs tier-promotion if needed.
- D5 (cold-start punishes): closed — floor always on, trust gates only ceiling.

## Kill criterion (Phase 3)

Monotonic relationship between trust tier and user-revert outcomes on a labelled corpus (Spearman ρ > 0.3 between tier and keep-rate). If absent, trust is demoted to advisory-only — expansion gates stay at manual approval, no auto-tiering. The badge in the agents panel shows the score but no gating happens.

## Dependencies

- `castellan-core` (TrustTier, EnvelopeProfile)
- `castellan-ledger` (event spine)
- `castellan-proof` (positive signal — placebo-controlled proof)
- `castellan-freezer` (revert signal — `castellan undo` invokes freeze)
- Owned primitives (all Rust, linked as crates): `cortex-rs` (BUILT, tier-promotion if decay needed), `castellan-proof` placebo module (was proof-fixes, rewritten as Rust), `cert-evals` (BUILT, stays Python for dev/CI benchmarking only — NOT in daemon).
- NOT used: `refactor-proof` (KILL), `half-life` (KILL).

## Status

Greenfield scoring engine; owned positive-signal pipeline. Phase 3, ~2 weeks.
