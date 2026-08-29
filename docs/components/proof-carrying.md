# Proof-carrying sessions (designed core)

Every session ends with a cryptographic ProofCertificate: stayed in bounds, didn't remove validation paths, preserved config completeness, passed placebo-controlled tests. Tamper-evident, exportable, transferable. **The agent is the prover; the daemon is the verifier.** Not built yet — this doc is the design.

## Why we think this is worth building

Proof-carrying code (Necula, 1990s) externalized verification from the runtime to a certificate. Castellan generalizes relay-vuln's ProofCertificate from "this code is vuln-free" to "this session was safe." The placebo control is the candidate answer to the gaming problem: self-reported "tests passed" is worthless, but a neutral-placeholder comparison plus a daemon-side re-run is harder to fake. Whether it survives contact with real agents is exactly what the P4 kill criteria test.

Nothing here is unbuildable by others: Landlock/cgroup plumbing is documented syscall work, and the proof composition is just engineering. Our advantage is inventory and momentum — internal primitives (relay-vuln, proof-fixes, cert-evals, evidence-pack, seq-engine, config-radar, agent-audit-trail) already exist and were benchmarked for other purposes, so the composition cost for us is lower than for a cold start. See docs/PRIMITIVES.md for honest verdicts, including primitives that died in real-data testing (refactor-proof: KILL).

## ProofCertificate schema

```json
{
  "session_uuid": "...",
  "project_hash": "blake3",
  "started_at": 1234567890,
  "ended_at": 1234567999,
  "envelope_profile": "tier2",
  "bounds_proof": {
    "kernel_witnessed_writes": [...],
    "out_of_bounds_attempts": 0,
    "verdict": "STAYED_IN_BOUNDS"
  },
  "validation_path_proof": {
    "scanner": "relay-vuln",
    "missing_validation_paths_found": 0,
    "evidence_tuples": [],
    "verdict": "NO_VALIDATION_PATH_REMOVED"
  },
  "completeness_proof": {
    "config_scanner": "config-radar",
    "missing_keys": [],
    "verdict": "COMPLETENESS_PRESERVED"
  },
  "placebo_test_proof": {
    "pre_existing_tests_re_run_by_daemon": true,
    "tests_passed": true,
    "danger_signal_drop_real_fix": 0.78,
    "danger_signal_drop_placebo": 0.03,
    "placebo_delta": 0.75,
    "verdict": "PLACEBO_CONTROLLED_PASS"
  },
  "audit_chain": {
    "trail_root_hash": "...",
    "trail_verified": true,
    "kernel_vs_agent_mismatches": 0
  },
  "quality_label": "STRONG",
  "signature": "ed25519:..."
}
```

## The four proofs

### 1. Bounds proof
From the kernel-witnessed event spine (overlayfs upper layer + inotify on expanded paths). `verdict: STAYED_IN_BOUNDS` if zero out-of-bounds attempts and all writes were inside the envelope allow-set. Fail → `OUT_OF_BOUNDS_ATTEMPT` (trust takes the −20 hit, certificate is WEAK).

### 2. Validation-path proof
relay-vuln scans post-edit state for missing-validation-path patterns (the `missing_space.rs`, `path_vuln.rs`, `validation_density.rs` detectors). Produces EvidenceTuples. `verdict: NO_VALIDATION_PATH_REMOVED` if zero findings. **Honest limit:** relay-vuln is grammar-free with false negatives — this proof is labeled "best-effort detection," not "proven safe." Quality label reflects this: if validation-path proof is the only positive evidence, the certificate is at most MODERATE.

### 3. Completeness proof
config-radar checks for missing config keys (per-format extractors: YAML/TOML/JSON/HCL/INI/.env/Dockerfile/NGINX). `verdict: COMPLETENESS_PRESERVED` if it passes. Failure → `COMPLETENESS_BROKEN` (certificate is WEAK or NON-EVIDENTIAL). **seq-engine was KILLed 2026-08-27** — the expected-pair auditor is tautological on event-derived token sets (78% of learned expectations co-emitted by the same event), learns zero expectations on composite-only encoding, and its ordered fingerprints add no separation over radar's order-agnostic encoding on real spines. See PRIMITIVES.md.

### 4. Placebo test proof (the un-gameable positive signal)
Two-factor, both required:
- **Factor A — daemon re-run:** the daemon independently re-runs the pre-existing test suite (tests that existed pre-session AND were unmodified by the session) in a side-scope reading post-edit state. Must pass. Agent-reported results do not count. (commitment #3)
- **Factor B — placebo control:** a real fix (the session's actual edits) must drop the danger_signal more than a neutral placeholder would. proof-fixes methodology: apply the real fix, measure danger_signal; apply a neutral placeholder (e.g., a no-op comment), measure danger_signal; the real fix must drop more. `assert True` and "delete the dangerous line" both fail this — they're placebos that don't differentially drop danger. (commitment: placebo control mandatory for any causal claim)

`verdict: PLACEBO_CONTROLLED_PASS` only if both factors pass. This is the ONLY positive trust signal (Phase 3).

## Quality labels (from evidence-pack)

- **STRONG:** all four proofs pass, audit chain verified, zero kernel-vs-agent mismatches.
- **MODERATE:** bounds + placebo pass; validation-path or completeness has minor findings (within relay-vuln's known false-negative rate, honestly labeled).
- **WEAK:** bounds passes but placebo fails, OR validation-path/completeness has significant findings.
- **NON-EVIDENTIAL:** out-of-bounds attempts, or audit chain broken, or kernel-vs-agent mismatches.

## Daemon as verifier (commitment #3)

The agent does NOT generate the certificate. The daemon does, from:
- kernel-witnessed event spine (bounds, audit chain)
- daemon-re-run test results (placebo factor A)
- relay-vuln scan of post-edit state (validation-path — daemon calls relay-vuln as a Rust crate; relay-vuln reads state directly, not agent-reported)
- config-radar scan of post-edit state (completeness — same)
- proof-fixes placebo computation (daemon invokes proof-fixes; the danger_signal comparison is done by proof-fixes reading state, not by the agent)

The agent's audit-trail is cross-checked against kernel truth (mismatches decrement trust and weaken the certificate) but is never the source of truth.

## Transfer (fleet trust, Phase 5)

Verified ProofCertificates raise a project's trust tier. A fleet of verified sessions = a reputation system with cryptographic, placebo-controlled backing. Composed from:
- engfield SDM (predictive memory: prior verified sessions influence context, zero-token)
- cortex-rs consolidation (verified sessions promote to consolidated tier)
- evidence-pack export (portable certificate format)
- agent-audit-trail (tamper-evident backing)

HV fingerprints of verified sessions sync across machines via Omarchy's usage-sync-folder, signed per-machine (commitment #9). A new machine joining a project sees "this project has 47 verified sessions across 3 machines" and starts at a higher tier.

## Antagonism survivors

- A5 (fake tests): closed — placebo + daemon re-run + pre-existing-only.
- A6 (fake placebo): closed — two-factor.
- A9 (proof replay): closed — session-bound (UUID + cgroup start + ledger hash).
- B1 (agent lies about tests): closed — daemon re-runs.
- B6 (agent tampers with audit trail): closed — hash chain + kernel cross-check.
- D1 (refactor-proof killed): closed — placebo control replaces it.

## Residual risks

- relay-vuln false negatives: validation-path proof is best-effort, not proven-safe. Labeled honestly in quality labels (MODERATE at best if validation-path is the only positive).
- Proof coverage: if a session made no edits (read-only), the placebo proof is vacuous. Certificate is MODERATE ("no harm done, no benefit proven") rather than STRONG.
- Cross-machine trust transfer assumes the machines share a project definition (realpath hash). A malicious machine could ship fabricated certificates — defeated by ed25519 signatures (commitment #9), but a compromised daemon key is residual.

## Kill criterion (Phase 4)

20 known-bad sessions (agent removed validation, broke completeness, or wrote a fake test) classified NOT-EVIDENTIAL or WEAK; 20 known-good sessions classified STRONG or MODERATE. False-negative rate on known-bad < 20%. We accept relay-vuln is grammar-free and not perfect — the proof is honestly labeled "best-effort detection," not "proven safe."

## Dependencies

- `castellan-core` (ProofCertificate type)
- `castellan-ledger` (kernel-witnessed events)
- `castellan-trust` (certificate feeds positive signal)
- Owned primitives (all Rust crates, linked into the daemon — no Python in the trusted path):
  - `relay-vuln` (validation-path, EvidenceTuple, ProofCertificate origin pattern — already pure Rust, 52K LOC)
  - `castellan-proof` export module (was evidence-pack — rewritten as Rust, quality labels via serde)
  - `castellan-proof` placebo module (was proof-fixes — rewritten as Rust, placebo orchestration over relay-vuln)
  - `cert-evals` (benchmark methodology, SHA-256 cert — stays Python, dev/CI only, NOT in daemon)
  - `castellan-completeness` (was config-radar — rewritten as Rust; seq-engine KILLed 2026-08-27, see PRIMITIVES.md)
  - `castellan-ledger` audit chain (was agent-audit-trail — rewritten as Rust hash chain)
  - `engfield` (Phase 5 priors — already has 2183 LOC Rust, link as crate)
  - `cortex-rs` (Phase 5 consolidation — already pure Rust, link as crate)
- CVEfixes DB: local at `/home/john/data/`, never shipped.

## Status

Greenfield certificate assembly; owned scanner pipeline. Phase 4, ~3 weeks. This is the contribution worth being patient for.
