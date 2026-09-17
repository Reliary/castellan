# Proof-carrying sessions

Every session ends with a ProofCertificate: stayed in bounds, passed
placebo-controlled proof, with the spine hash-chain verdict and an optional
ed25519 signature. **The agent is the prover; the daemon is the verifier.**
**Built** (P4 assembly, chapter 5 signing). This doc describes the implemented
certificate and marks, explicitly, what is designed-but-not-built.

## What actually shipped

- **Bounds proof** — counts of kernel-witnessed in-bounds writes and
  out-of-bounds attempts, from the event spine.
- **Placebo proof** — row-level from the trust ledger for THIS session:
  `proofs_passed` (pair-placebo) and `test_rerun_passed` (Factor A).
- **Census attestation** — `Some((found, killed))` when the session-end
  orphan census ran (N6).
- **Artifact scan** — findings-only-negative; a finding delta names the
  scanner, a clean delta is `None` (no claim).
- **Spine chain (S1)** — `checked`/`tip`/`intact`/`broken_at` from
  `EventSink::verify_chain`. `None` = no chained spine.
- **Signature (S2)** — detached ed25519 over canonical (signature-stripped)
  JSON; `None` = unsigned and the CLI says so. `castellan verify` checks the
  signature (optional pinning) and the embedded chain verdict.

**Designed, not built** (present in the schema below for the record only):
a separate relay-vuln "validation-path proof" crate, a config-radar
"completeness proof", a Merkle `audit_chain` with signed tree heads, and
cross-machine fleet transfer. The implemented artifact-scan factor is the
scanner hook; the dedicated crates and the transparency log are deferred.

## ProofCertificate schema (implemented)

```json
{
  "session": "s...",
  "project": "/path/to/project",
  "generated_at": 1234567999,
  "bounds": { "writes_inside": 12, "out_of_bounds_attempts": 0, "verdict": "STAYED_IN_BOUNDS" },
  "placebo": { "proofs_passed": 1, "test_rerun_passed": false, "verdict": "PLACEBO_CONTROLLED_PASS" },
  "census": [1, 1],
  "artifact_scan": null,
  "spine_chain": { "checked": 14, "tip": "9f...", "intact": true, "broken_at": null },
  "signature": { "public_key": "a6...", "signature": "3c...", "scope": "integrity and provenance within this boot; not non-repudiation against a same-uid adversary with kernel access" },
  "quality_label": "MODERATE"
}
```

## The proofs (implemented)

### 1. Bounds proof
From the kernel-witnessed event spine. `verdict: STAYED_IN_BOUNDS` if zero
out-of-bounds attempts. Fail → `OUT_OF_BOUNDS_ATTEMPT` and the certificate is
NON-EVIDENTIAL.

### 2. Placebo test proof (the un-gameable positive signal)
Row-level OR, cert-level AND (see C12 in DESIGN_DECISIONS.md):
- **Factor A — daemon re-run:** the daemon independently re-runs the
  pre-existing test suite (unmodified by the session) from a config-pinned
  command. Agent-reported results do not count. Each pass earns its own
  `proof_passed` ledger row (`evidence` "test suite").
- **Factor B — placebo control:** the session's actual edit (orig → new) must
  drop the danger_signal more than a neutral placeholder would. `assert True`
  and no-op edits fail; a real guard that drops danger passes. Each passing
  file earns its own `proof_passed` ledger row (`evidence` "placebo-controlled").
- Factor A is skipped and honestly labeled `test_rerun_passed: false` when the
  project configures no test command.

### 3. Artifact scan (P9.2)
A pluggable scanner (relay-vuln or semgrep) runs at the keep gate over the
session's touched files. **Findings-only-negative:** a new finding produces a
factor and a `vuln_introduced` event; a clean delta is `None` (no claim). The
cert states the scanner's scope and that absence of findings is not evidence of
safety.

### 4. Spine chain + signature (chapter 5)
The spine is a sha256 hash chain; `verify_chain` reports the first broken link.
The certificate is signed with an in-process ed25519 key (memory-only,
non-dumpable daemon — S0 probe). `castellan verify` re-checks both.

## Quality labels (implemented)

- **STRONG:** in bounds + placebo proof + test re-run.
- **MODERATE:** in bounds + one positive factor (placebo or tests).
- **WEAK:** in bounds, no positive evidence.
- **NON-EVIDENTIAL:** out-of-bounds attempt, or no event spine.

The validation-path and completeness proofs are NOT part of the label today
(they were designed, not built); the artifact scan is reported as a factor but
does not raise the label.

## Daemon as verifier (commitment #3)

The agent does NOT generate the certificate. The daemon assembles it from the
kernel-witnessed spine, the trust ledger (scoped to this session), the census
file, the scanner evidence, and — when a key exists — signs it.

## Residual risks

- Scanner false negatives: the artifact scan is best-effort, labeled per
  finding and findings-only-negative. No "proven safe" claim.
- Proof coverage: a read-only session has no placebo evidence → WEAK at best.
- **Signature scope:** the key and the anchor (spine) live on the same
  machine, so a signature proves integrity/provenance **within a boot**, not
  non-repudiation against a same-uid adversary with kernel access. Cross-machine
  trust transfer is designed, not built.
- A compromised daemon key is out of scope (kernel-level compromise).

## Dependencies (implemented)

- `castellan-core` — `Event` with `prev`/`hash`, `EventSink::verify_chain`,
  `ChainVerdict`.
- `castellan-proof` — `certificate` (assembly) and `signing` (ed25519).
- `castellan-trust` — ledger rows feeding the placebo factor.
- `castellan-ledger` — overlay diff for the pair-placebo.
- Scanner adapter (P9.2) — relay-vuln or semgrep behind one interface.
- CVEfixes DB: local at `/home/john/data/`, never shipped.

## Status

Built: assembly (P4), hash chain + signing (chapter 5). Kill criterion met on
a scripted corpus (P4, 0/20 FN both arms) and the crypto properties verified
live (test/shell.d/ch5-proof.sh 8/8). Not built: dedicated validation-path and
completeness crates, Merkle transparency log, fleet transfer.
