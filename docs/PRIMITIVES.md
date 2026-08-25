# Owned primitives inventory

Every primitive we already have, with its **real-data verdict** (where one exists) and its role in castellan. Primitives marked KILL or MARGINAL are demoted to advisory-only or dropped — they are NOT load-bearing.

## Built and load-bearing for castellan

| Primitive | Repo | Lang | Verdict | Castellan role |
|---|---|---|---|---|
| agent-audit-trail | agent-audit-trail | Python | PASS | advisory event layer (tamper-evident hash chain); compared against kernel truth for mismatches |
| agent-profile | structural-stack/agent-profile | Rust | BUILT (442 LOC) | session fingerprint + drift detection; auto-detects Cursor/Claude/Aider/JSONL |
| carrion | carrion | Rust | BUILT (227 LOC) | dead-code detection; reused for harness-state anomaly baseline |
| cert-evals | cert-evals | Python | BUILT | benchmark methodology — interleaved + placebo + SHA-256 cert; directly satisfies the interleaving directive |
| config-radar | config-radar | Rust | BUILT (validated) | post-session completeness check (missing config keys); proof-carrying component |
| cortex-rs | cortex-rs | Rust | BUILT (~3000 LOC) | tier-promotion trust engine (recall-based, NOT time-decay); consolidation; Hebbian HV |
| engfield | engfield | Rust | BUILT (substantial) | predictive memory priors, SDM 65K locations, zero-token context influence; opt-in Phase 5 |
| evidence-pack | evidence-pack | Python | BUILT (256 LOC) | ProofCertificate export format with STRONG/MODERATE/WEAK/NON-EVIDENTIAL quality labels |
| fp-toggle | fp-toggle | Shell + systemd | BUILT (shipped) | biometric thaw for the freezer and high-risk bless-broker approvals |
| git-archaeology | structural-stack/git-archaeology | Rust | BUILT (538 LOC) | architecture-shift detection (Tukey fence on inter-commit fingerprint distance) |
| llm-replay | llm-replay | Python | PASS | deterministic replay keyed by (model, messages_hash); forensic replay component |
| proof-fixes | proof-fixes | Python | BUILT (BUILD verdict) | placebo-controlled fix application; the positive trust signal methodology |
| relay-vuln | relay-vuln | Rust | BUILT (136 modules, 49GB DB) | proof-carrying vuln detection, missing-validation-path, EvidenceTuple; DB stays local |
| seq-engine | seq-engine | Python + Rust stub | BUILT (Python 745 LOC) | completeness auditor (expected token pairs, drift/R0); proof-carrying component |
| sift | sift | Rust | BUILT | output compression for notifications and command logs |
| skein | skein | Rust | BUILT (203 LOC) | vocabulary fingerprint diffing; harness-state-watcher baseline |
| spec-exec | structural-stack/spec-exec | Rust | BUILT (647 LOC) | speculative next-action prediction; forensic replay component |
| stria | stria | Rust | BUILT (8050 LOC) | edit guard / contract / verify-packet; edit confinement in observation plane |
| structural-core | structural-stack/core | Rust | BUILT (413 LOC) | shared HDC + fingerprint + Mellin + R0 primitives; foundation for radar |

## Built but KILLed or MARGINAL — advisory-only, NOT load-bearing

| Primitive | Repo | Verdict | Why | Castellan role (if any) |
|---|---|---|---|---|
| refactor-proof | refactor-proof | KILL | 100% false-negative on Defects4J — real bugfixes change operators/args, not line shapes | NONE. Was originally the trust positive signal; replaced by placebo-controlled proof-fixes |
| half-life | half-life | KILL | vocabulary persistence decay falsified as a signal | NONE. Trust uses cortex-rs tier-promotion (recall-based) instead. No time-decay. |
| vuln-fix-genome | vuln-fix-genome | KILL | BLAST-for-security lookup, falsified | NONE |
| sec-commit-label | sec-commit-label | MARGINAL | k-NN retroactive tag, not predictive | advisory hint only, off-by-default |
| constellation-drift | constellation-drift | KILL | p=0.43, AUROC 0.557 on SPY | NONE |
| agent-log-compress | agent-log-compress | KILL | loses to zlib (5.56x vs 11.25x) | NONE (sift wins) |

## Built, experimental — off-by-default, hint plane only

| Primitive | Repo | Verdict | Castellan role |
|---|---|---|---|
| sensor-regime | sensor-regime | BUILT (synthetic AUROC 1.0 on 3 seeds — NOT real data) | sentinel hint; off-by-default; must show AUROC > 0.7 on real labelled corpus or stays off forever |
| sensor-hdc | sensor-hdc | BUILT (286 LOC) | HV radar encoding; zero-dep |

## Greenfield (no owned primitive — must be built fresh)

| Castellan component | What's missing |
|---|---|
| envelope (Landlock + seccomp) | no Landlock/seccomp anywhere in our repos |
| freezer (cgroup.freeze ownership) | no cgroup delegation code anywhere |
| undo (overlayfs + user namespaces) | no overlayfs/user-ns anywhere |
| ledger (inotify watchers) | no inotify anywhere |
| egress proxy | no HTTP proxy with credential injection anywhere (reliary-agent's proxy was REMOVED in v0.8.0) |
| canary-credentials + honeypot | no honeypot listener anywhere |
| bless-broker | no dbus nonce-gated approval flow anywhere |
| daemon | reliary-agent daemon PATTERN exists (TCP line protocol) but the castellan daemon is new code |

## Removed / abandoned (do not cite as owned)

| Primitive | Repo | Status |
|---|---|---|
| callgraph_v2 | reliary-agent (pre-v0.8.0) | REMOVED in strip; recoverable via git tag `1278ce4b` but not in HEAD |
| fuzzy/byte-span edit repair | relay | NOT-FOUND; relay has exact replace + validate only |
| auto-deescalation modes (fast/reactive/strict) | harness/gate.js | NOT-FOUND in harness/; was reliary-agent proxy logic, REMOVED in v0.8.0 |
| HTTP proxy | reliary-agent | REMOVED in v0.8.0 (proxy.rs 965 LOC) |
| MCP SSE transport | reliary-agent | REMOVED in v0.8.0 (mcp_sse.rs 242 LOC) |
| 39 research modules (HDC/PPR/LSA/NCD/density/spectral/homology/transport/belief_prop/info_bottleneck/hopfield/dmrg/holographic/ryu_takayanagi/correlation/persistent_lap/rough_sets/consensus/interactions/robust/router/fusion/hybrid/arc10_ensemble/boltzmann/graph_iso/text_sim/negative/rich_features/rich_gate/salience/expr_tree/refal/op_table/node_classifier/signature/scope_types/scope_query/type_inference/type_flow/full_file/cross_file_method/file_meta/lazy_tables/ft_weight/block_lookup/callgraph_match/exact/pattern/phrase_index/qualified/similar/structural) | reliary-agent | REMOVED in v0.8.0 strip (~8642 LOC); recoverable via git tag `1278ce4b` |

## CVEfixes DB location correction

The DB is at `/home/john/data/cvefixes/cvefixes.db` (49.3 GB) and `/home/john/src/ideation-data/cvefixes/cvefixes_v3.db` (49.3 GB). It is NOT at `~/.cache/relay-vuln/` (that directory does not exist). The DB never ships, never gets committed, never gets vendored. relay-vuln integration is strictly local and opt-in.

## What this inventory changes about the architecture

1. The enforcement plane is entirely greenfield. Honest framing: owned primitives cover observation + analysis; enforcement is new Rust.
2. The trust positive signal is placebo-controlled proof (was proof-fixes in Python, rewritten as Rust in castellan-proof), NOT refactor-proof (which is KILLed). This is the commitment #3 verifier pattern.
3. Trust uses cortex-rs tier-promotion (recall-based), NOT half-life (KILLed). No time-decay unless a future real-data verdict revives it.
4. Output compression is sift, NOT agent-log-compress (KILLed).
5. The daemon pattern is reused from reliary-agent (unix socket, lock-protected state), but the daemon code is new.
6. The HTTP proxy from reliary-agent is gone — the egress proxy is built fresh, with credential injection (a different threat model than reliary's pass-through).
7. **The daemon is pure Rust — no Python subprocess in the trusted path.** relay-vuln is already pure Rust (52K LOC, links as a crate). skein, carrion, sensor-hdc, cortex-rs, config-radar, engfield, stria are already Rust. The four Python-only primitives in the daemon's path (agent-audit-trail 109 LOC, evidence-pack 302 LOC, proof-fixes 270 LOC, seq-engine 1368 LOC) are rewritten as Rust crates (~2050 lines total, all algorithmic). cert-evals and llm-replay stay Python — they're dev/CI tooling, not shipped, not in the daemon.
