# Roadmap

Six phases. Each phase has a **kill criterion**: if the criterion fails, the phase does not advance and either ships in a reduced form (audit-only, advisory-only) or is killed entirely. No phase ships enforce-by-default until its kill criterion passes via the [benchmark methodology](benchmark-methodology.md).

## Phase 0 — Substrate + freeze + QML toggle

**Scope:** session identity (systemd user scope + env tag), cgroup.freeze wiring with daemon-owned freezer (commitment #1), Hyprland global keybind Super+Escape, top-bar toggle in the Omarchy agents panel, terminal-cooperative "FROZEN" status line, time-bounded freeze (auto-escalate to kill at 5min), fp-toggle biometric thaw.

**Deliverables:**
- `castellan-daemon` skeleton (unix socket, scope creation via zbus/dbus, freezer ownership)
- `castellan-freeze` CLI shim (toggle/all/status)
- Quickshell QML plugin for the agents panel
- Hyprland keybind config
- fp-toggle integration for thaw

**Kill criterion:** freeze + thaw works on 5 concurrent sessions across 3 harness brands (claude, codex, pi) with zero self-thaw attempts succeeding. Latency < 50ms. No daemon crash on session exit.

**Dependencies:** none (this is the wedge).

**Estimated effort:** 1 week. Smallest possible PR to upstream Omarchy; zero threat-model stakes; delightful demo.

**Upstream shape:** single PR adding `omarchy-freeze` command + QML plugin. No Landlock, no claims.

## Phase 1 — Envelope floor (audit mode)

**Status: BUILT (core).** `castellan-policy` + `castellan-envelope` crates, `castellan launch [--enforce] -- cmd`, `castellan audit <session>`, event spine (events.jsonl), harness-state snapshot/diff at session end. Acceptance 13/13 PASS on kernel 7.0.3 (Landlock ABI 8): enforce allows workspace writes / denies home writes with EACCES; git workload runs clean under enforce; ptrace returns EPERM under seccomp; audit classifies would-deny writes. Remaining P1 scope: blake3 before-images (moves to undo substrate), agent-audit-trail advisory tagging, omarchy launch-path integration.

**Scope:** Landlock + seccomp envelope minter (commitments #8), wrapper around Omarchy's existing agent launch path (`omarchy-launch-agent`), inotify-ledger on allowed paths, agent-audit-trail wired in (advisory vs kernel-truth tagging), harness-state-watcher (skein/carrion baseline). Default mode: **audit** (deny logged, not enforced) for upgraders; **enforce** only for fresh installs.

**Deliverables:**
- `castellan-envelope` crate (Landlock ruleset minting, seccomp BPF generation) ✅
- `castellan-policy` crate (pure classification, unit-tested) ✅
- event spine: events.jsonl per session ✅
- harness-state-watcher snapshot/diff ✅
- `castellan-ledger` crate (blake3 before-images — deferred to overlayfs undo substrate)
- agent-audit-trail integration
- `omarchy-launch-agent` wrapper replacing direct mise-stub exec

**Kill criterion:** false-block rate < 2% on a legit Omarchy-workload corpus (run Omarchy's own acceptance-test-like scenarios under audit mode, count denials on legitimate operations). If the metric does not pass, Phase 1 ships audit-only indefinitely and enforce-default is deferred. No exceptions.

**Dependencies:** Phase 0 (substrate).

**Estimated effort:** 2-3 weeks. Landlock + seccomp is greenfield Rust; no owned primitives here. This is the build-cost bottleneck.

**Upstream shape:** PR series — first the wrapper in audit mode (no behavior change for users, just logging), then enforce-default for fresh installs behind a migration.

## Phase 2 — Surgical undo + canary credentials

**Status: BUILT.** `castellan-ledger` crate: unprivileged overlayfs over the project in a user+mountain namespace, upper-layer diff (creations/modifications/whiteout-deletions), discard (undo), and commit (keep). `castellan launch --undo -- cmd`; CLI verbs `diff|undo|keep <session>`. Acceptance 17/17 PASS: session writes fully invisible to the real project; diff names every change incl. deletions; discard restores exactly; commit materializes changes + deletions. P0/P1 regressions still 15/15 and 13/13. `castellan-canary` crate: plants fake AWS/GitHub/npm creds in session scratch, registers them with a localhost honeypot; any connection whose bytes contain a canary secret trips (logs canary_trip event, freezes the session via cgroup). Landlock ABI4 net rules kernel-deny all TCP connect except the honeypot port (port-scoped, not address-scoped — residual documented). `--net` launch flag wires the honeypot port into the envelope; `canary` CLI verb; daemon `canary_register`/`honeypot_port` ops. Verified live: plant → register → trip on secret use → event logged → session frozen. Remaining P2 scope: egress proxy v0 (local-only: blocks all real egress, only canary honeypot reachable).

Kernel findings recorded during build:
- Kernel 7.0.x DENIES self-written uid_map from inside a fresh userns (EPERM) — older kernels allowed it. Fix: a forked map-helper stays outside the ns and writes /proc/<pid>/uid_map for the session process.
- Mounting overlay before the helper's map-write is visible fails EACCES intermittently — fixed with an ack round-trip before mount.
- Overlay upper dirs from crashed sessions are owned by dead namespaces and cannot always be removed by later cleanup runs (documented wart; needs GC).

**Scope:** overlayfs undo substrate (commitment #2), `castellan undo <session>` with 3-way merge UX (session-start, session-end, current-user-edited), freeze-before-undo sequencing, pinned GC, canary-credential planting (commitments #4, #5), localhost honeypot listener, auto-freeze on canary hit.

**Deliverables:**
- `castellan-ledger` crate (overlayfs mount in user namespace, upper enumeration, discard, commit) ✅
- `castellan-canary` crate (credential planting, honeypot listener, trigger → freeze wiring) ✅
- egress proxy v0 (local-only: blocks all real egress, only canary honeypot reachable)

**Kill criterion:** undo correctly reverses 100% of kernel-witnessed writes on 20 test sessions with concurrent user edits to unrelated files (no collateral damage). Canary trip rate is 0% on legit sessions, 100% on sessions that attempt to use a planted canary.

**Dependencies:** Phase 1 (envelope, ledger).

**Estimated effort:** 2 weeks. overlayfs + user namespaces is the new plumbing here.

## Phase 3 — Earned autonomy (trust gates expansion)

**Scope:** trust scoring engine (cortex-rs tier-promotion, no time-decay — half-life is KILLed), negative-dominant signals (revert, envelope-escape-attempt, canary-hit), placebo-controlled positive signal (proof-fixes methodology, daemon-re-run tests), trust gates ONLY expansion (egress unlock, config-dir writes via bless-broker). Cold start at tier 2 (full-auto within workspace, no expansion).

**Deliverables:**
- `castellan-trust` crate (EWMA, tier mapping, single-writer trust.db) ✅
- placebo-proof pipeline (daemon test re-run, danger-signal comparison) ✅
- bless-broker v1 (nonce-gated, rate-limited, fp-toggle biometric for high-risk) ✅ (v1 records approval; envelope re-mint + restart is P4)

**Kill criterion:** monotonic relationship between trust tier and user-revert outcomes on a labelled corpus (sessions the user reverted should cluster at lower tiers than sessions the user kept). If no monotonic relationship, trust is demoted to advisory-only (expansion gates stay at manual approval, no auto-tiering). **Status: engine + signals built and verified live; the labelled-corpus benchmark is the remaining gate.**

**Dependencies:** Phase 2 (undo for revert signal, canary for negative signal), Phase 1 (envelope for escape-attempt signal).

**Estimated effort:** 2 weeks. proof-fixes + cert-evals are owned; the wiring is new.

## Phase 4 — Proof-carrying sessions (the novel core)

**Scope:** ProofCertificate generation (daemon-as-verifier, from kernel-witnessed state), certificate schema (bounds-stayed, validation-paths-preserved via relay-vuln, completeness-preserved via seq-engine/config-radar, placebo-tests-passed), evidence-pack export, deterministic replay via llm-replay + spec-exec (forensic, permissive-case delta + max-strict re-exec, coverage % reported honestly).

**Deliverables:**
- `castellan-proof` crate (certificate assembly, relay-vuln + seq-engine + config-radar integration)
- `castellan-replay` crate (action-stream extraction from harness JSONL, overlayfs shadow execution, diff)
- evidence-pack integration (STRONG/MODERATE/WEAK/NON-EVIDENTIAL labels)

**Kill criterion:** certificates correctly classify 20 known-bad sessions (where the agent removed validation or broke completeness) as NOT-EVIDENTIAL or WEAK, and 20 known-good sessions as STRONG or MODERATE. False-negative rate on known-bad < 20% (relay-vuln is grammar-free, we accept it's not perfect — this is honestly labeled "best-effort detection").

**Dependencies:** Phase 3 (trust uses proofs as positive signal), Phase 1 (ledger for kernel truth), relay-vuln (local, DB at `/home/john/data/`).

**Estimated effort:** 3 weeks. relay-vuln is substantial but built; the wiring + certificate schema is the new work.

**Upstream shape:** this is the novel contribution. Standalone first; upstream proposal as a follow-up once benchmarks pass.

## Phase 5 — Opt-in analysis + fleet

**Scope:** HV radar (sensor-hdc + cortex-rs, daemon-computed, ed25519-signed, fleet sync via Omarchy's usage-sync-folder), engfield priors (zero-token context influence, SDM), poc-risk-topology envelope sizing, sentinel as hint-layer (off-by-default, honestly labeled synthetic-only).

**Deliverables:**
- `castellan-radar` crate (HV encoding, signing, local outlier, fleet sync)
- engfield integration (opt-in)
- sentinel integration (off-by-default)

**Kill criterion for radar:** reproduces a known-injected session as an outlier on ≥ 1 machine before any fleet claim. Kill criterion for sentinel: must show AUROC > 0.7 on a real (non-synthetic) labelled corpus, else stays off-by-default and advisory-only forever.

**Dependencies:** Phase 4 (event spine, proofs), Phase 1 (kernel truth).

**Estimated effort:** 2 weeks. sensor-hdc + cortex-rs + engfield are all owned.

## Total

~12-14 weeks of build at honest pace, sequenced. P0 ships first as a standalone demoable wedge and the first upstream PR. Each phase gates on its kill criterion; failure → reduced scope, not hand-waving.

## What is explicitly NOT in scope

- Any parser, AST, tree-sitter, or per-language code analysis. Grammar-free, no exceptions.
- Shipping the CVEfixes DB. It stays at `/home/john/data/` locally; relay-vuln integration is opt-in and local-only.
- Preventing indirect prompt injection at the semantic layer. We bound blast radius; we do not prevent confusion.
- Kernel-level defense against kernel compromise.
- Retroactive confinement of pre-existing malware.
- Any claim of savings, percentages, or security guarantees until benchmarks pass.
