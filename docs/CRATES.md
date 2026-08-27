# Crate layout (proposed workspace)

```
castellan/
├── Cargo.toml                      workspace, lto=fat, codegen-units=1, panic=abort, strip=true, mimalloc
├── crates/
│   ├── castellan-core/             shared types: SessionId, Event, EnvelopeProfile, TrustTier, ProofCertificate
│   ├── castellan-envelope/         Landlock ruleset minting, seccomp BPF generation, degrade-tier detection
│   ├── castellan-freezer/          cgroup.freeze ownership, systemd scope delegation, time-bounded kill
│   ├── castellan-ledger/           overlayfs upper enumeration, inotify fallback, blake3 blob store, event spine, audit hash chain (was agent-audit-trail)
│   ├── castellan-undo/             3-way merge, freeze-before-undo, pinned GC
│   ├── castellan-trust/            EWMA, tier mapping, placebo-proof ingest, single-writer trust.db (rusqlite bundled)
│   ├── castellan-proof/            ProofCertificate assembly + export (was evidence-pack), placebo pipeline (was proof-fixes), relay-vuln + config-radar wiring
│   ├── castellan-completeness/     config key audit (was config-radar). seq-engine KILLed 2026-08-27 — see PRIMITIVES.md
│   ├── castellan-replay/           action-stream extraction, overlayfs shadow execution, permissive-case diff
│   ├── castellan-egress/           HTTP proxy, real-cred injection, canary honeypot listener
│   ├── castellan-canary/           credential planting, honeypot trigger → freeze wiring
│   ├── castellan-radar/            sensor-hdc encoding, ed25519 signing, local outlier, fleet sync
│   ├── castellan-drill/            P8.0 live-fire drills: nonce registry, scheduler, 5-drill suite
│   ├── castellan-memory/           P8.1 Kanerva-immune memory: SDM (vendored from engfield), fragment recall, self/tolerance shapes
│   ├── castellan-voice/            P8.3 acoustic channel: nonce grammar, panic phrase, protocol state machine (STT/TTS feature-gated)
│   ├── castellan-pharmaco/         P8.4 pharmacovigilance: PRR/ROR/EBGM estimators (methodology only, fleet-pending)
│   ├── castellan-bless/            dbus nonce-gated approval, rate limit, fp-toggle biometric integration
│   ├── castellan-watch/            harness-state-watcher: skein + carrion baseline, skill quarantine
│   ├── castellan-daemon/           unix socket, single-writer-per-session, watchdog, all-component orchestration
│   └── castellan-cli/              thin CLI shims (castellan-freeze, castellan-undo, castellan-trust, etc.) over the socket
├── bin/                            bash shims matching omarchy-* prefix for upstream: omarchy-freeze, omarchy-launch-agent, ...
├── shell-plugin/                   Quickshell QML: freeze toggle, trust badge, bless-broker notification UI
├── skill/                          SAFETY SKILL.md symlinked like Omarchy's existing skill
├── migrations/                     upstream-ready: audit-mode-default for upgraders, enforce-default for fresh installs
└── test/
    ├── all                         aggregate runner
    ├── cli                         CLI routing
    └── shell.d/                    per-component shell tests
```

## Dependency policy

- **rusqlite (bundled)** for trust.db, blob store index, HV store — matches reliary-agent.
- **zbus** (pure Rust, no libdbus) for systemd user manager `StartTransientUnit` and dbus nonce-gated bless broker.
- **nix** crate for Landlock, seccomp, cgroup, inotify, overlayfs, user-namespace syscalls — well-maintained, idiomatic.
- **blake3** for content-addressed before-images (matches stria/relay).
- **ed25519-dalek** for per-machine HV signing.
- **mimalloc** global allocator.
- **rustc-hash FxHash** maps in hot paths (matches reliary-agent).
- **ahash** where insertion-heavy and not security-sensitive (matches reliary-compress).
- **rayon** for parallel ingest/reindex/scavenger (matches reliary-agent).
- **NO HTTP framework** for the egress proxy — hyper or a minimal hand-rolled parser. The proxy is in the trusted path and must be auditable; small surface.
- **NO parsers, ASTs, tree-sitter, per-language code** — grammar-free, no exceptions.

## Crate dependency graph (proposed)

```
castellan-cli → castellan-daemon → {castellan-envelope, castellan-freezer, castellan-ledger,
                                     castellan-undo, castellan-trust, castellan-proof,
                                     castellan-replay, castellan-egress, castellan-canary,
                                     castellan-radar, castellan-bless, castellan-watch,
                                     castellan-drill, castellan-memory, castellan-voice}
                                  → castellan-core
castellan-trust → castellan-proof (positive signal), castellan-ledger (events), castellan-core
castellan-proof → relay-vuln (Rust crate, opt-in), config-radar (Rust crate), castellan-ledger
castellan-radar → sensor-hdc (Rust crate, vendored), castellan-core
castellan-watch → skein (Rust crate), carrion (Rust crate)
castellan-memory → blake3 (SDM vendored from engfield, MIT)
castellan-campaign → castellan-core, castellan-trust (signature module: P8.2)
castellan-pharmaco → standalone estimators (P8.4, no daemon wiring yet)
```

## Pure Rust — no Python in the daemon

The daemon is the trusted core. It must be one static binary with no Python runtime, no subprocess spawns in the hot path, no version drift, no missing-dependency failures. Every primitive that runs inside the daemon's proof-generation, trust-scoring, or observation flow is Rust — either already Rust (linked as a workspace member or vendored) or rewritten as a Rust crate.

This mirrors the project directive: "relay must be pure Rust (no Python runtime)." The same principle applies to castellan — the daemon is the trusted path.

**What's already pure Rust** (verified by inspecting the repos):
- relay-vuln: 52,258 lines of Rust in `src/`, zero Python in the scanner. The 20 Python files are `scripts/` (mining/eval tooling), not the scanner. Links as a Rust crate.
- skein (203 LOC), carrion (227 LOC), sensor-hdc (286 LOC), cortex-rs (1632 LOC): already pure Rust.
- config-radar (2698 LOC Rust), engfield (2183 LOC Rust), stria (8050 LOC Rust): already have substantial Rust; Python is legacy/tooling only.

**What gets rewritten as Rust** (Python-only, in the daemon's trusted path):

| Primitive | Python LOC | Rust crate | Rewrite cost |
|---|---|---|---|
| agent-audit-trail | 109 | castellan-audit (in castellan-ledger) | trivial — hash chain + JSON |
| evidence-pack | 302 | castellan-proof (export module) | trivial — serde_json + quality labels |
| proof-fixes | 270 | castellan-proof (placebo module) | small — placebo orchestration over relay-vuln |

~680 lines of Python total, all small, all algorithmic, all in the proof pipeline. Rewrite as Rust crates and the daemon is pure Rust.

**seq-engine is NOT rewritten.** KILLed 2026-08-27 by real-data probe on 29 local spines: 78% of learned expectations are within-event tautologies (tokens co-emitted by the same event); the composite-only encoding learns zero expectations; ordered fingerprints add no separation over radar's order-agnostic encoding (identical cosine 0.0150); the trust stream has 5 distinct tokens in 30 events. The earlier claim of a 1,368-LOC Rust port was false — the Rust crate is a "Hello, world!" stub. See PRIMITIVES.md.

**What stays Python** (dev/CI tooling, NOT shipped, NOT in the daemon):
- cert-evals (319 LOC) — benchmark harness run by humans/CI, not user-facing
- llm-replay (152 LOC) — forensic replay tooling, run by developers
- relay-vuln `scripts/` — mining/eval, not the scanner

These are developer tools. They don't ship to users, don't run inside the daemon, and aren't in the trusted path. Python is fine for dev tooling.
