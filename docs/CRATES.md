# Crate layout (proposed workspace)

```
castellan/
├── Cargo.toml                      workspace, lto=fat, codegen-units=1, panic=abort, strip=true, mimalloc
├── crates/
│   ├── castellan-core/             shared types: SessionId, Event, EnvelopeProfile, TrustTier, ProofCertificate
│   ├── castellan-envelope/         Landlock ruleset minting, seccomp BPF generation, degrade-tier detection
│   ├── castellan-freezer/          cgroup.freeze ownership, systemd scope delegation, time-bounded kill
│   ├── castellan-ledger/           overlayfs upper enumeration, inotify fallback, blake3 blob store, event spine
│   ├── castellan-undo/             3-way merge, freeze-before-undo, pinned GC
│   ├── castellan-trust/            EWMA, tier mapping, placebo-proof ingest, single-writer trust.db (rusqlite bundled)
│   ├── castellan-proof/            ProofCertificate assembly, relay-vuln + seq-engine + config-radar wiring
│   ├── castellan-replay/           action-stream extraction, overlayfs shadow execution, permissive-case diff
│   ├── castellan-egress/           HTTP proxy, real-cred injection, canary honeypot listener
│   ├── castellan-canary/           credential planting, honeypot trigger → freeze wiring
│   ├── castellan-radar/            sensor-hdc encoding, ed25519 signing, local outlier, fleet sync
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
                                     castellan-radar, castellan-bless, castellan-watch}
                                  → castellan-core
castellan-trust → castellan-proof (positive signal), castellan-ledger (events), castellan-core
castellan-proof → relay-vuln (subprocess, opt-in), seq-engine (subprocess), config-radar (subprocess), castellan-ledger
castellan-radar → sensor-hdc (vendored or subprocess), castellan-core
castellan-watch → skein (subprocess), carrion (subprocess)
```

Existing Python primitives (relay-vuln, seq-engine, config-radar, skein, carrion, agent-audit-trail, evidence-pack, proof-fixes, cert-evals, llm-replay, engfield) stay as Python and are invoked as subprocesses from the Rust daemon. Rewriting them in Rust is out of scope for the first build; they're built, tested, and have real-data verdicts — no reason to rewrite. The Rust daemon owns the kernel surface and the single-writer boundaries; Python owns the analysis it already does well.

## What gets rewritten in Rust vs kept as Python subprocess

| Component | Language | Reason |
|---|---|---|
| envelope, freezer, ledger, undo, daemon, bless, canary, egress, watch, radar encoding, cli | Rust | kernel surface, single-writer, hot path, must be one binary |
| trust scoring | Rust | single-writer to trust.db, in daemon |
| ProofCertificate assembly | Rust | in daemon |
| relay-vuln scan | Python (subprocess) | 136 modules, 49GB DB, already built; rewrite is huge for no gain |
| seq-engine completeness | Python (subprocess) | built; Rust main is a stub |
| config-radar | Rust (subprocess) | already Rust; invoked as subprocess for isolation |
| skein, carrion | Rust (subprocess) | already Rust |
| agent-audit-trail | Python (subprocess) | built; small |
| evidence-pack | Python (subprocess) | built; export only |
| proof-fixes | Python (subprocess) | built; placebo methodology |
| cert-evals | Python (subprocess) | built; benchmark harness |
| llm-replay | Python (subprocess) | built; PASS verdict |
| engfield | Rust (subprocess) | already Rust |
| sensor-hdc | Rust (vendored or subprocess) | tiny (286 LOC), could vendor |
| cortex-rs | Rust (subprocess) | built; tier-promotion memory |
