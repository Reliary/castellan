# AGENTS.md — castellan

Conventions for AI agents (and humans) working on castellan.

## Style

- **Rust, stable toolchain.** Workspace with `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`, mimalloc global allocator (matches reliary-agent).
- **Pure Rust daemon — no Python in the trusted path.** The daemon is one static binary. Every primitive in the daemon's proof-generation, trust-scoring, or observation flow is Rust (linked as a workspace crate or vendored). Python is allowed only for dev/CI tooling (cert-evals, llm-replay) that is not shipped and not in the daemon. See [docs/CRATES.md](docs/CRATES.md).
- **Grammar-free, no exceptions.** No parsers, no ASTs, no tree-sitter, no per-language code. Function boundaries use indentation-anchored scanning. JSON parsing is allowed (it is structured data, not source code). Configuration formats are parsed by their existing libraries, not hand-rolled.
- **Deterministic, predictable results.** Tool output format must match what the LLM expects from native tools. No stochastic gates in the enforcement path.
- **Two spaces for indentation in Rust and Markdown.** No tabs. No trailing whitespace. No emojis unless explicitly requested.
- **No comments in code unless asked.** Commit messages succinct, describe the change. Atomic commits only.

## Honesty rules (non-negotiable)

- No savings, percentage, or security claims in docs or commits until benchmark results are stable, repeatable, and pass the kill criteria in [docs/ROADMAP.md](docs/ROADMAP.md).
- Every positive trust signal must be **placebo-controlled**: a real fix must drop the danger signal more than a neutral placeholder, or it is not evidence. See [docs/components/proof-carrying.md](docs/components/proof-carrying.md).
- Benchmark comparisons run **baseline and gate conditions interleaved in the same session batch** to control for LLM stochastic variance. See [docs/benchmark-methodology.md](docs/benchmark-methodology.md).
- Primitives with real-data verdicts of KILL or MARGINAL must not be used as load-bearing components. They may be referenced as advisory-only and must be labeled as such. See [docs/PRIMITIVES.md](docs/PRIMITIVES.md).
- Residual risks are documented in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), not hidden.

## Build and test

TBD — workspace is stubbed. When code lands:

- `cargo build --release --workspace` — build all crates
- `cargo test --workspace` — unit + integration tests
- `cargo bench` — benchmarks (cert-evals methodology)
- `./test/all` — aggregate runner (planned)

## Architecture

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before touching anything. The 10 commitments in that doc are non-negotiable for safety; changing one requires a design-decision record in [docs/DESIGN_DECISIONS.md](docs/DESIGN_DECISIONS.md).

## Git

- Atomic commits: one coherent change per commit.
- Never commit secrets, API keys, or the CVEfixes DB.
- The CVEfixes DB (49 GB) lives at `/home/john/data/cvefixes/cvefixes.db` locally and is NEVER shipped, vendored, or committed. relay-vuln integration is strictly local and opt-in.

## Threat model

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before designing any new component. The three threat classes (agent pulls its own levers, agent fakes, malicious actor) must be re-antagonised against any new surface.
