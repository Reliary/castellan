# Plan — CI audit: borrow security/leak-detection config from sibling Rust projects

**Status:** frozen 2026-10-02, post-antagonism pass. Plan-mode design; not yet built.
**Source set audited:** reliary-agent, reliary8, stria, relay-vuln, quale, autopsylab-agent, AI-Playground, bisA-family (templated baseline), tokio-obf, OpenPass.
**Castellan state at write time:** 7 workflows / 369 LOC — `ci.yml` (check, release-build, cross-arch, supply-chain, syscall-drift, workload-syscalls, diff-trust-gate, escape-regression), `codeql-analysis.yml`, `hardening.yml` (deny — duplicates ci supply-chain), `pr-secret-scan.yml` (gitleaks-action@v2 floating), `release.yml` (2-target, unsigned), `scorecard.yml`, `size.yml` (daemon-only, 15 MB budget).

## Antagonism verdicts (what was cut or downgraded, and why)

| Candidate | Verdict | Ground |
|---|---|---|
| checksec hard gate | **cut → informational log** | We strip binaries + `panic=abort` + LTO; canary/fortify findings would be false-red noise from an inapplicable threat model. RELRO/PIE are linker-flag controlled already. |
| shellcheck blocking | **downgrade → report-only** | Pre-existing style debt across shell suites would gate on hundreds of findings; semantic bugs (pipes, exit codes) are what actually bit us, not parse errors. |
| dependency-review-action | **downgrade → verify first, drop if cargo-blind** | It is dependency-graph based (strong npm/Go); may silently no-op on Cargo.lock changes. Shipping a decorative gate is the dead-gate anti-pattern. Must be proven to fire on a cargo dep-diff PR before keeping. |
| SHA-pin every action | **scope → privilege-bearing only** | Pin actions holding `contents: write`, `security-events: write`, or `id-token: write` (release, codeql, scorecard, upload-sarif). `rust-toolchain`/`rust-cache` hold `contents: read` and no secrets — dependabot churn > benefit. |

## Surviving items and their measured basis

- **Fix ci.yml:146 pipe** — live latent silent-pass (the exact F4 hazard).
- **gitleaks pinned binary** — *required*, not aesthetic: Reliary is an org; the gitleaks-action org license is paid (14 sibling workflows carry `GITLEAKS_LICENSE`). Borrow reliary8's pinned-binary pattern (v8.30.x), full-history `detect --redact`, run locally first; `.gitleaks.toml` allowlist only if a real false positive appears, documented per entry.
- **Fuzz — 3 targets weekly** — measured surface: 59 unwrap/expect/panic/slice lines across `castellan-proxy` (18), `castellan-canary` (13), `castellan-core` (28); `proxy/lib.rs:485` radix-parses an agent-controlled chunk-size over `unwrap_or("")` with no length cap. P12 and P15 both fixed real proxy-parse defects; fuzz is evidence-driven here.
- **dependabot (cargo + github-actions, weekly)** — SHA pins rot without it; reliary8/.github/dependabot.yml is the template.
- **Release checksums + cosign keyless** — borrowed from reliary-agent release.yml (checksums job: `SHA256SUMS`, `sigstore/cosign-installer@3454372f…` SHA, `sign-blob --bundle`, verify instructions in release notes).
- **P15 unit pins** — escape-regression pattern extended to attribution: `session_scope_of` cgroup-string fixtures + dispatch-kind table (`canary_trip`/`canary_framing`/`canary_unattributed`) in canary crate; extract proxy loopback+`deny_ports` check to a pure predicate and unit-test.
- **Misc borrows** — test-count ratchet (floor = current workspace total at build time, deliberate bump PRs only, reliary8 pattern); CLI binary added to size budget; `concurrency: cancel-in-progress` (quale); remove `|| true` from tool installs; dedup deny (ci `supply-chain` is the single home; hardening.yml becomes checksec-log + build-log secret grep, borrowed shapes from reliary-agent but measured-before-gated).

## Explicitly not borrowed (with reasons)

Coverage % gate (shell suites are the real assertions; a number is gameable), semgrep/bandit (python harness only, and our threat classes live in Rust), bench.yml (no-perf-claims rule), publish.yml (`publish = false` in workspace), cargo-semver-checks (not publishing crates), reliary-agent fuzz.yml's `| tail` pipes (would hide crashes — borrow the shape, fix the pipes), its dead `cargo_outdated` job (schedule-gated with no schedule trigger), bisA's suspicious repeated-nibble codeql SHA (`4dd161…b8b8` — resolve SHAs from reliary-agent or GitHub, never from that file).

## Execution phases

**A — fixes + cheap borrows** (commit per item): ci pipe fix · gitleaks pinned binary (local-run first) · dependabot.yml · checksec informational + dedup deny · actionlint blocking (if clean at first run) + shellcheck report-only · test-count ratchet · size budget for CLI · concurrency blocks · `|| true` install removal · P15 unit pins (canary dispatch table + proxy predicate).

**B — release integrity**: SHA256SUMS + cosign sign-blob bundles + verify instructions in generated notes; `id-token: write` on release; softprops/codeql/scorecard/upload-sarif SHA-pinned (privilege-bearing set).

**C — fuzzing**: `cargo fuzz init`; targets `proxy_fuzz` (CONNECT line + head reader + chunk-rewrite via `#[cfg(fuzzing)]` or doc-hidden feature shims — no production-path change), `rpc_fuzz` (pub `Request` JSON decode), `ledger_fuzz` (partial/corrupt ledger lines must never panic at restart — this is the restart-survival path). Local nightly run first; weekly + dispatch cron Monday 06:00 with corrected (unpiped, checked-install) steps.

**D — conditional**: dependency-review verified against a real cargo PR dep change; kept only if it fires.

## Verification (all required before closing)

actionlint over all modified workflows · gitleaks local run green · checksec local measurement recorded in commit message · shellcheck report generated (not gated) · `cargo test --workspace` green incl. new pins · YAML-parse every workflow · push and confirm every workflow run green via `gh run list` · fuzz targets each run ≥60s locally on nightly without crash · release cosign path proven on the next real tag (or a draft-tag dry run).

## Kill criteria

- Any borrowed gate red on first CI run with no real finding → fix or drop the gate before merge; do not land red.
- dependency-review blind on cargo dep-diff → remove (D).
- Fuzz target flaky (>1 nondeterministic crash across two runs on the same seed) → shrink or fix before enabling as a gate.
- checksec informational log shows a genuinely missing RELRO/PIE → escalate to gate (evidence upgrades it).

## Execution record (2026-10-02)

All four phases built. Deviations from the frozen plan, each with its evidence:

- **checksec cut → became a blocking readelf assertion** (the plan's own
  kill criterion fired: measured locally, both binaries already have
  PIE + NX + GNU_RELRO + BIND_NOW, so an assertion cannot false-red).
  Readelf-based rather than borrowed checksec.sh — the borrow would have
  meant curling a third-party shell script into the trust boundary.
- **shellcheck report-only + a new error-severity zero gate.** The local
  v0.10.0 report: 239 findings all-severity (report-only, per plan),
  1 error — SC2145 in `p12-proxy.sh launch_env`, a REAL latent bug
  (`$@` inside the `script -qec` string would splice flags into
  script's own argv). Fixed the bug; the error class now gates at zero
  under the pinned version. Evidence upgrade, documented deviation.
- **gitleaks: default ruleset, no `.gitleaks.toml`.** Local pre-enable
  run v8.30.1: 134 commits, no leaks. Antagonism finding: the sibling
  config omits `useDefaultConfig = true`, so borrowing it would REPLACE
  the full default ruleset with 3 rules — a coverage downgrade. Binary
  pattern borrowed (org paid-license trap confirmed: 14 sibling
  workflows carry GITLEAKS_LICENSE), config deliberately not.
- **SHA pins resolved and commit-verified via gh api** (not trusted
  from annotations): cosign-installer v3.8.2, softprops v2.6.2,
  codeql-action v4.36.2, scorecard v2.4.3, dependency-review v5.0.0.
  Version comments were initially guessed (v3.10.0/v2.5.x) and caught
  by the tag-peel before commit.
- **dependency-review precondition verified before enabling** (plan
  said "verify first, drop if blind"): `/dependency-graph/sbom`
  returns 125 packages from this repo's Cargo.lock — the graph is
  active and cargo PR diffs are visible. Kept.
- **Fuzz built and locally verified before the workflow shipped:**
  `cargo +nightly fuzz build` clean; proxy_fuzz 3,623,603 execs / 60s,
  rpc_fuzz 1,884,392, ledger_fuzz 735,212 — zero crashes (kill
  criterion not triggered). Shims are `#[cfg(feature = "fuzz")]`
  wrappers calling the private production fns — zero production
  behavior change; `cargo check --features fuzz` linted for both
  crates.
- **Test-count ratchet floor = 211** (measured with plain cargo, not
  a wrapper summary: 51 suites, exit 0).
- **P15 unit pins:** `trip_dispatch_attribution_table` (the C40a
  regression lock — row 2 freezes the SENDER), `session_scope_parse_fixtures`
  (+harden: a non-scope dir under castellan.slice no longer fabricates
  a sid — pre-extract code split on `.scope` with no match), and
  `honeypot_tunnel_denied_table` (+hardening: bracketed `[::1]` is
  parsed, not failed-open).

### Verification at close

actionlint 0 · YAML parse 9/9 · cargo test 211/211 (51 suites) ·
clippy 0 errors · gitleaks v8.30.1 history clean (134 commits) ·
shellcheck error-class 0 · fuzz 3×60s zero crashes · feature-shim
`cargo check` clean. Workflows run in CI verified via PR (see push
record).

### Post-push: first-ever CI execution found 4 pre-existing red jobs (2026-10-02/03)

PR #6 was the first time these workflows ever ran — feature-branch
pushes never matched the branch triggers, so `check`, `supply-chain`,
`cross-arch` and `syscall-drift` had been red at every recent quattro
commit without anyone watching (diff-trust baseline shows the same
four). All four triaged and fixed; none introduced by the CI-audit
commits:

- **syscall-drift (kernel gap):** `rseq_slice_yield` is a real
  syscall (kernel 7.0.3) that CI runner kernels predate — the gate's
  typo detector false-REDed. Fix keeps knowledge in the table: the
  gate reads the introducing version from the class rationale
  ("<name> (X.Y.Z)") and notes expected absence on older kernels;
  undocumented absence or absence on a kernel that should have it
  still FAILs. Testing caught a bash pitfall in the comparison helper
  (`local a=.. b=${a}..` expands before assignment — want_minor
  captured empty). Gate PASS, selftest 5/5 preserved.
- **check (clippy -D warnings):** 71 warnings were errors on CI while
  local clippy (no -D) had been passing — the gate was red from day
  one. 14 auto-fixes; the rest by hand: memory's index→enum string
  round-trip replaced with `from_index` (and the now-dead `from_str`,
  `decode_response`, `ROLE_SELF` removed — the read path is
  `read_margin` and the self set is the plain list by design);
  daemon's never-constructed respawn stubs and audit fields kept with
  `#[allow(dead_code)]` + honest "designed, not wired" status
  comments; `Caller::Rejected` kept the same way (classification is
  binary today); two `too_many_arguments` allows with rationale; loop
  and sort rewrites; cli's `}      if` suspicious-else formatting
  fixed as a newline only (behavior unchanged — both blocks run,
  before and after). Final: `-D warnings` exit 0.
- **supply-chain (cargo audit):** three advisories — two already
  dispositioned in deny.toml with written rationales (cargo-audit
  does not read deny.toml) plus RUSTSEC-2026-0097 (rand 0.7 INFO/
  unsound: custom-logger reentrancy we do not have; no 0.7 patch
  exists — fix is the tracked dalek v2 upgrade). All three mirrored
  into `cargo audit --ignore` flags and deny.toml's ignore list.
  Verified locally with the exact CI flags on a fresh advisory DB:
  exit 0; `cargo deny check advisories` ok.
- **cross-arch (aarch64):** `libc::SYS_{iopl,ioperm,chown,lchown}`
  do not exist on aarch64 (E0425 ×4) — the denylist named x86-only
  constants unconditionally. Split into `ARCH_ONLY_SYSCALLS` /
  `ARCH_ONLY_FILTER_NAMES` (present on x86, empty elsewhere —
  uninvocable syscalls need no entry) with `filter_names()` as the
  single lookup so an arch-split pair cannot diverge. Local aarch64
  `cargo check`: zero E0425 (remaining 3 errors are build-scripts
  needing cross-gcc, which CI installs); envelope suite 12/12.

Also redacted a pre-existing login-name comment in castellan-ledger
while that file received its auto-fixes.

Verification at close: clippy `-D warnings` 0 · tests 211/211 ·
audit exit 0 (exact flags) · deny advisories ok · actionlint 0 ·
drift gate PASS + selftest 5/5 · aarch64 E0425=0.

### Final CI verdict (2026-10-03, SHA e3814c9, PR #6)

All six PR-triggered workflows green — first fully green ci run in
this repo's recorded history: ci 11/11 (check, release-build,
cross-arch, supply-chain, syscall-drift, workload-syscalls,
diff-trust-gate, escape-regression, lint-workflows,
shellcheck-report, test-ratchet), Secret scan, Dependency review,
Supply-chain hardening, Binary size, CodeQL. The last red (selftest)
was the dev-box REPO default in syscall-drift-selftest.sh — the one
file P14's self-location correction missed — fixed the same way.

Not exercised by this PR (by design of their triggers): fuzz.yml
(workflow_dispatch discovers workflows from the default branch — runs
post-merge or on schedule), Scorecard (push-to-quattro + weekly
schedule), Release cosign path (first real `v*` tag; local
verification limited to YAML/actionlint since keyless signing needs
GitHub OIDC).
