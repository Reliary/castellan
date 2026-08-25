# Architecture

Castellan is four planes, one substrate, one event spine, one daemon. The planes compose; the substrate is the keystone every plane hangs off.

## The substrate: session identity

Attribution is the hard problem everywhere (undo, trust, freeze, radar, proofs). Solve it once at the kernel level and every plane reuses the answer.

A **session** is one invocation of one agent harness on one project. Every session gets:

- **systemd user scope** `castellan-<uuid>.scope` via `StartTransientUnit` on the user manager. All descendant processes inherit the scope automatically. No root required. Gives free process-tree enumeration and the cgroup v2 freezer.
- **Landlock ruleset** self-applied at spawn. Inherited by children. Irreversible mid-session (kernel guarantee: restrictions only stack tighter). The envelope.
- **seccomp BPF filter** allowlist applied at spawn. Blocks `io_uring` syscalls (GhostClaw bypass), `ptrace`, `process_vm_readv`, `chmod`/`chown`/`fchmod`/`fchown`/`utime`/`futimes` (Landlock ABI gap), and everything not on the allowlist (future-proofing).
- **`CASTELLAN_SESSION=<uuid>` env tag** for cooperative harnesses. The cgroup is enforcement truth; the env var is convenience truth.
- **overlayfs mount** over the project directory inside a user namespace: lower = read-only real, upper = session writes, work = kernel workdir. The undo substrate and the ledger substrate in one.

Degradation tiers (availability cliff, documented honestly):
1. systemd user manager + Landlock ABI v4+ + user namespaces + overlayfs — full capability.
2. cgroup v2 without systemd user manager — manual cgroup creation, freezer works, no scope delegation.
3. Landlock ABI < v4 — filesystem only, no network restrictions, seccomp still applies.
4. No Landlock — fail-closed by default; configurable to audit-only (no enforcement, observation still works via fanotify fallback... see ledger doc for the inotify fallback when overlayfs is unavailable).

## The event spine

Append-only, per-session, kernel-witnessed event log at `~/.local/state/castellan/sessions/<uuid>/events.jsonl`. Every event has `{ts, session, cgroup, type, target, hash, source}` where `source` is `kernel` (inotify/overlayfs/seccomp-audit) or `agent` (declared via audit-trail). Kernel events are truth; agent events are advisory. The spine feeds trust, radar, proofs, and undo.

Content-addressed before-images (blake3) live in a dedup blob store at `~/.local/state/castellan/blobs/`. Shared across sessions, GC with pinning.

## The daemon

One static Rust binary, `castellan-daemon`, owns the single-writer-per-session correctness boundary. Unix-socket CLI. Responsibilities:

- mints envelopes (Landlock + seccomp rulesets) at spawn
- creates systemd scopes (or cgroup fallback)
- owns cgroup.freeze files (agent cannot self-thaw — see commitment #1)
- runs the overlayfs mount setup in a user namespace
- runs the inotify watchers on allowed paths (ledger)
- ingests agent-audit-trail events (advisory) and tags them vs kernel events (truth)
- computes trust scores (single writer to trust.db)
- computes HV fingerprints and signs them with the per-machine ed25519 key
- runs the egress proxy (holds real credentials, injects them per-request; envelope only ever sees canaries)
- runs the bless broker (expansion requests, nonce-gated, biometric for high-risk)
- re-runs tests independently in a side-scope (verifier ≠ prover)
- generates ProofCertificates from kernel-witnessed state
- watchdog: daemon heartbeat stops → systemd restarts daemon AND auto-freezes all agent scopes (fail-closed)

Bash `castellan-*` shims stay thin (socket queries), matching Omarchy's `omarchy-*` command pattern and `cmd-present` degradation philosophy.

## The four planes

```
┌─────────────────────────────────────────────────────────────┐
│ HINT        (experimental, off-by-default, advisory-only)    │
│   sentinel (sensor-regime, synthetic-only)                   │
│   sec-commit-label (marginal, advisory)                      │
├─────────────────────────────────────────────────────────────┤
│ ANALYSIS    (owned, opt-in)                                  │
│   vuln-regression (relay-vuln + proof-fixes, DB local)       │
│   post-mortem export (evidence-pack)                         │
│   deterministic replay (llm-replay, spec-exec)               │
│   benchmark methodology (cert-evals)                         │
│   memory priors (engfield, cortex-rs)                        │
│   blast-radius topology (poc-risk-topology)                  │
├─────────────────────────────────────────────────────────────┤
│ OBSERVATION (owned, wired in by default)                     │
│   decisions → agent-audit-trail (advisory, tamper-evident)   │
│   session fingerprint + drift → agent-profile                │
│   harness-state drift → skein                                │
│   edit confinement → stria guard/contract/verify-packet      │
│   output entropy gate → gate.js / sift                       │
│   completeness → seq-engine + config-radar                   │
│   architecture-shift → git-archaeology                       │
│   speculative next-action → spec-exec                        │
├─────────────────────────────────────────────────────────────┤
│ ENFORCEMENT (greenfield Rust)                                │
│   envelope minter (Landlock + seccomp)                       │
│   session scope (systemd user unit → cgroup v2 → PID cliff)  │
│   freeze (cgroup.freeze, time-bounded → kill at 5min)        │
│   inotify-ledger on allowed paths (or overlayfs upper)       │
│   bless-broker for expansion, gated by fp-toggle (biometric) │
└─────────────────────────────────────────────────────────────┘
                  ↑ all hang off the substrate ↑
            session identity + event spine + daemon
```

## Component map

| Component | Plane | Doc | Owned primitives reused | Status |
|---|---|---|---|---|
| envelope | enforcement | [envelope.md](components/envelope.md) | quale (sizing hints, advisory) | greenfield |
| freezer | enforcement | [freezer.md](components/freezer.md) | fp-toggle (biometric thaw, BUILT) | greenfield |
| undo | enforcement | [undo.md](components/undo.md) | overlayfs (new), skein/carrion (integrity) | greenfield |
| ledger | enforcement | [ledger.md](components/ledger.md) | agent-audit-trail (BUILT), inotify (new) | greenfield + wired |
| bless-broker | enforcement | [bless-broker.md](components/bless-broker.md) | fp-toggle, quale (risk card) | greenfield |
| egress-proxy | enforcement | [egress-proxy.md](components/egress-proxy.md) | — | greenfield |
| canary-credentials | enforcement | [canary-credentials.md](components/canary-credentials.md) | — | greenfield |
| harness-state-watcher | observation | [harness-state-watcher.md](components/harness-state-watcher.md) | skein (BUILT), carrion (BUILT) | wired |
| trust | analysis | [trust.md](components/trust.md) | cortex-rs (BUILT), proof-fixes (BUILT), cert-evals (BUILT) | greenfield + wired |
| proof-carrying | analysis | [proof-carrying.md](components/proof-carrying.md) | relay-vuln (BUILT), evidence-pack (BUILT), proof-fixes, cert-evals, agent-audit-trail | greenfield + wired |
| hv-radar | analysis | [hv-radar.md](components/hv-radar.md) | sensor-hdc (BUILT), cortex-rs (BUILT), engfield (BUILT) | greenfield + wired |
| sentinel | hint | [sentinel.md](components/sentinel.md) | sensor-regime (BUILT, synthetic-only) | wired, off-by-default |
| daemon | all | [daemon.md](components/daemon.md) | reliary-agent daemon pattern (BUILT) | greenfield |

## The 10 commitments (non-negotiable for safety)

These survived antagonism. Changing one requires a design-decision record.

1. **Daemon owns cgroup.freeze** — agent runs as the user, user can write the freezer file, so the daemon must own it (via systemd delegate or setuid thaw helper). Without this the panic button is theater.
2. **overlayfs is the undo substrate** — not inotify. inotify loses races (agent writes+deletes faster than the watcher fires). overlayfs upper layer is atomic at FS level, no race.
3. **Daemon re-runs tests independently** — the agent is the prover, the daemon is the verifier. Agent-reported test results are advisory. Trust and proofs use only daemon-verified results.
4. **Real credentials never enter the envelope** — all egress proxied through the daemon, which holds real keys and injects them server-side. The envelope contains only canary credentials. Any credential the agent can read is a canary by definition.
5. **Canary keys are wired to a localhost honeypot listener** — using OR probing the canary IS the trigger. There is no "is this key real?" step that does not trip the wire.
6. **Trust has a ceiling and an always-on deny-list** — even a tier-0 (max-trust) agent cannot touch `~/.ssh`, `.gnupg`, systemd units, `.desktop` files, shell rc. A patient attacker gaming trust gets egress, not escape.
7. **Daemon crash → auto-freeze** — systemd watchdog restarts the daemon and freezes all agent scopes on heartbeat loss. Fail-closed.
8. **seccomp is an allowlist, not a denylist** — and it blocks chmod/chown/utime (Landlock ABI gap) plus io_uring, ptrace, process_vm_readv. Future new syscalls are blocked by default.
9. **HVs are signed per-machine** — the daemon signs every HV with its ed25519 key (key outside any envelope). Fleet sync verifies signatures. Agent cannot forge HVs or poison fleet detection.
10. **Bless broker is nonce-gated, rate-limited, biometric for high-risk** — the nonce comes from the notification UI via dbus, not from anything the agent can forge. Max 3 expansions per session, cooling-off period, fp-toggle biometric for egress or config-dir writes.

## Residual risks (documented in [THREAT_MODEL.md](THREAT_MODEL.md), not hidden here)

- Patient attacker via slow trust accumulation (mitigated by ceiling + deny-list, not eliminated).
- relay-vuln false negatives (proof = best-effort detection, not proven-safe; labeled honestly).
- Human social-engineering at the bless broker (inform, can't prevent).
- Persistence via workspace files (detect via post-session scan, can't prevent — workspace is writable by agent, executable by user; that boundary is a trust transfer we instrument only).
- Pre-existing compromise (assumes clean install).
- Kernel compromise (out of scope).
