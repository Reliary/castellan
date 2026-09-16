# castellan

**The OS is the trust boundary for AI agents.**

Castellan is a Linux-native agent safety system that confines, observes, and proves what AI coding agents do on your machine — at the kernel level, where prompt injection cannot reach. It is being designed as a contribution to [Omarchy](https://github.com/basecamp/omarchy) (DHH's Arch + Hyprland distro), but the core is reusable on any systemd + Landlock Linux.

> **Status: working.** P0–P4 are implemented and acceptance-tested on Linux 7.x / Landlock ABI 8: session substrate + freeze (P0), the envelope floor with audit + enforce launch (P1), surgical undo + canary credentials (P2), earned autonomy (trust engine + placebo-proof pipeline + bless-broker, P3), and proof-carrying sessions (certificate assembly + kill-criterion benchmarks, P4). P5 (HV radar, engfield, sentinel) is designed but not built. Every claim below is scoped accordingly; see [docs/ROADMAP.md](docs/ROADMAP.md) for phase status, [docs/PRIOR_ART.md](docs/PRIOR_ART.md) for what already exists elsewhere, and [docs/benchmark-methodology.md](docs/benchmark-methodology.md) for how claims get earned.

## The problem in one sentence

AI agents now run unattended on personal machines with broad filesystem and network access, and every safety tool today lives *inside the agent* — which is exactly the part prompt injection hijacks.

## The pitch in plain English

A distro owns the one layer where a single policy applies to every brand of agent identically: the OS itself. Harness vendors can only confine their own agent; agent-safety tools can't confine anyone else's either. Castellan makes the kernel the trust boundary so the agent cannot argue with it, bypass it, or be tricked out of it.

## The five pieces

Shipped:

1. **Kernel walls** — `castellan launch --enforce -- claude ...` confines the session via Landlock + seccomp before any agent code runs: writes limited to project + harness state + scratch, hard-deny for `~/.ssh`, systemd units, autostart, shell rcs, `/etc` `/usr` `/boot`; ptrace/process_vm/io_uring/module syscalls return EPERM. Verified: workspace work (git included) runs clean under enforce; home-dir escapes get EACCES.
2. **Panic button** — every launched or adopted session lives in its own cgroup scope. `castellan freeze` stops all sessions at once: zero CPU, no userspace execution until thaw. (Kernel 7.x note: SIGKILL still kills frozen processes — freeze stops computation, it does not shield against external kill.)
3. **Security camera** — default mode is audit: sessions run unrestricted while every file write is classified into `events.jsonl` as allowed or would-deny (`castellan audit <session>`). Harness-state folders are fingerprinted at spawn and diffed at exit, so a poisoned skill or hook gets flagged. This produces the false-block-rate data that decides whether enforce becomes the default.
4. **Surgical undo** — per-session rollback via overlayfs upper layer (`castellan launch --undo`), so one bad agent doesn't force a whole-disk rollback. `castellan diff/undo/keep` shows, discards, or commits the session's changes.
5. **Canary credentials** — fake credentials planted in the envelope, wired to a localhost honeypot. Using a canary IS the trigger: trip → event logged + session frozen. Egress lockdown (Landlock ABI 4 net rules) denies all TCP connect except the honeypot port.
6. **Earned autonomy** — per-project trust score (EWMA, tiers 0–4) fed by kernel-witnessed signals: placebo-controlled proof (+10, the only positive signal), clean session (+1), user revert (−30), envelope escape (−20), canary hit (−50). The trust tier is consulted at spawn: tiers 0–1 run fail-closed (enforce + undo + net forced, launcher flags ignored — the agent cannot self-widen), tiers 2+ run with the launcher's flags. Bless-broker approves record daemon-side one-shot grants (in-memory, never on disk where the agent could forge them) that override the floor for one expansion.
7. **Proof-carrying sessions** — `castellan cert <session>` assembles a ProofCertificate from kernel-witnessed state: bounds proof (event spine), placebo + test evidence (trust ledger, session-scoped). Quality labels STRONG/MODERATE/WEAK/NON-EVIDENTIAL. Kill-criterion benchmarks pass: 0/20 known-bad FN, 0/20 known-good FN, monotonic tier↔revert (ρ=0.900).
8. **Forensic replay** — `castellan replay <session> <narrower-project>` re-classifies the recorded event spine against an alternate envelope (static re-classification, never re-execution) and reports the permissive-case delta: writes the original envelope allowed that a narrower one would deny.

Designed, not built yet:

9. **HV fleet sync** — ed25519-signed cross-machine prototype exchange via Omarchy's usage-sync-folder (local outlier detection is shipped and live-verified; see `castellan radar`).
10. **Mid-session expansion restart** — a bless approval currently grants the *next* launch; re-minting the envelope of a *live* session (kill → relaunch same session id in a wider domain) is designed, not built. Landlock cannot be loosened mid-session, so this needs daemon-side re-fork orchestration.

## Independent e2e verification (poc-ten POC10)

A model-written ETL script with planted escapes (read `~/.ssh/id_ed25519`,
write `~/.config/pwned`, read `/proc/self/mem`) run under
`castellan launch --` on kernel 7.0.3: home write → PermissionError;
session writes invisible to the real project (overlayfs upper layer);
`diff` lists both planted artifacts. Read-escapes (`~/.ssh` read,
`/proc/self/mem` read) are **in-scope residuals** (P2 egress/net scope) —
the narrow-jail product claim is write-containment + undo + canaries
only, not read or egress blocking.

## Quickstart

Requires: systemd with a user session, cgroup v2, Linux 7.0+ (Landlock ABI 4+). Verified kernels: 7.0.3 and 7.1.8 (x86_64).

```sh
cargo build --release --workspace          # or download the release binary
castellan preflight                        # check your kernel: all 6 checks must pass
castellan daemon &                         # or run as a systemd user unit (recommended)
castellan launch -- claude                 # enforced by default: workspace-only writes
castellan status                           # see the session
castellan freeze && castellan thaw         # the panic button
castellan launch --undo -- claude          # every write lands in a discardable overlay
castellan diff <session>                    # what did it change?
castellan keep <session>                   # commit it, or `undo` to throw it away
```

`--harness` is auto-detected from the command (claude, codex, pi, opencode, aider, cursor-agent, gemini, crush); unknown harnesses still get the envelope, just no harness-state protection. `--no-enforce` opts out loudly (audit mode) — for debugging only.

## Why this fits Omarchy

Omarchy already treats agents as first-class (launchers, agents panel, crash diagnosis) but ships no safety story — its manual says "be ready to rollback if the agent makes a mess." Castellan slots onto existing motifs: channels ↔ trust tiers, migrations ↔ session migrations, snapshots ↔ surgical undo, agents panel ↔ freeze toggle. The core is reusable on any systemd + Landlock Linux regardless of whether Omarchy takes it.

## What we bring

No moat, no secrecy: everything here is buildable by anyone willing to write the kernel plumbing — Landlock and cgroups are documented Linux features, and nothing in this repo is protected. The individual primitives are all crowded (see [docs/PRIOR_ART.md](docs/PRIOR_ART.md) for the dated survey: Codex/Claude/Gemini sandboxes, AWS graduated autonomy, Thinkst canaries, overlayfs undo tools). What is unbuilt as of Aug 2026 is the **composition** — one OS-owned daemon applying envelope + freeze + undo + canaries + trust + approval + certificates across all harnesses simultaneously — plus the **placebo-controlled proof** as the only positive trust signal, and the **desktop-native unprivileged** form factor. What we have is momentum and inventory: the observation/proof layers are accelerated by internal primitives already built and benchmarked elsewhere in our repos (grammar-free fingerprinting, deterministic replay, placebo-controlled eval methodology, HDC memory) — see [docs/PRIMITIVES.md](docs/PRIMITIVES.md) for the full list with honest verdicts, including which ones died in testing. The kernel-enforcement layer contains zero borrowed magic; it is plain documented syscall work that anyone can replicate.

## Repo layout

```
README.md                      this
AGENTS.md                      conventions for AI agents working on castellan
Cargo.toml                     workspace: castellan-core, -policy, -freezer,
                               -envelope, -daemon, -cli
crates/
  castellan-core               session types, protocol, event spine
  castellan-policy             envelope classification (pure, unit-tested)
  castellan-freezer            cgroup v2 freeze/thaw/kill
  castellan-envelope           Landlock ruleset, seccomp BPF, audit watcher
  castellan-daemon             unix-socket server, session registry
  castellan-cli                castellan status|launch|audit|freeze|thaw|kill|...
test/shell.d/                  acceptance suites (run on a real desktop Linux;
                               need user cgroup slices — not CI-runnable)
docs/
  ARCHITECTURE.md              4 planes, substrate, event spine, 10 commitments
  THREAT_MODEL.md              Threat A/B/C, mitigations, residual risks
  ROADMAP.md                   P0-P5 with kill criteria and phase status
  PRIMITIVES.md                internal primitive inventory with real-data verdicts
  DESIGN_DECISIONS.md          antagonism record: what died, what hardened, why
  CRATES.md                    Rust workspace layout
  upstream-strategy.md         Omarchy integration path and PR sequence
  benchmark-methodology.md     cert-evals interleaved + placebo + SHA-256 cert
  glossary.md                  terms
  components/                  per-component design docs with status
```

## License

MIT. See [LICENSE](LICENSE).
