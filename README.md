# castellan

**The OS is the trust boundary for AI agents.**

Castellan is a Linux-native agent safety system that confines, observes, and proves what AI coding agents do on your machine — at the kernel level, where prompt injection cannot reach. It is being designed as a contribution to [Omarchy](https://github.com/basecamp/omarchy) (DHH's Arch + Hyprland distro), but the core is reusable on any systemd + Landlock Linux.

> **Status: planning.** This repository contains the design and plan. No code is shipped yet. Every claim below is either grounded in an owned, built primitive (see [docs/PRIMITIVES.md](docs/PRIMITIVES.md)) or marked as greenfield. No savings, no percentages, no security guarantees until benchmarks pass — see [docs/benchmark-methodology.md](docs/benchmark-methodology.md).

## The problem in one sentence

AI agents now run unattended on personal machines with broad filesystem and network access, and every safety tool today lives *inside the agent* — which is exactly the part prompt injection hijacks.

## The pitch in plain English

Omarchy (and any modern Linux distro with agents) owns the one layer a single safety policy can use to lock every brand of agent identically: the OS itself. No harness vendor can do this (they only control their own agent); no agent-safety SaaS can (they're not the distro). Castellan makes the kernel the trust boundary so the agent cannot argue with it, bypass it, or be tricked out of it.

## The five pieces

1. **Kernel walls** — when any agent launches, Landlock + seccomp confine its writes to the project + harness state. It physically cannot touch `~/.ssh`, systemd units, `.desktop` files, shell rc — even if a webpage tricks it into trying. Zero harness configuration; the OS does it.
2. **Panic button** — Super+Escape freezes every running agent instantly via cgroup v2 freezer (kernel-level; frozen processes can't even handle signals until thaw). Biometric thaw via the fingerprint reader.
3. **Surgical undo** — every file the agent touched is kernel-witnessed (not agent-reported) via an overlayfs upper layer. `castellan undo <session>` reverses exactly that session — no reboot, no whole-disk snapshot, no nuking your unrelated edits.
4. **Earned autonomy** — agents start confined to the workspace (full-auto within it). To unlock network or config-dir writes they *earn* it via placebo-controlled proofs: an agent writing `assert True` fails the gate; only a real guard that drops danger passes. Sloppy or compromised agents get a narrower cage automatically.
5. **Proof-carrying sessions** — every session ends with a cryptographic certificate: stayed in bounds, didn't remove validation paths, preserved config completeness, passed placebo tests. Tamper-evident, exportable, transferable — verified sessions raise a project's trust tier fleet-wide.

## Unique value

**To Omarchy:** Omarchy already treats agents as first-class (launchers, agents panel, crash diagnosis) but has no safety story — its manual literally says "be ready to rollback if the agent makes a mess." Castellan slots onto existing Omarchy motifs: channels ↔ trust tiers, migrations ↔ session migrations, snapshots ↔ surgical undo, agents panel ↔ freeze toggle + trust badge.

**To general Linux:** The pattern is "one OS-owned agent-safety policy across all harnesses" — reusable on any systemd + Landlock Linux. Proof-carrying sessions are novel to agent safety: they convert "trust the agent" into "verify the agent's proof." Placebo-controlled positive trust solves the gaming problem every reputation system has.

## Why us

Anyone can plumb Landlock + cgroup (the enforcement layer is greenfield Rust, no moat there). The moat is the proof + observation layer, built from primitives we already own that nobody else in agent safety has: HDC tier-promotion memory (cortex-rs), placebo-controlled proof (proof-fixes, cert-evals), proof-carrying vuln detection (relay-vuln, evidence-pack), grammar-free fingerprinting (stria, skein, agent-profile), completeness auditors (seq-engine, config-radar), deterministic replay (llm-replay). See [docs/PRIMITIVES.md](docs/PRIMITIVES.md) for the full inventory with honest verdicts.

## Repo layout

```
README.md                      this
AGENTS.md                      conventions for AI agents working on castellan
Cargo.toml                     workspace (members stubbed until build)
docs/
  ARCHITECTURE.md              4 planes, substrate, event spine, 10 commitments
  THREAT_MODEL.md              Threat A/B/C, mitigations, residual risks
  ROADMAP.md                   P0-P5 with kill criteria
  PRIMITIVES.md                owned primitive inventory with real-data verdicts
  DESIGN_DECISIONS.md          antagonism record: what died, what hardened, why
  CRATES.md                    proposed Rust workspace layout
  upstream-strategy.md         Omarchy integration path and PR sequence
  benchmark-methodology.md     cert-evals interleaved + placebo + SHA-256 cert
  glossary.md                  terms
  components/                  per-component design docs
    envelope.md  freezer.md  undo.md  trust.md  proof-carrying.md
    egress-proxy.md  canary-credentials.md  harness-state-watcher.md
    ledger.md  hv-radar.md  sentinel.md  bless-broker.md  daemon.md
```

## License

MIT. See [LICENSE](LICENSE).
