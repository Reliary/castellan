# Upstream strategy

Target: [basecamp/omarchy](https://github.com/basecamp/omarchy) (quattro branch, MIT, ~31k stars). Standalone incubation first; upstream proposals once benchmarks pass.

## Why standalone first

The antagonism rounds surfaced heavy architectural commitments (overlayfs undo substrate, egress proxy with credential injection, daemon-owned freezer, user-namespace mounts). These are weeks of greenfield Rust before any owned primitive wires in. Building directly in a fork of omarchy from day one would produce a long-lived divergent branch with no path to merge until the enforcement core is solid. Standalone lets us:

- ship P0 (freeze) as a real upstream PR immediately — it's small, delightful, zero threat-model stakes
- dogfood P1-P4 on our own machines without forcing omarchy users onto an unstable enforcement core
- keep the proof-carrying + radar work in our repo where it can mature without omarchy's merge-burden
- propose adoption once each phase has passed its kill criterion with benchmark evidence

## PR sequence to omarchy

Each PR is atomic, matches Omarchy's `AGENTS.md` conventions (`omarchy-` prefix, `GROUP_DESCRIPTIONS` updates, bash 5 conditionals, `[[ ]]` / `(( ))`, two-space indent, full-line markdown), and degrades gracefully when the castellan binary is absent (their `cmd-present` philosophy).

### PR 1 — freeze (Phase 0)
- Adds `omarchy-freeze` command group to `bin/`
- Quickshell QML plugin for the agents panel (freeze toggle, frozen indicator)
- Hyprland keybind Super+Escape
- `omarchy-freeze toggle|all|status|thaw` (thaw prompts fp-toggle biometric if available)
- No Landlock, no daemon, no claims — just cgroup.freeze over processes named like known agents (claude, codex, pi, omp, ori, crush, copilot, agy, grok)
- Updates `GROUP_DESCRIPTIONS`
- Skill entry: "Castellan freeze is a panic button, not a sandbox"
- **Acceptance:** works on 5 concurrent sessions across 3 harness brands; zero self-thaw; < 50ms; no crash on session exit

### PR 2 — audit-mode wrapper (Phase 1, audit-only)
- Adds `omarchy-launch-agent` wrapping the existing mise-stub launch path
- When `castellan-daemon` is present: launches agent in a Landlock+seccomp envelope in audit mode (deny logged, not enforced), writes events to `~/.local/state/castellan/`
- When absent: execs the agent directly (zero behavior change)
- No enforce-default. No claims. Audit logs only.
- Migration: existing installs get audit mode opt-in via `omarchy toggle agent-audit`
- **Acceptance:** false-block rate on legit omarchy workloads reported in PR description; no behavior change for users who don't toggle it on

### PR 3 — surgical undo (Phase 2)
- Adds `omarchy-agent-undo <session>` command
- Requires castellan daemon + overlayfs; degrades to "not available" message otherwise
- 3-way merge UX, freeze-before-undo
- **Acceptance:** undo correctly reverses 100% of kernel-witnessed writes on 20 test sessions with concurrent unrelated user edits

### PR 4 — trust badge in agents panel (Phase 3, advisory)
- QML plugin shows per-project trust tier as a badge in the existing agents panel
- Trust gates expansion only; no auto-enforce
- Bless-broker notification UI (dbus nonce-gated, fp-toggle for high-risk)
- **Acceptance:** monotonic tier-vs-revert-outcome relationship demonstrated on labelled corpus in PR description; if not met, ships as advisory badge only with no gating

### PR 5 — proof-carrying session export (Phase 4)
- Adds `omarchy-agent-proof <session>` command exporting a ProofCertificate via evidence-pack
- `omarchy-agent-replay <session> --under-envelope <profile>` for forensic replay
- **Acceptance:** known-bad/known-good classification rates reported honestly in PR description with placebo-controlled methodology

### PR 6+ — opt-in analysis (Phase 5)
- HV radar, engfield priors, sentinel hint — all opt-in, all off-by-default
- Documented as experimental; no default-omarchy behavior change

## What stays in castellan, never proposed for omarchy

- The CVEfixes DB (49 GB, local only)
- relay-vuln full scan (too heavy for default distro)
- HV fleet sync (cross-machine, experimental)
- The daemon's internal crate structure (omarchy just sees the `omarchy-*` shims and the optional binary)

## Coordination with omarchy maintainers

Before PR 1, open a discussion issue on basecamp/omarchy:
- State the intent (OS-native agent safety, harness-agnostic)
- Share the castellan repo link and ARCHITECTURE.md
- Ask for feedback on the `omarchy-freeze` command shape and QML plugin placement
- Disclose the crash-diagnosis prompt-injection observation (Threat C5) as a concrete contribution beyond the safety system itself

Do NOT lead with security theater or unverified claims. Lead with the freeze demo, the disclosure, and the architecture doc. Let the proof-carrying work speak for itself in PR 5.
