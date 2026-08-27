# Prior art — what already exists (surveyed Aug 2026)

This doc exists to keep claims honest. Every piece of castellan was checked
against the current landscape before being called a contribution. The
verdict: **the individual primitives are all crowded; the composition is
not.** Cite this doc before making any "novel" or "first" claim.

## Kernel containment primitives — crowded

| Primitive | Existing products | Notes |
|---|---|---|
| Landlock LSM | ChromeOS Minijail, firejail, landrun, rstrict, sandboxec; OpenAI Codex used Landlock then demoted it to fallback behind bubblewrap+seccomp | systemd `LandlockConfig` is a draft PR, not merged |
| seccomp BPF | Docker default profile, nsjail, gVisor, Chromium, firejail | commodity |
| cgroup v2 freeze | systemd `systemctl freeze` (v246+), AgentCgroup research (freeze under memory pressure) | no shipped agent kill-switch product uses freeze |
| OverlayFS per-session undo | oops, rewind-sdk, teleport-env, RewindBPF (envelope+undo+policy), Docker overlay2, btrfs snapshots, NixOS | per-session agent undo exists |
| Canary credentials / honeytokens | Thinkst Canarytokens (incl. AI Agent Guardrail Triggers + MCP token), AWS honeytoken infra, agent-canary (alert-only) | **no product wires canaries into agent envelopes with auto-freeze** |
| Trust tiers / earned autonomy | AWS "Closing the AI agent trust gap with graduated autonomy" (T1–T4, Cedar policy, honeypot-injection → demotion, rollback, emergency stop), Prove7, VeriSwarm, Microsoft AgentMesh (0–1000 scoring), IETF progressive-trust drafts | **AWS graduated autonomy is the closest thing to castellan's P3** |
| Human approval gates | Codex approval policies + auto-review, Claude Code auto mode, Gemini sandbox expansion requests (≈ bless-broker), sudo/polkit | crowded |
| Proof-carrying code | Necula POPL'97; PCAA (Proof-Carrying Agent Actions, arXiv), FAVA, proof-carrying certs for LLM pipelines (Lean 4) | research-only, not shipped |

## Agent sandboxing products (harness-level)

- **OpenAI Codex CLI** — per-command sandbox: bubblewrap + seccomp on
  Linux (Landlock demoted to fallback), Seatbelt on macOS. Read-only /
  workspace-write / danger-full-access modes + approval policies.
- **Anthropic Claude Code** — bubblewrap + optional seccomp on Linux,
  Seatbelt on macOS; applies to the Bash tool only; network isolation via
  SOCKS5 proxy with domain allowlist; open-sourced sandbox-runtime.
- **Google Gemini CLI** — Docker/Podman containers (default on Linux),
  optional gVisor/LXC; per-tool sandboxing; sandbox expansion requests
  (human approval gate).
- **Cloud sandboxes** — E2B (Firecracker microVMs), Modal (gVisor +
  snapshots/rollback), Vercel Sandbox, Daytona. Isolation + rollback, no
  trust scoring, no approval gates.

All of these confine **their own harness only**. None applies one policy
across every agent brand simultaneously.

## Agent security startups — proxy/gateway layer, not OS

Zenity, Lasso Security, Prompt Security, Lakera, Wiz, Harmonic, Cyera
(Agent Guardian), Protect AI (→ Prisma AIRS). All operate at
proxy/gateway/MCP/agent layer: discovery, posture, intent detection,
inline block/redact. **None does OS-kernel containment.**

## Standards / research

- NIST AI Agent Standards Initiative (Feb 2026); CAISI RFI on agent
  security; NCCoE agent identity/authorization concept paper. Focus:
  identity, authorization, posture — not OS sandboxing.
- Benchmarks: AgentDojo, InjecAgent, AgentShield, ASB, AgentDefense-Bench.
- **Placebo-controlled evaluation of agent fixes: not found anywhere.**
  Nearest analogues are matched benign/attack suites (AgentDojo's
  utility-under-attack, AgentShield's over-refusal penalty). The
  placebo-control methodology (real fix must drop danger more than a
  neutral placeholder) is castellan's own, inherited from proof-fixes'
  real-data work on CVEfixes.

## What this means for castellan's claims

**Not novel (do not claim):** Landlock/seccomp envelopes, cgroup freeze,
overlayfs undo, canary credentials, trust tiers, approval gates,
proof-carrying agent actions. All exist in some form.

**Genuinely unbuilt as of Aug 2026 (claimable, with dated proof):**
1. **The composition** — one OS-owned daemon applying envelope + freeze +
   undo + canaries + trust + approval + certificates across ALL harnesses
   simultaneously. Closest partials: RewindBPF (envelope+undo, no
   freeze/trust/canaries), AWS graduated autonomy (trust+approval, no OS
   envelope), AgentCgroup (freeze only).
2. **Placebo-controlled proof as the only positive trust signal** — no
   prior art found.
3. **Desktop-native, unprivileged** — everything above is CLI/cloud;
   castellan's verified unprivileged cgroup freeze (no systemd
   delegation, kernel 7.0.3) and panic-button UX are desktop-native.
4. **ProofCertificate as a shipped artifact** — PCAA is research;
   `castellan cert` ships.

## Corrections owed

- Earlier internal surveys missed **AWS graduated autonomy** and
  **Thinkst's agent canaries** — the two closest things to P3/P4. This
  doc supersedes those surveys.
- "OpenAI Linux distro" is **unverified rumor** — no such distro exists
  per this survey. Do not cite it.
