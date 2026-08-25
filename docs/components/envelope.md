# Envelope

The Landlock + seccomp ruleset applied to a session at spawn. Defines what the agent can write, what it can connect to, and which syscalls it can issue. Irreversible mid-session. Inherited by all children regardless of how they're spawned.

## Mechanism

At spawn, `castellan-daemon` (via the `castellan-envelope` crate) builds two rulesets and applies them to the agent process before exec:

### Landlock ruleset
- **Read:** broad — `$HOME`, `/usr`, `/etc`, `/opt`, system libs. Reading is cheap to allow and denials here are the false-block killer.
- **Write:** allow-set = project dir + harness state dirs (`~/.claude`, `~/.codex`, `~/.pi/agent`, `~/.gemini`, `~/.local/state/claude` etc.) + session scratch at `~/.local/state/castellan/sessions/<uuid>/`. Everything else denied.
- **Hard deny (always-on, regardless of trust tier — commitment #6):** `~/.ssh`, `~/.gnupg`, `~/.config/omarchy`, `~/.config/systemd`, `~/.local/share/systemd`, `~/.config/hypr` (unless expanded via bless broker), `.desktop` files anywhere, shell rc files (`~/.bashrc`, `~/.zshrc`, `~/.profile`).
- **Network (Landlock ABI v4+, Arch kernels have it):** phase v0 = no network restriction (filesystem-only envelope). Phase v1 = TCP bind/connect restricted to loopback + 443. Phase v2 = egress proxy (see egress-proxy.md) replaces direct network entirely.

### seccomp BPF filter (commitment #8)
- **Allowlist, not denylist.** Everything not on the list is blocked by default, so future new syscalls are denied until reviewed.
- **Blocked syscalls:** `chmod`, `fchmod`, `chown`, `fchown`, `lchown`, `utime`, `utimes`, `utimensat`, `futimesat` (Landlock ABI gap), `io_uring_setup`, `io_uring_enter`, `io_uring_register` (GhostClaw bypass), `ptrace`, `process_vm_readv`, `process_vm_writev` (namespace-escape primitives), `mount`, `umount2`, `pivot_root` (filesystem topology), `keyctl`, `bpf` (privilege escalation).
- **PR_SET_NO_NEW_PRIVS** set before restrict_self.

## Degrade tiers (documented honestly)

1. **Full capability:** Landlock ABI v4+ (network) + seccomp + user namespaces + overlayfs. Arch kernels ≥ 6.12 ship this. This is the assumed baseline on Omarchy.
2. **Filesystem-only envelope:** Landlock ABI v3 (no network restrictions). seccomp still applies. Egress enforced by the proxy, not Landlock.
3. **seccomp-only:** Landlock unavailable or ABI < v3. Filesystem writes are NOT kernel-restricted — this is "audit mode at the kernel level." Daemon logs all writes via inotify; trust heavily penalizes any session run in this tier.
4. **Fail-closed:** Landlock unavailable AND user configured `enforce` mode → refuse to launch the agent. Configurable to `audit` (launch with inotify-only observation).

Detection: `castellan-envelope detect-abi` returns the available tier; the daemon uses the highest tier present.

## Envelope profiles (derived from trust tier)

- **tier 2 (cold start, default):** workspace + harness state writable; no egress; config-dir writes via bless broker only.
- **tier 3 (50-79):** + egress via proxy (allowlist); config-dir via bless.
- **tier 4 (80-99):** + egress broader allowlist; config-dir writes auto-approved (still kernel-logged).
- **tier 5 (100):** + system config writes via bless biometric. Still cannot touch the always-on deny-list (commitment #6).

Profiles are minted at spawn from trust.db. Mid-session expansion is impossible (Landlock irreversible) — expansion happens via bless broker, which restarts the session in a new wider domain (with the human's approval). This is a real UX cost; document it.

## Antagonism survivors

- A1 (raw exec bypass): closed — Landlock inherits.
- A2 (write wrapper/daemon): closed — outside allow-set.
- A4 (chmod/chown/utime): closed — seccomp blocks.
- C1 (compromised harness): closed — confinement is OS-level, harness code irrelevant.
- C2 (malicious MCP): closed — MCP servers are children, inherit envelope.

## Open questions

- Does the harness state dir allow-set create a persistence hole (a malicious skill written to `~/.claude/skills/`)? Yes — closed by harness-state-watcher, not by the envelope alone. See harness-state-watcher.md.
- How does `omarchy agent crash <pid>` (the coredump-diagnosis path) get wrapped? With a diagnosis-only profile: read-only fs, no egress except the LLM provider, no writes. See Threat C5.
- What about agents that need `~/.config/hypr` edits (that IS Omarchy customization)? Via bless broker expansion to a config-writer profile, minted fresh. Default agents don't get it.

## Dependencies

- `castellan-core` (SessionId, EnvelopeProfile, TrustTier)
- `castellan-trust` (tier → profile)
- `nix` crate (Landlock, seccomp syscalls)
- Owned primitive: `quale` for sizing hints (advisory — quale's hub-risk can suggest which paths a task class typically touches; NOT load-bearing, NOT a claim).

## Status

Greenfield. No Landlock or seccomp code exists anywhere in our repos. This is the build-cost bottleneck (Phase 1, 2-3 weeks).
