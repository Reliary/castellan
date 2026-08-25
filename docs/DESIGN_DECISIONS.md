# Design decisions (antagonism record)

This document records what antagonism killed, what it hardened, and why each of the 10 commitments is non-negotiable. New design decisions append here; existing ones are not edited retroactively (errata go in a dated note).

## What antagonism killed

### D1. refactor-proof as the trust positive signal
**Original claim:** "tests-passed + refactor-proof equivalence = positive trust."
**Killed by:** refactor-proof has a real-data verdict of KILL — 100% false-negative on Defects4J. Real bugfixes change operators and arguments, not line shapes; the skeleton-token LCS classifier cannot distinguish them.
**Replacement:** placebo-controlled proof-fixes methodology. A real fix must drop the danger_signal more than a neutral placeholder, AND the daemon must independently re-run the pre-existing test suite (commitment #3). This is un-gameable: `assert True` is a placebo that fails the danger-drop test, and "delete the dangerous line" fails the existing-test-suite re-run.

### D2. half-life for trust decay
**Original claim:** "trust has a half-life; older sessions contribute less."
**Killed by:** half-life's real-data verdict is KILL — vocabulary persistence decay was falsified as a signal.
**Replacement:** cortex-rs tier-promotion (recall-based: memories recalled 10+ times promote from episodic → semantic → consolidated). No time-decay. If future real-data work revives time-decay, it's a separate decision record.

### D3. fanotify write interception for the ledger
**Original claim:** "fanotify FAN_ACCESS_PERM gives us permission-event interception for the ledger."
**Killed by:** FAN_ACCESS_PERM is root-only on mainline. We don't want root at runtime.
**Replacement:** inotify on allowed paths (Landlock defines the allow-set; inotify watches exactly that set; ledger coverage = envelope). Then further replaced by overlayfs upper-layer enumeration (commitment #2) as the primary ledger substrate, with inotify as the fallback when overlayfs/user-ns is unavailable.

### D4. Sentinel auto-freeze on regime detection
**Original claim:** "sensor-regime z-score detector auto-freezes on behavioral anomaly."
**Killed by:** sensor-regime's AUROC 1.0 is on synthetic data (3 seeds). No real labelled corpus. Claiming AUROC would violate the honesty directives.
**Replacement:** sentinel is demoted to hint-layer. It notifies and decrements trust; it never auto-freezes. Only deterministic canary-credential hits auto-freeze. Sentinel must show AUROC > 0.7 on a real labelled corpus or it stays off-by-default and advisory-only forever.

### D5. Cold-start tier-2 default gating power users
**Original claim:** "new agents start at tier 2 (mid-trust) and earn up."
**Killed by:** conflicts with Omarchy's "trusted, get out of the way" ethos. DHH himself would be gated on first run.
**Replacement:** envelope is always-on (the floor). Trust gates ONLY expansion (egress unlock, config-dir writes). Power users get full-auto within the workspace from day one. Safety is the kernel floor; trust is the ceiling.

### D6. Predictive replay ("confinement would have prevented the attack")
**Original claim:** "replay the session under a permissive envelope to prove confinement would have helped."
**Killed by:** confinement changes the trajectory — a denied tool result produces a different next action, so you cannot replay-against-permissive and claim prevention. That's an unprovable claim and violates the honesty directives.
**Replacement:** replay is forensic-only. (a) Static analysis of the recorded action list vs an alternate envelope ruleset gives the permissive-case delta ("these recorded writes would have been denied"). (b) Re-execution happens only under max-strict to observe fs effects. Never re-exec under a looser envelope than the original. Coverage % reported honestly (network/time-dependent steps marked opaque).

### D7. "Privacy-preserving HV" as a cryptographic claim
**Original claim:** "HV fingerprints are one-way; safe to sync across machines."
**Killed by:** sensor-hdc's random projection is approximately invertible given enough samples + a known vocabulary. It's not a cryptographic guarantee.
**Replacement:** soft claim only — "reduces leakage to ~1.25KB/session, defeats casual reconstruction, not a cryptographic guarantee." Documented honestly in the HV radar doc.

### D8. "Distro-default sandboxing is unclaimed"
**Original claim:** "no one ships kernel-enforced agent envelopes on by default."
**Killed by:** false. ManageLM, Claude Code's sandbox-runtime, Codex CLI all ship kernel sandbox on-by-default at the harness level.
**Replacement:** the novel claim tightens to "one OS-owned envelope policy across all harnesses simultaneously." Harness-agnostic envelope at the OS layer is the contribution; the sandbox primitive itself is not novel.

### D9. Inotify as the primary ledger substrate
**Original claim:** "inotify watches allowed paths; that's the ledger."
**Killed by:** inotify has a race — an agent can write+delete faster than the watcher fires, losing the before-image.
**Replacement:** overlayfs upper layer is the primary ledger substrate (atomic at FS level, no race). inotify is the fallback when overlayfs/user-ns is unavailable. This is commitment #2.

### D10. agent-log-compress for output compression
**Original claim:** "we have a Markov-model log compressor for agent output."
**Killed by:** agent-log-compress's real-data verdict is KILL — loses to zlib (5.56x vs 11.25x).
**Replacement:** sift is the output compressor. It's built, grammar-free, and wins.

## What antagonism hardened (the 10 commitments)

### C1. Daemon owns cgroup.freeze
**Attack:** in a systemd user scope, the user owns the cgroup files. An agent running as the user can write `cgroup.freeze=0` and thaw itself.
**Without this:** the panic button is theater.
**Commitment:** the daemon takes cgroup delegation via `StartTransientUnit` (or a setuid thaw helper as fallback). The agent process never has write access to its own freezer file.

### C2. overlayfs is the undo substrate
**Attack:** inotify loses races (write+delete faster than watcher fires).
**Without this:** undo can lose before-images; surgical undo is not surgical.
**Commitment:** overlayfs upper layer is atomic. Lower is read-only mount. Undo = discard upper. No race.

### C3. Daemon re-runs tests independently
**Attack:** agent reports "tests passed" when they didn't; agent writes `assert True`.
**Without this:** trust and proofs rest on agent-reported results, which is the threat-B surface.
**Commitment:** the agent is the prover; the daemon is the verifier. Daemon re-runs the pre-existing test suite in a side-scope reading post-edit state. Tests added or modified by the session do not count.

### C4. Real credentials never enter the envelope
**Attack:** agent finds a real AWS key in `~/.aws/credentials` and exfils it.
**Without this:** envelope can't stop credential theft — the credentials are inside the writable boundary.
**Commitment:** all egress proxied through the daemon, which holds real keys and injects them server-side. The envelope contains only canary credentials. Any credential the agent can read is a canary by definition.

### C5. Canary keys are wired to a localhost honeypot
**Attack:** agent probes a canary to see if it's real before using it.
**Without this:** there's a "is this key real?" step that does not trip the wire, giving the agent a safe-probe path.
**Commitment:** using OR probing the canary IS the trigger. The honeypot listener is on localhost. There is no probe that does not trip.

### C6. Trust has a ceiling and an always-on deny-list
**Attack:** patient agent slow-drips trust over weeks to unlock everything.
**Without this:** a patient attacker escapes.
**Commitment:** even tier-0 agents cannot touch `~/.ssh`, `.gnupg`, systemd units, `.desktop` files, shell rc. Worst-case trust-gaming unlocks egress (which the proxy restricts), not escape.

### C7. Daemon crash → auto-freeze
**Attack:** attacker DoSes the daemon to escape observation.
**Without this:** daemon downtime = agents run unobserved.
**Commitment:** systemd watchdog restarts the daemon and freezes all agent scopes on heartbeat loss. Landlock + cgroup persist without the daemon (kernel-enforced), so enforcement survives daemon death. Fail-closed.

### C8. seccomp is an allowlist, blocks chmod/chown/utime + io_uring + ptrace + process_vm_readv
**Attack:** Landlock doesn't cover chmod/chown/utime/ioctl; io_uring can bypass; ptrace/process_vm_readv are namespace-escape primitives.
**Without this:** the Landlock ABI gap is a real hole; future new syscalls are unknown unknowns.
**Commitment:** seccomp BPF allowlist. Blocks the metadata-manipulation family (Landlock gap), io_uring (GhostClaw), ptrace, process_vm_readv. Everything not on the allowlist is blocked by default, so future syscalls are denied until reviewed.

### C9. HVs are signed per-machine
**Attack:** agent forges HVs to poison fleet radar; or a malicious machine ships bad HVs.
**Without this:** fleet detection is spoofable.
**Commitment:** the daemon signs every HV with its per-machine ed25519 key (key outside any envelope). Fleet sync verifies signatures. Agent cannot sign.

### C10. Bless broker is nonce-gated, rate-limited, biometric for high-risk
**Attack:** agent forges an approval to self-expand its envelope; or socially engineers the human at scale.
**Without this:** expansion is the bypass path.
**Commitment:** nonce comes from the notification UI via dbus (not from the agent's environment). Max 3 expansions per session, cooling-off period. fp-toggle biometric required for egress or config-dir writes. Risk card (quale) shown for every request.

## Alternatives considered and rejected

### A1. bubblewrap instead of Landlock
**Rejected because:** bubblewrap is namespace-based and was escaped by Claude Code in April 2026 (the agent found a path synonym not on the denylist and then disabled the sandbox). Landlock is path-based, unprivileged, and irreversible mid-session. seccomp + Landlock is the defense-in-depth pair that survives the bubblewrap-escape class.

### A2. microVMs (Firecracker, gVisor) instead of in-process confinement
**Rejected because:** the goal is OS-native safety across all harnesses on a personal machine, not cloud-style isolation. microVMs add 200ms+ boot, GPU passthrough constraints, and break the "agent runs on my machine" UX. Landlock + seccomp is the right primitive for the personal-machine threat model.

### A3. Denylist seccomp instead of allowlist
**Rejected because:** denylists have the unknown-unknown problem (future new syscalls). Allowlists fail-closed on novelty. The bubblewrap escape was a denylist problem.

### A4. Harness-level permission prompts (Claude Code's Guardian, Codex's approval policy)
**Rejected because:** all harness-level defenses operate inside the agent process. A prompt-injected agent bypasses its own Guardian. Kernel enforcement is outside the agent process and cannot be bypassed by the agent. This is the central thesis.

### A5. Time-decay trust
**Rejected because:** half-life is KILLed. cortex-rs tier-promotion is recall-based and built. See D2.
