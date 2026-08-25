# Threat model

Three threat classes, antagonised in order. Each attack vector is marked with its status: **closed** (mitigated by construction or commitment), **mitigated** (reduced but not eliminated), or **residual** (documented, cannot be closed without larger architecture changes).

## Threat A — Agent pulls its own levers

The agent tries to disable, widen, or escape the safety system.

### A1. Agent execs a raw harness binary, bypassing the wrapper
**closed.** Landlock domains are inherited by all children regardless of how they're spawned. A raw `claude` exec'd by the agent inherits the same restrictions. seccomp filters inherit too.

### A2. Agent writes to the wrapper binary, daemon config, trust.db, or daemon socket
**closed.** All of those paths are outside the envelope's allow-set. Landlock denies the write.

### A3. Agent thaws itself by writing `cgroup.freeze=0`
**closed by commitment #1.** In a systemd user scope, the user owns the cgroup files, so an agent running as the user could thaw itself — UNLESS the daemon owns the freezer file. The daemon takes cgroup delegation via `StartTransientUnit` (or a setuid thaw helper as fallback). This is P0 critical-path: if the agent can thaw itself, the panic button is theater.

### A4. Agent uses chmod/chown/utime/ioctl to alter files Landlock doesn't restrict
**closed by commitment #8.** Landlock's filesystem flags don't cover `chmod`, `chown`, `utime`, some `ioctl`, `fcntl`. seccomp blocks the `chmod`/`chown`/`fchmod`/`fchown`/`utime`/`futimes` syscall family. seccomp is an allowlist, so future new metadata-manipulation syscalls are blocked by default.

### A5. Agent games the trust score with fake tests (`assert True`)
**closed.** Positive trust signals require: (a) placebo-controlled proof (real fix drops danger_signal more than a neutral placeholder — `assert True` is a placebo that fails this), AND (b) the daemon independently re-runs the pre-existing test suite (commitment #3) in a side-scope reading post-edit state. Tests added or modified by the session do not count. The agent is the prover; the daemon is the verifier.

### A6. Agent fakes a placebo proof
**closed.** Placebo control is two-factor: the neutral placeholder must NOT drop danger_signal while the real fix must. "Delete the dangerous line" fails because existing tests break (daemon-re-run). Only a real guard that drops danger without breaking tests passes both factors.

### A7. Agent Sybil-attacks (many tiny sessions to farm trust)
**closed.** Trust is per-project, sessions must have a non-empty kernel-witnessed ledger, and there is a ceiling per time-window (cannot jump tiers in one day).

### A8. Agent slow-drips trust over weeks (patient accumulation)
**residual, mitigated.** Ceiling + always-on deny-list (commitment #6) means worst-case trust-gaming unlocks egress, not escape. Documented. Not eliminated: a patient attacker who earns egress and then exploits a network-reachable vulnerability is a real path. The mitigate is the egress proxy (commitment #4) which restricts what egress can reach even when unlocked.

### A9. Agent replays a stolen proof certificate
**closed.** ProofCertificates are session-bound: UUID + cgroup start time + ledger hash. The daemon verifies the session actually happened by checking the kernel-witnessed event spine.

### A10. Agent corrupts the undo ledger
**closed by commitment #2.** overlayfs lower layer is read-only mount; the agent cannot modify it. The blob store is outside the envelope. The upper layer IS agent-writable (that's the point), but undo = discard upper, so a corrupted upper is undone by discarding it.

### A11. Agent DoSes the daemon with event flooding
**closed.** Per-session rate limit on event ingest. Daemon watchdog (commitment #7) catches daemon resource exhaustion → auto-freeze.

## Threat B — Agent fakes

The agent fabricates outputs, results, or telemetry to appear compliant.

### B1. Agent reports "tests passed" when they didn't
**closed by commitment #3.** Daemon re-runs tests independently. Agent-reported results are advisory only and never feed trust or proofs.

### B2. Agent reports "I only touched X" when it touched Y
**closed.** Ledger is kernel-witnessed (inotify on allowed paths + overlayfs upper enumeration). The agent's declared audit-trail is forensically compared to kernel truth; mismatches are flagged and decrement trust.

### B3. Agent uses a real credential it found in the envelope
**closed by commitments #4 and #5.** Real credentials never enter the envelope. Every credential the agent can read is a canary wired to a localhost honeypot. Using it IS the trigger; there is no "probe first" step that does not trip the wire.

### B4. Agent forges HV fingerprints to poison fleet radar
**closed by commitment #9.** HVs are computed by the daemon from the kernel-witnessed event stream, then signed with the per-machine ed25519 key. The key lives outside any envelope. The agent cannot sign, so forged HVs are rejected at fleet sync.

### B5. Agent forges a bless-broker nonce to self-approve an expansion
**closed by commitment #10.** The nonce is generated by the notification UI via dbus, not by anything in the agent's environment. The agent cannot forge it.

### B6. Agent tampers with the audit trail
**closed by agent-audit-trail design.** agent-audit-trail is a hash chain (`prev_hash` computed, not stored; `verify()` detects both content tamper and chain breaks). The agent could append fabricated entries, but those are labeled advisory and cross-checked against kernel truth. Mismatches decrement trust.

## Threat C — Malicious actor (external)

An external attacker targets the agent, the harness, or the safety system.

### C1. Compromised harness (supply-chain attack on Claude Code / Codex / Pi)
**closed by construction.** The entire point of OS-level enforcement: a compromised harness is STILL confined by the envelope. It cannot touch `~/.ssh`, systemd, `.desktop`, etc., regardless of what the harness code does.

### C2. Malicious MCP server
**closed.** MCP servers are subprocesses spawned by the harness, so they inherit the envelope. A malicious MCP server cannot exfiltrate via real credentials (envelope has none — commitment #4) and cannot write outside the envelope.

### C3. Poisoned skill written to `~/.claude/skills/` (allowed in envelope for harness function)
**closed by harness-state-watcher.** skein/carrion fingerprint baseline of `~/.claude/skills/`, `~/.codex/skills/`, `~/.pi/agent/skills/` at install. Delta = new skill or hook → notify + quarantine pending human approval. This closes the persistence-vector hole that Landlock alone can't (the harness state dir must be writable for the harness to function).

### C4. Persistence via workspace files (agent writes malicious `.envrc` or build script)
**residual, mitigated.** The workspace is writable by the agent and executable by the user's shell (outside the envelope). A planted `.envrc` runs when the user's shell next enters the dir. Cannot be prevented (the workspace MUST be writable for the agent to do its job). Detected by: post-session relay-vuln scan of workspace additions, skein fingerprint diff of workspace before/after. seccomp-blocking chmod (commitment #8) means the agent cannot `chmod +x` its planted file, but the user's shell can. This is a fundamental trust-transfer boundary we instrument, not eliminate.

### C5. Prompt injection via core dumps (Omarchy's crash-diagnosis pipeline)
**closed for castellan-wrapped sessions.** Omarchy's `omarchy agent crash <pid>` hands coredumps to the default agent unattended. Core dumps contain attacker-influenced bytes (symbol names, paths) — an indirect prompt injection vector. Castellan wraps the crash-diagnosis agent in a read-only envelope (no writes, no egress except the LLM provider), so even if injected, it cannot act. Upstream contribution: harden `omarchy agent crash` to launch via castellan with a diagnosis-only profile.

### C6. Indirect prompt injection via tool outputs (logs, web pages, commit messages)
**mitigated, not closed.** Envelope + egress proxy limit what an injected agent can DO (can't touch secrets, can't exfil real creds), but cannot prevent the agent from being confused. The harm is bounded: worst case the agent writes garbage in the workspace (undoable) or makes bad edits (surgical undo). Trust decrements on suspicious patterns. Canary credentials catch credential-exfil attempts. This is the inherent limit of OS-level defense against semantic attacks — we bound the blast radius, we don't prevent the confusion.

### C7. Daemon crash / DoS
**closed by commitment #7.** Landlock + cgroup persist without the daemon (kernel-enforced). Daemon heartbeat stops → systemd restarts daemon AND auto-freezes all agent scopes. Fail-closed.

### C8. Pre-existing compromise (malware already running as user before castellan)
**residual.** Castellan assumes a clean install. Pre-existing malware with user privileges could interfere. Documented as a prerequisite. Mitigation: castellan ships as part of a clean Omarchy install, not as a bolt-on for already-compromised systems.

### C9. Kernel compromise
**out of scope.** A kernel break breaks everything, including us. Documented.

## Residual risks summary

| Risk | Status | Mitigation |
|---|---|---|
| Patient trust-gaming → egress | residual | ceiling + deny-list + egress proxy limit reach |
| relay-vuln false negatives | residual | proof labeled "best-effort detection," not "proven safe" |
| Human social-engineering at bless broker | residual | risk card + biometric + cooling-off inform, can't prevent |
| Persistence via workspace files | residual | post-session scan + skein diff detect, can't prevent |
| Pre-existing compromise | residual | clean-install prerequisite documented |
| Indirect prompt injection (semantic) | mitigated | blast radius bounded by envelope + proxy, confusion not prevented |
