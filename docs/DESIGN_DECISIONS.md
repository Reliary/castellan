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
**Replacement:** the claim tightens to "one OS-owned envelope policy across all harnesses simultaneously." Harness-agnostic envelope at the OS layer is the contribution; the sandbox primitive itself is not novel. See [PRIOR_ART.md](PRIOR_ART.md) for the dated survey (Aug 2026) — the composition (envelope + freeze + undo + canaries + trust + approval + certificates in one daemon) is unbuilt; every individual primitive is crowded.

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

### C8. seccomp is a denylist (re-labelled 2026-08-29 — the allowlist claim was false, B6 D4-F10)
**Attack:** Landlock doesn't cover chmod/chown/utime/ioctl; io_uring can bypass; ptrace/process_vm_readv are namespace-escape primitives.
**Without this:** the Landlock ABI gap is a real hole.
**Commitment:** seccomp BPF **denylist, default-ALLOW**. Blocks the metadata-manipulation family (chmod/fchmod/fchmodat/chown/fchown/fchownat/lchown/utime/utimes/utimensat/futimesat — Landlock gap), io_uring (GhostClaw), ptrace, process_vm_readv. A real allowlist is deferred until a harness-scoped probe proves it survivable (B6 A5). The A3 rejection below argued allowlist; the implemented state is denylist and the docs say so truthfully.

### C9. HVs are signed per-machine — DESIGN-ONLY, not implemented (B6 D4-F10)
**Attack:** agent forges HVs to poison fleet radar; or a malicious machine ships bad HVs.
**Without this:** fleet detection is spoofable.
**Commitment:** the daemon signs every HV with its per-machine ed25519 key (key outside any envelope). Fleet sync verifies signatures. Agent cannot sign. **STATUS: HV signing still designed, not built; fleet sync does not exist.** ed25519 code now exists in the workspace (chapter 5, `castellan-proof::signing`) but it signs *certificates*, not HVs. HV integrity currently rests on daemon-write-only storage. Revisit before any fleet sync. See C37 for the certificate-signing decision and its S0-derived scope.

### C10. Bless broker is nonce-gated, rate-limited, biometric for high-risk
**Attack:** agent forges an approval to self-expand its envelope; or socially engineers the human at scale.
**Without this:** expansion is the bypass path.
**Commitment:** nonce comes from the notification UI via dbus (not from the agent's environment). Max 3 expansions per session, cooling-off period. fp-toggle biometric required for egress or config-dir writes. Risk card (quale) shown for every request.

### C12. ProofPassed AND-vs-OR (decided 2026-09-03, V3 antagonism)
**Contradiction found:** trust.md, THREAT_MODEL A5/A6, and proof-carrying.md all say ProofPassed requires BOTH factors (placebo AND daemon test re-run — "two-factor"), but `undo_commit` emits TWO independent `proof_passed` rows: one for the pair-placebo (`evidence` contains "placebo-controlled"), one for Factor A (`evidence` "test suite"). A placebo-only session earns +10 with the same signal name as a test-only session. The cert's STRONG label (placebo AND tests) was the only consumer honoring the AND; the TRUST SCORE never did.
**Decision:** the ledger signal is OR at the row level (each factor earns its own `proof_passed` row — both are real evidence), and the AND lives in the CERTIFICATE quality label (STRONG requires both; MODERATE for one). The two-factor gaming argument (THREAT_MODEL A6) stands only for STRONG certs, not for +10 rows. trust.md and THREAT_MODEL A5/A6 corrected to the row-level OR + cert-level AND framing. The V3 corpus K5 asserts the row-level factor it exercises (placebo, with strength>0 and a matching baseline manifest) and labels Factor A honestly: skipped-unconfigured in the corpus project.
**Alternatives rejected:** (a) single AND-gated row — loses evidence granularity and makes the corpus's placebo-only project earn nothing, which understates the placebo's standalone value against `assert True`-class gaming; (b) two signal names — churns the ledger schema and all consumers for a distinction the evidence_json already carries.

### C14. Trust ceiling-window enforcement + tier-3 proof gate (decided 2026-09-05, A7 fix)
**Found by R3-lite (V3 corpus, dc5b876):** 30 rapid keep-shaped sessions bought tier 2 → 3 (50.0 → 80.0) in minutes. `TIER_CEILING_WINDOW_SECS` (86_400) was declared but unenforced — no timestamp check existed in `apply_weighted`. The per-apply +1-tier cap limited jump SIZE but nothing rate-limited applies.
**Decision (two halves, option b):**
- **C14a — wall-clock window:** score is never clamped (the ledger stays honest about what happened), but the TIER follows upward at most once per `TIER_CEILING_WINDOW_SECS` since the last tier-up (`last_tier_up_ts` column, best-effort migration for pre-C14 databases). Downgrades always land immediately — a canary trip floors the project the same second, never deferred (asymmetric by design: bad news is urgent, good news can wait a day).
- **C14b — tier-3 evidentiary gate:** tier 3 is the first tier that widens the expansion surface beyond the tier-2 default, so entry requires a `proof_passed` row in the project's ledger. Farmed keeps buy score but not the tier; entry lands on the first apply after a proof row exists. Downgrades unaffected. This is the evidentiary complement (option b): the window alone would let a patient farmer buy tier 3 in 2 days of keeps; the gate requires a real fix that differentially drops danger_signal.
**Alternatives rejected:** (a) window-only — bounded only in time, not in evidence; a 2-day drip still farms tier 3 with zero adversarial skill. (b) ledger non-triviality for +1 (empty/trivial commits earn nothing) — worth doing separately, but "non-trivial" is a judgment call the daemon cannot make grammar-free; the proof row is already kernel-witnessed evidence with a fixed schema, so it gates cleanly.
**Verified:** 4 new unit tests (window holds rapid second tier-up; window opens after 24h; farm without proof stays tier 2; farm with proof enters tier 3). R3-lite rerun expected: tier stays 2 after 30 keeps.

### C11. Cold-start fail-closed (option B, decided 2026-08-30)
**Decision:** a project with no trust history (last_event_ts == 0) runs its first session with undo+net forced, regardless of launcher flags; an explicit human `--no-enforce` is still honored (audit mode is a labeled debug opt-out — an informed human decision is not softened by the floor). After one clean keep the project is off cold and tier-2 defaults apply.
**Why:** the pre-B6 posture was an inversion — the least-trusted session (a fresh project's first agent) got the widest write surface (direct writes to the real project, no overlay, no canary lockdown), while a project with earned trust got more confinement. B6 made enforce the default for everyone; this closes the remaining first-session gap: writes land in the discardable overlay from session zero, and the human decides with `keep`/`undo`.
**Alternatives rejected:** (a) keep tier-2 cold permissive — adoption-friendly but preserves the inversion; decided against. (b) cold floor overriding `--no-enforce` too — maximum safety but blocks the labeled debug mode on every new project and broke the p1 audit suite; the explicit human flag is the boundary the floor respects.
**Verified:** cold+default forces undo+net (banner, session record); cold+`--no-enforce` runs audit with undo+net still forced (enforce:false in the record); keep moves 50.0→51.0 and off cold; warm tier-2 launches force nothing. All suites green (p0-p4, p9-stack).

### C37. Certificate signing: memory-only key, S0-derived scope (chapter 5, 2026-09-17)
**Attack:** a same-uid agent forges or edits a ProofCertificate, or edits the spine it is assembled from.
**Probe (S0, docs/s0-key-extraction-probe.md):** `/proc/<daemon>/mem`, `process_vm_readv`, and ptrace are kernel-denied (ptrace_scope=1). Two real vectors: a **disk** key is readable (read roots are `/`), and a plain **memory** key is recoverable from a coredump (`kill -6` wrote a core containing the planted secret). The spine, `sessions/`, and `trust.db` are write-denied to the agent.
**Decision:** (a) never persist the key; (b) generate it in-process at daemon start after `PR_SET_DUMPABLE=0` + `RLIMIT_CORE=0` (verified: `/proc/<daemon>/*` is then root-owned and no core is produced); (c) hash-chain the spine (S1) so post-hoc edits to the anchor are detectable even without the signature; (d) sign certificates over canonical JSON and verify with an optional pinned key.
**Scope (stated in the artifact):** integrity and provenance **within a boot**; not non-repudiation against a same-uid adversary with kernel-level access. A signature does not make the spine independently witnessed — both keys and anchor live on the same machine. This is the honest boundary, not a weakness to hide.
**Alternatives rejected:** (a) persist a key file — readable by the agent, worthless; (b) sign without hardening — coredump-extractable; (c) skip the chain and sign only the cert — leaves the *evidence* (spine) editable while the wrapper verifies, which is security theater.
**Verified:** test/shell.d/ch5-proof.sh 8/8 (hardening, signed verify, edited-cert reject, edited-spine BROKEN, unsigned reported honestly).

### C38. The trust floor gates egress with a second, destination-scoped mechanism (P11, 2026-09-17)
**Gap:** the P6 floor made the trust score control `enforce` and `undo`, and nothing else. A tier-0 project still had unrestricted egress, so the score gated writes but not the network — the highest-value exfil channel was the one dimension trust did not touch.
**The obvious fix is a deadlock, and we had already paid for it.** Forcing `--net` at low tiers looked right and was implemented: Landlock net rules are **port-scoped**, so allowing port 443 for the LLM API also allows 443 exfil, and forcing the rule denies the API itself. A tier-0 project could not run, produced no edits, was auto-reverted, and could never earn trust back — unrecoverable (found live by real-session dogfooding, 2026-09-16, 4 of 12 trials bricked). The fix was to stop forcing it, which left egress ungated.
**Decision:** keep `--net` exactly as it is (Landlock, port-scoped, operator-only, never forced) and add `--net-restrict` (the broker's **IP allowlist**, destination-scoped). The floor forces `net_restrict` at tiers 0-1. Because the allowlist is destination-scoped, the declared LLM host stays reachable and the agent is not bricked, while public TCP, public UDP, and DNS all return EPERM. Cold start forces undo only: absence of trust history is not evidence of misbehavior, and a stranger's first session should not be unable to fetch a dependency.
**The allowlist is operator-owned, deliberately.** Sources in order: `--allow-host`, `CASTELLAN_EGRESS_ALLOW_HOSTS`, `$XDG_CONFIG_HOME/castellan/egress.toml` `[llm] hosts`. The harness's own provider config is **not** a source — it lives in the agent-writable state root, so deriving the allowlist from it would let the agent authorize its own egress. The list is resolved daemon-side at spawn so the enforced policy and the recorded policy cannot diverge.
**DNS needed its own fix, found by the census.** The first restricted run read DNS OPEN: on a systemd-resolved host `/etc/resolv.conf` names the **local stub** `127.0.0.53`, the blanket loopback allowance passed it, and the stub relays to the real upstream — an unmonitored path and a DNS tunnel. The policy now denies the stub's exact (ip, port) pairs while leaving every other loopback port, the canary honeypot included, alone. A denial scoped to a relay, not to loopback as a class.
**A near-miss worth recording.** The first implementation also denied destinations it could not parse *and* implicit destinations. The second would have broken every program that sends anything: glibc implements `send()` as `sendto` with a NULL destination on a connected socket, and TLS stacks use `sendmsg` the same way. Only `connect` carries a fresh destination; sends on an already-connected socket were vetted when it connected. There is a unit test asserting the implicit path stays allowed, because the instinct to fail closed there is wrong.
**Verification:** `test/channels-census.sh` measures both postures; `test/shell.d/p11-tier-egress.sh` 12/12 on 7.0.3; `test/p11-crosskernel.sh` 4/4 on 7.1.8. Measured: public TCP DENIED, public UDP DENIED, DNS DENIED under the floor.
**Honest residuals:** loopback UDP to a local listener; an fd connected before the filter was installed (a kernel property, both Landlock and the broker); and the broker's allow path uses `SECCOMP_USER_NOTIF_FLAG_CONTINUE`, so a racing thread can rewrite a `sockaddr` between our check and the kernel's re-read. The broker is a denial/detection layer for the LLM-agent threat model, not a hard boundary against a malicious multi-threaded actor.

### C39. The egress proxy terminates TLS with a per-session in-memory CA (P12, 2026-09-26)
**Gap:** commitment C4 says real credentials never enter the envelope and the daemon injects them server-side — but no mechanism existed. The envelope could hold only canaries, so a confined agent could not reach any authenticated API at all: safe, unusable.
**Decision (pre-registered, plan `docs/plans/p12-egress-proxy-keyring.md`):** Option A — a localhost CONNECT MITM whose CA is minted per session, key held only in daemon memory under the S0 hardening, cert written to the session scratch and advertised via `SSL_CERT_FILE`-family env. Option B (opaque CONNECT tunnel) was rejected before build: it cannot see inside TLS, therefore cannot inject, therefore cannot satisfy C4 for any real API — dead on arrival.
**Trade, stated:** the agent must trust the session CA, so it can read the CA *cert* (public by nature) and could run its own fake proxy for its own children on another loopback port. That is a documented non-boundary: it gains the agent nothing it lacks already (canaries are agent-readable by design; public TCP stays broker-denied; loopback was always reachable). What matters is the CA *key* never leaves daemon memory — verified K1d (`/proc/<daemon>/mem` is EACCES, S0 boundary holds for this key too).
**Policy is never invented by the proxy.** It enforces the session's resolved `allow_hosts` under `net_restrict` — the same list the broker got (C38's operator-owned sources). Floor sessions with an empty allowlist get 403 on every CONNECT (fail-closed matches the kernel path). Auth headers from the agent are stripped unconditionally, even for unbound hosts, so a canary never travels toward a real host; unbound allowlisted hosts are proxied WITHOUT injection (K6).
**The suite found three certificate-strictness bugs rustls hides:** an empty subject DN requires a critical SAN (python: "Subject empty and Subject Alt Name extension not critical"), leaves need AKI when the issuer has SKI, and CAs need explicit KU keyCertSign. The Rust integration test passed all three because rustls is lenient — only the in-session python client exposed them. Recorded because the asymmetry will recur: our own tests are not a proxy for real clients.
**v0 shape, honestly:** one HTTP exchange per connection (`Connection: close` forced), HTTP/1.1 only, no QUIC, no DNS filtering (C10a residual unchanged), loopback port added to Landlock's port list when `--net` is on (without it the proxy is unreachable under enforce — found before first run).
**Verification:** `test/shell.d/p12-proxy.sh` 25/25 (K1 keyring/no-leak/no-dumpable-read, K2 injection vs stub TLS upstream, K3a/b/c allowlist at all three layers, K4 fail-closed both views, K5 workspace-poison immunity, K6 no-injection, K7/K8 env + per-session CA, K9 spine rows + chain); proxy integration tests 4/4; regressions p0/p1/p4/p9/p11 all green.

### C40. The event spine gets a cross-process flock (P12 side-fix, 2026-09-26)
**Gap:** `EventSink::emit` does tip→append — a read-modify-write — with multiple emitters across processes (daemon audit watcher, launcher broker recorder, and now proxy threads). Two emitters interleave: both read the same tip, both write a `prev` pointing at it, and the S1 chain breaks at the second line. Latent before P12 (emission rarely coincided); caught live when a tunnel session's file writes (audit) raced its egress rows (proxy) — `p12` K9c failed once, passed never again until fixed.
**Decision:** an `flock` on a sibling `*.jsonl.lock` held across the whole read-modify-write in `emit`, released on drop. Cross-process by construction (the launcher recorder is a different process — an in-daemon mutex would not have covered it). Requires nix's `fs` feature (workspace Cargo).
**Verification:** K9c (chain intact under concurrent proxy + audit emission) plus the existing core chain tests (161 workspace tests green).

### C41. Drill fault injection is a compile-time feature, not an env var (2026-09-27)
**Gap:** the P8 suite proves its own value by mutating each defense and checking the matching drill fails (Koch criterion). That was served by `CASTELLAN_TEST_DISABLE_{LANDLOCK,SECCOMP,CENSUS,HONEYPOT,FREEZE,BLESS}` read *inside* the enforcement path of each defense — six places where a defense returned `Ok(())` having done nothing. The justifying comment was "the daemon's env is not agent-set". **That justification does not hold here:** read roots are `/` (documented residual), so a session can read the daemon's `/proc/<pid>/environ`, and the launcher CLI inherits the operator's shell. The failure mode is total and silent: every kernel wall off, the launch still reports `enforced`, and the session reports `rc=0`.
**Measured on .227 (kernel 7.1.8), pre-fix build, with all six vars set:** workspace write `IN_OK`, write outside the envelope `OUT_OK`, escape file materialized, `ptrace` `RC=0 ERRNO=0`. The hole was real and complete.
**Decision:** one chokepoint, `castellan_core::fault_injected(name)`, gated on a `drills` cargo feature that is **off by default**. A release build cannot disable any defense at runtime — the env var name is not compiled in at all, so `strings` finds no trace of it. A drills build announces itself on stderr at the moment of injection ("FAULT INJECTION ACTIVE ... NOT a production build") and on `castellan status`. `test/shell.d/p8-drills.sh` now refuses to run against a non-drills build rather than reporting vacuous passes.
**Verification** (`test/drill-gate-prod.sh`, .227, 16/16): release build ignores all six vars and stays confined — outside write `EACCES`, `ptrace RC=-1 ERRNO=1`, no injection announced, all 5 P8 drills pass; drills build fires each hook and the `envelope` drill correctly reports `write succeeded (envelope broken)`. Three-way check: drills build without injection → drill PASS; drills build with injection → drill FAIL; release build with the same injection → drill PASS.
**Scope, stated honestly:** this closes the *reachability* of the hooks. It does not change the denylist shape (A3 below) and it does not address read-root visibility.

### C42. Per-defense probe ordering when a hook short-circuits `apply_envelope`
**Detail, not a separate decision:** `apply_envelope` returns early when the Landlock hook fires, so a combined `LANDLOCK=1 SECCOMP=1` request never reaches the seccomp hook. That is correct fail-closed ordering, but it means a two-variable injection probe silently tests one hook and appears to fail the other. The gate probes one defense per launch. Recorded because the first version of the gate reported five spurious failures from this, and a future reader would otherwise re-derive it.

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
