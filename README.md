# castellan

**The OS is the trust boundary for AI agents.**

Castellan is a Linux-native agent safety system that confines, observes, and proves what AI coding agents do on your machine — at the kernel level, where prompt injection cannot reach. It runs on any systemd + Landlock Linux. MIT licensed.

> **The boundary is the launch path, not the process.** Castellan confines the agents *it launches*. A harness you start any other way — a plain `claude` in a terminal, a cron job, a second agent — runs completely unconfined, and no castellan command will ever see it. `castellan siblings` reports such processes so you can notice; it cannot stop them. It also confines **writes**: a confined agent can still *read* `~/.ssh`, `/proc/self/mem`, other sessions' state and the credential keyring file, because it must be able to read your repo and toolchain. The signing key is the exception — it is memory-only and the daemon is non-dumpable, so no same-uid process has a path to it. Full reasoning and the measured limits: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) ("Read this first").

> **Status: working.** Built and acceptance-tested on Linux 7.x / Landlock ABI 8–9: session substrate + freeze (P0), the envelope floor with audit + enforce launch, now the default (P1/B6), surgical undo + canary credentials (P2), earned autonomy (trust engine + placebo-proof pipeline + bless-broker, P3), proof-carrying sessions with hash-chained spines and ed25519 signing (P4/chapter 5), trust→envelope coupling and the fail-closed floor (P6), the frontier-round socket identity + timer sweep (B7), the seccomp egress broker (B8), the destination-scoped egress floor (P11), and the credential-injecting egress proxy + daemon keyring (P12) — real credentials reach allowlisted hosts without ever entering the envelope. **Demoted honestly:** HV radar shipped then was demoted to advisory-forever by its own kill criterion (47% FP on the scripted corpus, 70% on real sessions); the seq-engine port was killed before building (probe). **Not built:** HV fleet sync, mid-session expansion restart, Merkle transparency log. Every claim below is scoped accordingly; see [docs/ROADMAP.md](docs/ROADMAP.md) for phase status, [docs/PRIOR_ART.md](docs/PRIOR_ART.md) for what already exists elsewhere, and [docs/benchmark-methodology.md](docs/benchmark-methodology.md) for how claims get earned.

## The problem in one sentence

AI agents now run unattended on personal machines with broad filesystem and network access, and every safety tool today lives *inside the agent* — which is exactly the part prompt injection hijacks.

## The pitch in plain English

A distro owns the one layer where a single policy applies to every brand of agent identically: the OS itself. Harness vendors can only confine their own agent; agent-safety tools can't confine anyone else's either. Castellan makes the kernel the trust boundary so the agent cannot argue with it, bypass it, or be tricked out of it.

## What it does

Ten pieces ship today. Three more are designed and named below but not built — the two lists are separated for that reason.

**Shipped (10):**

1. **Kernel walls** — `castellan launch -- claude ...` confines the session via Landlock + seccomp before any agent code runs: writes limited to project + harness state + scratch, hard-deny for `~/.ssh`, systemd units, autostart, shell rcs, `/etc` `/usr` `/boot`; ptrace/process_vm/io_uring/module syscalls return EPERM. Verified: workspace work (git included) runs clean under enforce; home-dir escapes get EACCES.
2. **Panic button** — every launched or adopted session lives in its own cgroup scope. `castellan freeze` stops all sessions at once: zero CPU, no userspace execution until thaw. (Kernel 7.x note: SIGKILL still kills frozen processes — freeze stops computation, it does not shield against external kill.)
3. **Security camera** — with `--no-enforce` a session runs unrestricted while every file write is classified into `events.jsonl` as allowed or would-deny (`castellan audit <session>`); that posture installs no egress broker at all, so its "observation only, no containment" banner is literally true. Harness-state folders are fingerprinted at spawn and diffed at exit, so a poisoned skill or hook gets flagged. This is the opt-out debugging posture, and it also produces the false-block-rate data. **The default is enforced**, not audit.
4. **Surgical undo** — per-session rollback via overlayfs upper layer (`castellan launch --undo`), so one bad agent doesn't force a whole-disk rollback. `castellan diff/undo/keep` shows, discards, or commits the session's changes.
5. **Canary credentials** — fake credentials planted in the envelope, wired to a localhost honeypot. Using a canary IS the trigger: trip → event logged + session frozen. Egress lockdown (Landlock ABI 4 net rules) denies all TCP connect except the honeypot port.
6. **Earned autonomy** — per-project trust score (EWMA, tiers 0–4) fed by kernel-witnessed signals: placebo-controlled proof (+10, the only positive signal), clean session (+1), user revert (−30), envelope escape (−20), canary hit (−50). The trust tier is consulted at spawn: tiers 0–1 run fail-closed (enforce + undo + **egress restriction** forced, launcher flags ignored — the agent cannot self-widen), tiers 2+ run with the launcher's flags. Bless-broker approves record daemon-side one-shot grants (in-memory, never on disk where the agent could forge them) that override the floor for one expansion — including an `egress` grant. The floor's egress policy is destination-scoped, so a low-trust agent can still reach its LLM API: measured on two kernels, public TCP, public UDP, and DNS all return EPERM under the floor, while loopback (the canary honeypot) stays reachable.
7. **Proof-carrying sessions** — `castellan cert <session>` assembles a ProofCertificate from kernel-witnessed state: bounds proof (event spine), placebo + test evidence (trust ledger, session-scoped), the spine hash-chain verdict, and an ed25519 signature when the daemon has a key. Quality labels STRONG/MODERATE/WEAK/NON-EVIDENTIAL. `castellan verify <cert.json>` re-checks the signature and chain. Kill-criterion benchmarks pass: 0/20 known-bad FN, 0/20 known-good FN, monotonic tier↔revert (ρ=0.900 on a signal-simulated corpus; K1 holds on real sessions). **Signature scope, stated in the artifact:** integrity/provenance within a boot, not non-repudiation against a same-uid adversary (see docs/s0-key-extraction-probe.md).
8. **Forensic replay** — `castellan replay <session> <narrower-project>` re-classifies the recorded event spine against an alternate envelope (static re-classification, never re-execution) and reports the permissive-case delta: writes the original envelope allowed that a narrower one would deny.
9. **Egress broker** — `castellan launch --net-restrict` installs a seccomp user-notification broker that denies public TCP/UDP to an IP allowlist (public connect → EPERM) and denies the systemd private socket and session bus, closing the `systemd-run` escape route. Loopback and non-manager unix sockets stay allowed. Two distinct mechanisms: `--net` is Landlock's port-scoped rule (operator-only; never forced by the trust floor, because it cannot tell the LLM API from any other 443 host), `--net-restrict` is this destination-scoped one (which the floor can force safely). The DNS case needed its own fix: on a systemd-resolved host the resolver is the local stub `127.0.0.53`, which relays upstream, so the stub is denied by exact (ip, port) pair. Detection/denial for the LLM-agent threat model, not a racing-thread boundary (TOCTOU documented).
10. **Egress proxy + credential keyring** (P12) — every session gets a localhost MITM proxy with a per-session CA (key in daemon memory only); the agent holds only canaries while the proxy strips whatever auth it supplied and injects the real credential from the daemon keyring for host-bound entries. Same resolved allowlist the broker enforces (proxy and kernel cannot disagree); `egress_inject`/`egress_deny` spine rows; `castellan proxy off` fails closed both ways (session observes ECONNREFUSED, direct egress stays EPERM). Empty keyring degrades honestly to B8 + canaries. Acceptance: `test/shell.d/p12-proxy.sh` 25/25; decision record C39/C40.

**Designed, not built (3):**

11. **HV fleet sync** — ed25519-signed cross-machine prototype exchange (local outlier detection shipped, then demoted to advisory by its kill criterion; see `castellan radar`).
12. **Mid-session expansion restart** — a bless approval currently grants the *next* launch; re-minting the envelope of a *live* session is designed, not built, because Landlock cannot be loosened mid-session.
13. **Merkle transparency log** — the spine chain + per-cert signature are built; cross-machine append-only signed tree heads are not.

## Independent e2e verification

Inherited from the poc-ten release, where castellan was first built. Kept here because it
was written by someone outside the project, against a build they did not write.

A model-written ETL script with planted escapes (read `~/.ssh/id_ed25519`,
write `~/.config/pwned`, read `/proc/self/mem`) run under
`castellan launch --` on kernel 7.0.3: home write → PermissionError;
session writes invisible to the real project (overlayfs upper layer);
`diff` lists both planted artifacts. Read-escapes (`~/.ssh` read,
`/proc/self/mem` read) are **in-scope residuals** (P2 egress/net scope) —
the narrow-jail product claim is write-containment + undo + canaries
only, not read or egress blocking.

## Install

Requires: systemd with a user session, cgroup v2, Linux 7.0+ (Landlock ABI 4+). Verified
kernels: 7.0.3 and 7.1.8 (x86_64). `preflight` runs 6 checks — all 6 must pass.

From the [v0.1.0 release](https://github.com/Reliary/castellan/releases/tag/v0.1.0) (MIT).
That tag ships **only the CLI** (`castellan`); the daemon binary is not in it — build from
source below for a working daemon until the next tag, which bundles both.

```sh
chmod +x castellan
./castellan preflight                  # all 6 checks must pass
```

Or from source (builds both binaries):

```sh
cargo build --release --workspace
./target/release/castellan preflight
./target/release/castellan service install   # user service; daemon runs durable + fail-closed
```

Then see Quickstart below.

## Quickstart

```sh
cargo build --release --workspace          # or download the release binaries
castellan preflight                        # check your kernel: all 6 checks must pass
castellan service install                  # install + start the user service (durable daemon)
castellan init                             # scaffold keyring.toml + egress.toml (edit, then restart)
castellan launch -- claude                 # enforced by default: workspace-only writes
castellan status                           # see the session
castellan freeze && castellan thaw         # the panic button
castellan launch --undo -- claude          # every write lands in a discardable overlay
castellan launch --net-restrict -- claude   # egress denied to an IP allowlist (LLM host declared)
castellan diff <session>                    # what did it change?
castellan keep <session>                   # commit it, or `undo` to throw it away
castellan cert <session>                   # signed ProofCertificate (bounds, placebo, chain)
castellan verify cert.json                 # re-check the signature + spine chain
castellan gc --keep-last 20                # prune old session state (none before this)
castellan uninstall --yes                   # remove service, sessions, state and keyring
```

`--harness` is auto-detected from the command (claude, codex, pi, opencode, aider, cursor-agent, gemini, crush); unknown harnesses still get the envelope, just no harness-state protection. `--no-enforce` opts out loudly (audit mode) — for debugging only.

## What we bring

No moat, no secrecy: everything here is buildable by anyone willing to write the kernel plumbing — Landlock and cgroups are documented Linux features, and nothing in this repo is protected. The individual primitives are all crowded (the dated survey covers Codex/Claude/Gemini sandboxes, AWS graduated autonomy, Thinkst canaries, overlayfs undo tools). The prior-art survey in [docs/PRIOR_ART.md](docs/PRIOR_ART.md) is an **August 2026** snapshot and has not been re-surveyed since; treat it as dated. What that survey found unbuilt was the **composition** — one OS-owned daemon applying envelope + freeze + undo + canaries + trust + approval + certificates across all harnesses simultaneously — plus the **placebo-controlled proof** as the only positive trust signal, and the **desktop-native unprivileged** form factor. What we have is momentum and inventory: the observation/proof layers are accelerated by internal primitives already built and benchmarked elsewhere in our repos (grammar-free fingerprinting, deterministic replay, placebo-controlled eval methodology, HDC memory) — see [docs/PRIMITIVES.md](docs/PRIMITIVES.md) for the full list with honest verdicts, including which ones died in testing. The kernel-enforcement layer contains zero borrowed magic; it is plain documented syscall work that anyone can replicate.

## Repo layout

```
README.md                      this
AGENTS.md                      conventions for AI agents working on castellan
Cargo.toml                     workspace: castellan-core, -policy, -freezer,
                               -envelope, -daemon, -cli, -keyring, -proxy
crates/
  castellan-core               session types, protocol, event spine (flocked)
  castellan-policy             envelope classification (pure, unit-tested)
  castellan-freezer            cgroup v2 freeze/thaw/kill
  castellan-envelope           Landlock ruleset, seccomp BPF, audit watcher
  castellan-keyring            daemon-resident credentials (P12)
  castellan-proxy              per-session credential-injecting proxy (P12)
  castellan-daemon             unix-socket server, session registry, proxy lifecycle
  castellan-cli                castellan status|launch|audit|freeze|thaw|kill|proxy|...
test/shell.d/                  acceptance suites (run on a real desktop Linux;
                               need user cgroup slices — not CI-runnable)
docs/
  ARCHITECTURE.md              4 planes, substrate, event spine, 10 commitments
  THREAT_MODEL.md              Threat A/B/C, mitigations, residual risks
  ROADMAP.md                   P0-P5 with kill criteria and phase status
  PRIMITIVES.md                internal primitive inventory with real-data verdicts
  DESIGN_DECISIONS.md          antagonism record: what died, what hardened, why
  CRATES.md                    Rust workspace layout
  ATTACK_EXERCISE.md           five rounds of live self-attack: every escape found,
                               every battery that found nothing, and what was fixed
  PRIOR_ART.md                 dated prior-art survey (Aug 2026; not re-surveyed)
  s0-key-extraction-probe.md   what it takes to reach the signing key from a
                               same-uid process, and why memory-only wins
  upstream-strategy.md         internal: where this could be upstreamed
  benchmark-methodology.md     cert-evals interleaved + placebo + SHA-256 cert
  glossary.md                  terms
  components/                  per-component design docs with status
  plans/                       frozen build plans with pre-registered kill criteria
```

## License

MIT. See [LICENSE](LICENSE).

## Security

Found a bypass? Use private vulnerability reporting (**Security → Report a vulnerability**)
rather than a public issue — see [SECURITY.md](SECURITY.md). Start with its first section:
confinement is conditional on the agent being launched through castellan, and processes
you did not launch are unconfined.
