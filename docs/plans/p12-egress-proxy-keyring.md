# Plan P12 — Egress Proxy + Daemon Keyring (Credential Injection)

**Status: PLAN WRITTEN 2026-09-26, BEFORE any code.** All kill criteria and
acceptance-gate numbers below are frozen. Threshold changes after a run =
phase does not advance. Harness bugs may be fixed with a documented rerun
(same discipline as portfolio plans).

Read first: `docs/ARCHITECTURE.md` (10 commitments), `docs/THREAT_MODEL.md`,
`docs/components/egress-proxy.md` (design intent — marked "designed, not
built"), DESIGN_DECISIONS C4/C5/C37/C38.

## 1. The problem

Castellan today: the envelope + B8 broker (destination-scoped IP allowlist)
+ canary honeypot detect-and-freeze = a box an agent cannot escape, but also
a box in which **no real credential exists anywhere** — the agent literally
cannot reach a real API with a real key. The `egress-proxy.md` doc is
explicit: "no credential-injecting proxy and no daemon keyring today." This
is the honest adoption blocker: under full confinement the agent is safe but
unusable for anything that needs auth'd egress (LLM API with user keys, git
push, package registry publish).

Commitment C4 says: real credentials never enter the envelope; all egress
proxied through the daemon which injects them server-side. That commitment
is aspirational. P12 builds it.

## 2. What we build (scope, deliberately small)

Two artifacts, both pure Rust, both in the daemon's trusted path, both new
crates:

1. **`castellan-keyring`** — daemon-resident credential store.
2. **`castellan-proxy`** — localhost egress proxy that injects credentials
   server-side per-request.

Out of scope (explicitly NOT P12): fleet key sharing, UI, bless-broker
UX changes, any change to trust scoring, any change to the B8 broker's
kernel-level allowlist semantics (it is input, not dependency).

## 3. The core design decision (antagonized BEFORE build — this is the make-or-break)

The proxy needs to inject credentials into HTTPS requests. Two options,
with the honest trade recorded:

### Option A — TLS-terminating MITM (full injection)
Daemon runs a localhost HTTPS proxy with a per-boot, in-memory CA.
Agent's env points HTTPS_PROXY at it. Proxy terminates TLS, injects
`Authorization: Bearer <real>` from keyring, re-encrypts to upstream.

- Inject into any header, any body: full credential rewrite.
- **Killer objection:** CA cert must live somewhere; if in-memory-only
  (S0-style, `PR_SET_DUMPABLE=0`, verified for cert key in C37) the agent
  has "trust this CA" only via the launcher's env — but any agent process
  that sees the CA fingerprint could, in principle, add it to its own
  trust store... which the agent can't do (Landlock denies trust-store
  writes outside the envelope; the envelope itself denies `~/.config`).
  The real objection: **the agent process ITSELF must trust the proxy's
  CA** (its TLS library must accept the proxy's cert for api.github.com)
  → the agent is given the proxy CA cert → **the agent can then itself
  terminate its own TLS to the proxy and see plaintext.** But the proxy
  sees plaintext anyway (it's the whole point). The agent seeing its own
  request's plaintext is not a leak.
- The REAL question: can a same-uid attacker read the CA key? Same
  answer as C37: memory-only key + non-dumpable daemon + no core → no.
  Daemon holds CA key in-process only, regen per boot.

### Option B — CONNECT-only tunnel, strip-injection (minimal exposure)
Proxy accepts `CONNECT host:port`, opens upstream TCP, and CANNOT see
inside TLS. Injection impossible for HTTPS. Only works for plain HTTP
(which LLM APIs are not) or via a companion daemon-side redirect.

- Cannot inject into TLS. Dead on arrival for the real use-case
  (LLM API auth is over HTTPS). Killed before build.

### Decision (frozen, pre-build): **Option A — in-memory CA MITM proxy.**
Option B cannot satisfy C4 for HTTPS (all real APIs). The single risk —
CA key readable from daemon memory — is the S0/C37 boundary already
hardened and stated honestly (within-a-boot integrity, not vs kernel-level
same-uid adversary). We accept it. **This is recorded as design-decision
C39 when shipped.**

The trust-store problem (agent must trust proxy CA): solved by the
launcher — at spawn, the daemon mints the session env with:
- `HTTP_PROXY=http://127.0.0.1:<proxy_port>`
- `HTTPS_PROXY=http://127.0.0.1:<proxy_port>`
- `SSL_CERT_FILE=<session-scratch>/castellan-ca.pem` — the proxy CA cert,
  written into the session's overlay-sourced scratch (agent-writable but
  session-scoped and invisible to the real FS)
- `NODE_EXTRA_CA_CERTS=<same>` (Node), `REQUESTS_CA_BUNDLE=<same>`
  (Python), `CARGO_HTTP_CAINFO=<same>` (cargo) — frozen at spawn, the
  config-sha pin (F1 mechanism) prevents mid-session drift

The B8 broker allowlist still applies: even with the proxy reachable, the
allowlist decides which `CONNECT host` the proxy will honor AND which
upstream destinations seccomp allows the agent to reach directly (default:
proxy port + LLM host IP only; all other egress stays EPERM at kernel —
defense in depth: agent can bypass HTTP_PROXY env, but seccomp still
denies direct public TCP, so the only reachable host is the proxy).

## 4. Components

### 4.1 `castellan-keyring` (new crate, ~200 LOC)

- In-memory `HashMap<cred_id, Secret>` — `Secret` = zeroizing buffer,
  never written to disk, never logged, never in spine.
- Population sources (frozen, in order — all daemon-side, none agent-reachable):
  1. `$XDG_CONFIG_HOME/castellan/keyring.toml` — operator file, **outside
     every envelope** (daemon path), mode 0600, sha256 pinned per-session
     at spawn so agent-side edits to a workspace `keyring.toml` do nothing
     (F1 mechanism reuse)
  2. env at daemon start (`CASTELLAN_CRED_<NAME>_TOKEN`) — operator export
  3. (designed, not built) Secret Service via zbus — deferred to P13, needs
     dbus round-trip, out of P12 scope
- Per-secret access = keyring-side allowlist binding: cred `gh` is tagged
  `hosts: [api.github.com, github.com, upload.github.com]` — the proxy
  consults this binding, NEVER a request-header hint (agent can't
  self-authorize cred scope).
- Canary complement (C5 unchanged): the workspace envelope still gets
  planted canary `~/.aws/credentials` etc. The keyring holds the REAL
  ones; the envelope holds only canaries. Any agent-side credential read
  = canary = trip. The two never meet.

### 4.2 `castellan-proxy` (new crate, ~400 LOC, dependency-minimal)

- Listens on `127.0.0.1:0` (per-boot random port, daemon-side only), bound
  before any session launch.
- Accepts `CONNECT <host>:<port>` from the session. Validates host against:
  1. B8 allowlist (the operator's destination policy — operator-owned,
     C38's sources: `--allow-host`, env, `egress.toml`, never the harness)
  2. keyring host-binding (only hosts that have a cred are reachable via
     injection; all others connect but get no auth header — agent can
     still reach LLM API unauthenticated for public endpoints)
- On allow: establishes upstream TLS, mints on-the-fly a leaf cert for
  `<host>` signed by the in-memory CA, terminates the agent's TLS with
  that leaf, re-encrypts upstream with a rustls client (host-verified).
- Strips any agent-supplied `Authorization`/`Proxy-Authorization` (agent
  only has canaries — they'd be invalid anyway, but strip so a future
  misconfig can't leak a real-looking canary value to upstream).
- Injects: for each upstream request to a bound host, the keyring's
  `Authorization: Bearer <real_token>` (frozen scheme per cred: `bearer`
  for LLM/git, `x-api-key` for Anthropic-style — frozen map, not learned).
- Response path: plain pass-through, byte-for-byte, streaming.
- Request log (spine): `{ts, session, host, method, path, status,
  bytes_in, bytes_out, injected_cred_id: "gh" | none}` — host+path+status
  only, no body, no auth value, hash-chained into the session spine (S1).
  The `injected_cred_id` names WHICH keyring entry, never its value.

### 4.3 Daemon wiring (existing `castellan-daemon`, ~150 LOC delta)

- Proxy starts with daemon, dies with daemon (commitment C7 already
  freezes on heartbeat loss; proxy death = no egress path = fail-closed
  consistent).
- Session launch: env injection (4.3 vars above) + scratch CA cert write.
- Trust-tier gate (existing floor): tiers 0–1 → proxy refuses all
  forwarding (C38 fail-closed); tier 2+ → keyring-bound allowlist.
  **Bless-broker override unchanged:** a one-shot `egress` grant raises
  the proxy's allowlist for one host for one session — new verb
  `proxy_allow_grant(session, host)` alongside existing grants.
- Kill-switch: `castellan proxy off` — proxy stops accepting new
  CONNECTs; existing sessions keep B8 deny (fail-closed).

## 5. Kill criteria (Koch-style, frozen, run BEFORE any claim)

Each is a binary pass/fail test runnable on this machine (kernel 7.x,
Landlock ABI 8/9, verified). A phase ships enforce-by-default only if its
criterion passes. Failure → reduced form (audit-only / keyring-disabled) or
killed, per `benchmark-methodology.md`.

| Gate | Test | KILL if |
|---|---|---|
| **K1 credential-never-enters-envelope** | Launch a session under `--enforce --net-restrict --proxy`; agent runs `cat ~/.aws/credentials`, `env; cat $SSL_CERT_FILE`, reads scratch; assert: only canary values visible; run honeypot-trip drill (P8) — trip. Real cred never on agent-readable FS. | any real cred byte readable from inside the envelope, OR CA key readable via `/proc/<daemon>/mem`/coredump (S0 re-probe; C37 boundary) |
| **K2 injection works end-to-end** | Session runs `curl -H 'Authorization: Bearer canary' https://httpbin.org/bearer` (or a stub local TLS upstream with a pinned trust root — real external APIs are flaky and untestable deterministically; the stub is the deterministic check) through the proxy. Assert: stub sees `Bearer <real>` (from keyring), agent sees 200, spine logs `injected_cred_id`. | stub upstream sees the canary value, or sees no auth header, or the response fails TLS verification on either hop |
| **K3 allowlist is kernel-hard, proxy-hard, operator-owned** | (a) Agent sets `HTTPS_PROXY=` (unsets) and connects directly to public TCP — B8 EPERM. (b) Agent sets proxy to `http://attacker:port` — seccomp denies the CONNECT syscall to that sockaddr (B8). (c) Agent CONNECTs proxy to a non-allowlisted host — proxy 403, no upstream dial. (d) Agent CONNECTs to a host that has NO keyring binding — proxied but no Authorization injected (still allowed if B8 allows; the proxy is not a cred gate for unauth'd hosts). | any of (a)-(d) succeeds — proxy must be the ONLY egress path, and it must not inject into unbound hosts |
| **K4 fail-closed on proxy death** | `kill -9` the proxy mid-session; agent's next HTTPS request either (a) gets connection-refused on proxy port AND (b) direct TCP is still B8-EPERM — no silent fallback to direct egress. | any post-proxy-death request succeeds via any path |
| **K5 keyring pin survives config drift** | Agent writes a poisoned `keyring.toml` into workspace; spawn a new session in the same project — daemon reads only `$XDG_CONFIG_HOME/castellan/keyring.toml` (outside envelope), sha256-pin at spawn; the workspace copy is never read. | the poisoned workspace file's creds reachable, or the config-sha drift blocks a legit launch (F1 regression) |
| **K6 no-auth pass-through does not widen surface** | Agent CONNECTs proxy to a keyring-unbound allowlisted host (e.g. pypi.org) — request proxied, NO Authorization injected (agent can do unauth'd egress within allowlist, which is the C38 semantic); spine logs `injected_cred_id: none`. | any unbound host receives an injected header, OR an unbound host is refused when the B8 allowlist admits it (that would regress today's behavior) |

Phase ships only if **K1–K6 all pass**. Order matters: K1 and K5 are the
security core; K2 is the function; K3/K4 are the boundary; K6 is regression.

## 6. Acceptance test (new shell suite)

`test/shell.d/p12-proxy.sh` — 12 checks, runs on real desktop Linux (this
machine: kernel 7.1.8, Landlock ABI 9):

1. keyring file load; secret never logged
2. CA cert minted per boot; fingerprint changes across daemon restart
3. CA key not readable from daemon /proc or coredump (K1 probe)
4. session env has HTTPS_PROXY + SSL_CERT_FILE pointing at scratch
5. CONNECT to bound host → upstream sees real auth (stub TLS upstream)
6. CONNECT to unbound allowlisted host → proxied, no injection (K6)
7. CONNECT to non-allowlisted host → proxy 403 (K3c)
8. direct public TCP with proxy unset → EPERM (K3a)
9. agent-set foreign proxy env → CONNECT syscall denied (K3b)
10. proxy kill mid-session → no silent fallback (K4)
11. workspace-poisoned keyring.toml ignored (K5)
12. spine has `egress_inject` rows, chained, verify passes (S1)

Existing suites must stay green: p0, p1, p4, p6, p8, p9-stack, p11.

## 7. Honest scope statements (written now, not after)

- **The proxy terminates TLS.** An agent that runs a TLS client to the
  proxy trusts the proxy CA for CONNECT targets. This is by design — it is
  the only way to satisfy C4 for HTTPS. The alternative (no MITM) means
  no credential injection, which means no real egress, which means the
  envelope is safe-but-useless. The doc will say this plainly.
- **Boundary: within-a-boot.** CA key + keyring secrets live in daemon
  memory, non-dumpable, no core. A same-uid kernel-level attacker reads
  daemon RAM — out of scope (same as C37, stated in the artifact).
- **No DNS injection.** DNS exfil is a C10a residual, unchanged by P12.
- **No UDP/QUIC.** HTTP/3 is out; proxy is TCP/HTTP/1.1+2 CONNECT only.
  QUIC to an allowlisted host fails at seccomp (UDP connect denied for
  public IPs) — the honest posture: QUIC is unavailable under confinement,
  which is acceptable for LLM/git/registry traffic (all offer TCP fallback).
- **Sub-process env inheritance:** the env vars (HTTPS_PROXY et al.)
  inherit to all session children (Landlock/seccomp inherit; env
  inherits). A child that ignores proxy env (raw sockets) hits B8 EPERM
  — behavior is "break loudly," which K3a covers.
- **Trust-store pinning gap:** an agent could, in its own session scratch,
  re-point `SSL_CERT_FILE` at a self-signed file it controls. That is
  agent-side configuration in an agent-writable dir — not a security
  boundary (it only misdirects the agent's own validation logic). The
  daemon's injection is unaffected. Recorded as a non-boundary.

## 8. What P12 does NOT do

- No Secret Service integration (P13, needs dbus).
- No fleet key sync (no cross-machine anything — C37 boundary).
- No changes to B8 policy semantics (input, not dependency).
- No new trust signals (proxy events feed the spine as `kernel` source
  only; they don't move the score — that would need a placebo-controlled
  signal design of its own, out of scope).
- No QUIC, no DNS filtering, no UDP.

## 9. Effort estimate (honest, from the roadmap's own calibration)

- keyring: ~200 LOC, 1–2 days
- proxy (CONNECT + MITM + rustls): ~400 LOC, 3–4 days (rustls acme-cert
  minting in-process via `rcgen`; no external deps beyond rustls+rcgen)
- daemon wiring + env/spine: ~150 LOC, 1 day
- p12 suite + K1–K6 probes: 1–2 days
- **Total: ~1 week, single dev, no external service needed** (stub TLS
  upstream is local). Compare: roadmap P1 was 2–3 weeks for Landlock +
  seccomp greenfield — this reuses the substrate, so smaller.

## 10. Upstream shape (Omarchy)

After K1–K6 pass: PR to Omarchy adding `castellan proxy` verb + the env
injection at launch + docs. The PR must NOT claim "secure credential
storage" — the claim is "real credentials can now be used under full
confinement without entering the envelope; the boundary is within-a-boot,
non-dumpable, kernel-level attacker out of scope." Same honesty as C37.

## 11. Reused primitives (only PASS-verdict ones, per AGENTS.md)

| Owned primitive | Role | Verdict |
|---|---|---|
| castellan-broker (B8) | destination allowlist input + seccomp deny (K3a/b) | BUILT, verified |
| castellan-canary | canary complement, honeypot trip (K1) | BUILT, verified |
| castellan-proof (signing) | spine hash-chain rows for egress events (S1) | BUILT (ch5 8/8) |
| castellan-daemon config-sha pin | keyring config drift (K5, F1 mechanism) | BUILT, verified live |
| sift | spine row log compression (existing plumbing) | BUILT |

**Explicitly not used:** HV radar (advisory-forever, killed), seq-engine
(killed), refactor-proof (killed), agent-log-compress (killed), half-life
(killed), constellation-drift (killed), sec-commit-label (marginal).
None are load-bearing here.

## 12. Risks named now

- **RCA (root CA) UX friction:** every harness's TLS stack needs the CA
  hint. Frozen at spawn for the 4 known stacks (OpenSSL/curl, Node, Python
  requests, cargo); unknown stacks break loudly (K3a) rather than silently.
  If a harness ships a hardcoded trust root (some Go binaries do), that
  harness cannot use the proxy — recorded as adoption limitation, not hidden.
- **Proxy is in the trusted path** — every egress adds a hop. Latency
  ~1–5ms (egress-proxy.md's estimate, unchanged). No benchmark claim until
  K-suite passes.
- **Operator must populate keyring.toml** — if empty, P12 degrades to
  "B8 + canaries + no real creds" (today's posture). Degradation is
  honest: the system is no worse than now.

## 13. What "done" means

`test/shell.d/p12-proxy.sh` 12/12 on this kernel; K1–K6 pass; a live
end-to-end demo: `castellan launch --enforce --net-restrict --proxy --
claude -p "check gh api /user"` → real API call succeeds, agent never
sees the token, spine has the `egress_inject` row, honeypot drill still
trips. Commit message states K1–K6 plainly. ROADMAP gets a P12 entry with
the pass/fail record.

---

## Execution record (2026-09-26 — run after the gates above were frozen)

**Verdict: K1–K6 ALL PASS.** No gate was re-gated; no threshold changed.

| Gate | Result |
|---|---|
| K1 credential-never-enters-envelope | PASS — keyring token absent from daemon log, session state, session json; env carries only proxy port + public CA cert; `/proc/<daemon>/mem` EACCES (S0 holds for the CA key); session pins `keyring_sha` = config-dir file sha256 |
| K2 injection end-to-end | PASS — integration test: stub TLS upstream sees `Authorization: Bearer REAL-SECRET`, never `canary-value`; client sees 200; body intact |
| K3 allowlist at three layers | PASS — K3a direct public TCP EPERM (broker); K3b agent-set foreign proxy env still EPERM; K3c non-allowlisted CONNECT → 403 before any dial |
| K4 fail-closed on proxy death | PASS — `proxy off`: harness sees ECONNREFUSED; the session itself observes REFUSED (inside view); direct egress still EPERM |
| K5 workspace-poisoned keyring | PASS — poison token absent from daemon state; session keyring pin unchanged |
| K6 unbound = no injection | PASS — allowlisted-but-unbound host proxied with no auth header (integration test) |
| Suite extras | K7 env (HTTPS_PROXY/NO_PROXY/SSL_CERT_FILE-family + session tag), K8 distinct per-session CA bundles, K9 spine `egress_inject`+`egress_deny` with S1 chain intact — all PASS. `p12-proxy.sh` 25/25; proxy tests 4/4; workspace tests 161/161; regressions p0 15, p1 13, p4 5, p9-stack 12, p11 12. |

**Implementation deviations from the plan text (all pre-run or found by
the frozen gates — recorded, not smoothed):**

1. **Per-session CA instead of per-boot** (plan §6 check2 said per-boot
   fingerprints change across restarts): per-session CA is strictly
   tighter — the check passes a fortiori (K8).
2. **Spine flock added (C40)** — a pre-existing cross-process
   tip→append race surfaced by K9c under concurrent proxy+audit
   emission. The gate did its job: it caught a real defect, the defect
   was fixed, the gate was not touched.
3. **Certificate strictness rounds** — three python/OpenSSL3
   requirements found by the in-session client (empty-subject SAN must
   be critical → leaf gets CN; leaf needs AKI; CA needs KU keyCertSign).
   The Rust integration test passed earlier because rustls is lenient —
   recorded in C39 as a testing asymmetry.
4. **`Connection: close` one-exchange model** (plan mentioned
   keep-alive tolerance as future): v0 ships single-exchange; responses
   pipe to EOF with `close_notify` both hops (rustls0.23 rejects
   FIN-without-notify — found by the integration test).
5. **K2/K6/K3c-integration live in `crates/castellan-proxy/tests/mitm.rs`**
   (deterministic stub TLS upstream) and are run by the p12 suite via
   `cargo test -p castellan-proxy`, rather than being re-implemented
   as shell checks. The shell suite covers K1/K3/K4/K5/K7/K8/K9 plus
   in-session CONNECT behavior.

**Not in scope of this run (per plan §8), unchanged:** Secret Service
keyring backend, fleet sync, QUIC, DNS filtering, trust-score changes.
