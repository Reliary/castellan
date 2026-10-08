# Egress proxy (BUILT, P12, 2026-09-26)

**Status: built and acceptance-tested.** `castellan-keyring` +
`castellan-proxy` crates ship in the workspace; the daemon starts a
per-session proxy at spawn, the launcher points the session at it, and
real credentials are injected server-side. Gates K1–K6 +
`test/shell.d/p12-proxy.sh` (25/25) and the proxy integration tests
(4/4, stub TLS upstream) pass on kernel 7.x. The pre-registered plan and
its execution record live in `docs/plans/p12-egress-proxy-keyring.md`.

**Historical correction (2026-09-17):** an earlier version of this doc
claimed the envelope's network capability is "loopback only" via
Landlock ABI v4 TCP rules. That is **false**: Landlock net rules are
**port-scoped, not address-scoped** (C10a), so "loopback only" cannot be
expressed. The built mechanism for destination scoping is the B8 broker
with an IP allowlist; the proxy enforces the same resolved allowlist
daemon-side.

## What shipped

- **`castellan-keyring`** — daemon-resident credential store, loaded
  ONCE at daemon start from `$XDG_CONFIG_HOME/castellan/keyring.toml`
  (outside every envelope; the agent's project paths are never
  consulted, K5). Secrets are zeroized on drop, never logged, never
  written to state. Each credential binds to host patterns
  (`exact` or `*.suffix`); the proxy consults this binding, never a
  request-header hint. The config file's sha256 is pinned into the
  session record at spawn (F1 mechanism reuse).
- **`castellan-proxy`** — per-session `127.0.0.1:<random>` listener.
  CONNECT-only HTTP/1.1 MITM: a per-session CA (key in daemon memory
  only, cert in the session scratch) mints a leaf per target host;
  rustls terminates the agent's TLS and re-encrypts upstream with
  system roots. Strips any agent-supplied `Authorization` /
  `Proxy-Authorization` / `X-API-Key` / `api-key`, injects the bound
  credential's header, forces `Connection: close` (one exchange per
  connection, v0 model, documented below). Allowlist = the session's
  resolved destination policy (same list the B8 broker gets), so proxy
  and kernel never disagree.
- **Launcher env at spawn** — `HTTP(S)_PROXY`, `NO_PROXY` (keeps the
  canary honeypot on the direct path: a proxied canary probe would
  never trip the wire, C5), and `SSL_CERT_FILE` /
  `NODE_EXTRA_CA_CERTS` / `REQUESTS_CA_BUNDLE` / `CARGO_HTTP_CAINFO` /
  `CURL_CA_BUNDLE` pointing at the session CA file. Landlock's
  loopback port list gains the proxy port (without this the proxy is
  unreachable under `--net`).
- **Spine rows** — `egress_inject` (`cred=<name>|none`) and
  `egress_deny` per request, hash-chained (S1).
- **Kill switch** — `castellan proxy off [session]` (or the
  `proxy_off` op): listener closes; kernel posture unchanged
  (K4: session itself observes ECONNREFUSED, direct egress still
  EPERM, fail-closed both ways).

## Mechanism notes (v0)

- **TLS termination is the point.** C4 ("real credentials never enter
  the envelope") cannot be satisfied for HTTPS without the proxy
  seeing plaintext. The alternative (CONNECT-only tunnel) cannot
  inject and was rejected in the plan pre-build. The session trusts
  the session CA by env; the CA *cert* is agent-readable (intended;
  it is public), the CA *key* is daemon-memory-only under the S0
  hardening (K1d: `/proc/<daemon>/mem` is EACCES).
- **Per-session CA** (the plan said per-boot; implemented per-session,
  strictly tighter, K8: fingerprints differ across sessions).
- **One exchange per connection**: forwarded requests force
  `Connection: close`; responses pipe until EOF, `close_notify` sent
  on both hops (rustls0.23 treats FIN-without-notify as an error —
  found by the integration test, affects real rustls clients).
- **Stripped always**: agent-supplied auth headers are dropped even
  for unbound hosts — an unbound allowlisted host gets NO
  credential (K6), and a canary value never leaves toward a real
  host through the proxy path.
- **Leaf certs** carry `CN=<host>`, AKI, EKU serverAuth, KU
  digitalSignature; the CA carries KU keyCertSign — python/OpenSSL3
  rejects certs missing any of these (three failures found live by
  the in-session python client; rustls accepts them all, which is why
  the Rust integration test passed first).
- **No QUIC/HTTP3, no DNS filtering** — UDP connect is denied by the
  broker under restriction anyway; a client that insists on QUIC fails
  loudly (documented adoption limitation). DNS exfil remains the C10a
  residual (unchanged by P12).
- **Not a proxy for raw-socket tools**: tools ignoring `HTTP_PROXY`
  hit the broker's EPERM (K3a) rather than silently bypassing —
  break-loudly is the designed behavior.

## Allowlist (per trust tier — unchanged from the design)

The proxy does not invent policy; it enforces the session's resolved
`allow_hosts` under `net_restrict`:

- tier 0–1 (floor forced): empty allowlist → proxy 403s everything
  (K3c covers the deny; the floor path is the same list the broker
  uses).
- tier 2: operator's declared hosts (LLM provider + registries).
- egress grant (bless-broker one-shot): `net_restrict` drops for that
  launch → proxy passes everything, same as the broker.

## Spine concurrency (C40)

P12 exposed a pre-existing race: the event spine has multiple
cross-process emitters (daemon audit watcher, launcher broker
recorder, proxy threads) doing tip→append read-modify-writes; two
emitters interleaved and the S1 chain broke at a stale `prev` (caught
live in p12). `EventSink::emit` now takes an `flock` on a sibling
lockfile across the whole read-modify-write. Verified: K9c chain
intact under concurrent proxy + audit emission.

## Threat model deltas

- **B3** (agent uses a real credential): previously closed by
  construction-without-mechanism (canaries only, no real-credential
  path at all). Now has its mechanism: real keys live in the keyring
  outside every envelope; the envelope holds only canaries; the proxy
  injects. Traversal: read the env — `HTTPS_PROXY` is a port, the CA
  file is public, no secret; read the project — no keyring (K5);
  read `$HOME` config — the keyring path is write-denied under
  enforce (envelope), and read it if readable does not help without
  egress, which the broker gates.
- **New residual (documented, not hidden):** the agent can point its
  own children at a fake proxy on another loopback port with a
  self-minted CA via env — it can MITM *its own* loopback traffic.
  That gains the agent nothing it did not already have (it can read
  its own canaries; loopback services are already reachable), and
  direct public TCP remains broker-denied. Recorded as a non-boundary.
- **Daemon compromise = keyring compromise** — same trust as C37
  (signing key, honeypot secrets): the daemon is the TCB.

## Cost

~1–5ms per request for the proxy hop (plan estimate; no benchmark
claim — not separately measured). Every session pays a listener thread
+ one thread per active connection. Empty keyring degrades to
proxy-without-injection (B8 + canaries posture, fallback).

## Status

Built. See `docs/plans/p12-egress-proxy-keyring.md` for the frozen
gates and execution record, ROADMAP P12 for the phase entry, and
DESIGN_DECISIONS C39/C40 for the decisions behind it.
