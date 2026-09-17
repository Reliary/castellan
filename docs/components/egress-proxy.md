# Egress proxy (designed, not built)

**Status: this component is designed, not built.** What actually ships for
egress is the **B8 seccomp user-notification broker** (deny public TCP/UDP to
an IP allowlist, allow loopback and non-manager unix sockets) plus the canary
honeypot (detect-and-freeze). There is no credential-injecting proxy and no
daemon keyring today. The doc is kept as the design for real-egress support;
read it as intent, not inventory.

**Correction (2026-09-17):** an earlier version of this doc claimed the
envelope's network capability is "loopback only" via Landlock ABI v4 TCP
rules. That is **false**: Landlock net rules are **port-scoped, not
address-scoped** (C10a), so "loopback only" cannot be expressed. The built
mechanism is the B8 broker with an IP allowlist.

## Design intent

All network egress from an agent session would flow through the daemon's proxy.
The proxy holds real credentials and injects them server-side. The envelope
contains only canary credentials. **Any credential the agent can read is a
canary by definition.** This closes the credential-theft surface that the
envelope alone can't (the credentials would be inside the writable boundary).

## Why this exists (Threat B3, C2)

Without the proxy: the agent reads `~/.aws/credentials`, exfils the key.
The envelope can't stop this — the file is in `$HOME` which is read-allowed,
and (absent the broker) the agent may have network.

With the proxy: `~/.aws/credentials` is NOT in the envelope. The envelope has a
canary `~/.aws/credentials` instead. Real AWS calls go via the proxy, which has
the real key (in the daemon's keyring, outside any envelope) and injects it.
The agent never sees a real credential.

## Mechanism (designed)

- Envelope network capability: in the built system, the B8 broker denies public
  TCP/UDP and allows loopback + an explicit IP allowlist. (Not "loopback only"
  — that is inexpressible with Landlock net rules.)
- The proxy would listen on a localhost port (e.g., 127.0.0.1:8443).
- The agent's `HTTP_PROXY` / `HTTPS_PROXY` env vars point to the proxy.
- The agent makes an HTTP request to `https://api.github.com/...` — the client
  library uses the proxy.
- The proxy intercepts, strips any `Authorization` header the agent set (the
  agent only has canary creds, which would be invalid), injects the real
  `Authorization: Bearer <real-key>` from the daemon's keyring, and forwards.
- Responses flow back through the proxy.

## Allowlist (per trust tier)

- **tier 0-1:** no egress. Proxy refuses all forwarding.
- **tier 2:** allowlist = LLM provider + package registries (npm, crates, pypi, arch mirrors) + git hosts (github, gitlab, bitbucket).
- **tier 3:** broader allowlist (configurable per project).
- **tier 4:** broad allowlist + per-domain approval flow via bless broker.

The allowlist is the egress policy; the proxy enforces it. In the built system
the equivalent is the B8 broker's IP allowlist (loaded at policy construction),
not a loopback-only envelope.

## Credential keyring (designed)

The daemon would hold real credentials in a keyring:
- Linux: `keyring` crate (Secret Service / kwallet / plaintext fallback) OR a
  sealed file under the daemon's state dir.
- The keyring is OUTSIDE any envelope (daemon path, not agent path).
- Credentials are injected by the proxy, never written to disk in plaintext,
  never passed to the agent process.

**Not built.** No keyring or real-credential injection exists in the shipped
daemon. Today's posture is: no real credentials in the envelope, canaries wired
to the honeypot.

## Canary credentials (see canary-credentials.md)

For every real credential the daemon holds, a canary is planted in the envelope:
- `~/.aws/credentials` with a fake AWS key
- `~/.config/gh/hosts.yml` with a fake GitHub token
- `~/.netrc` with fake entries
- `~/.npmrc` with a fake token
- `~/.cargo/credentials.toml` with a fake cargo token

Each canary is wired to the localhost honeypot. Using OR probing it triggers the wire → auto-freeze.

## What this costs

- Every egress is proxied (latency: ~1-5ms per request for the proxy hop).
- The proxy is in the trusted path and must be auditable: minimal HTTP parser, no framework, small surface.
- Some tools don't respect `HTTP_PROXY` (e.g., tools using raw sockets or custom TLS). Those break under the proxy — flagged to the user, who can bless a per-tool bypass (biometric, rate-limited).

## Antagonism survivors (design intent)

- B3 (agent uses real credential): would be closed — no real credentials in
  the envelope. Today: canaries only, no real-credential path at all.
- C2 (malicious MCP exfils): partially — the MCP server inherits the session
  envelope; absent the broker, a raw-socket exfil is detected by the canary
  honeypot, not prevented (C10a).
- A8 (slow-drip → egress): mitigated by tier ceilings; egress restriction is
  the B8 broker's IP allowlist when net is requested.

## Residual risks

- DNS-based exfiltration: the B8 broker covers TCP/UDP connect, not DNS
  resolution (which goes to whatever resolver is configured). Documented as a
  known gap (C10a); a DNS allowlist is not built.
- A compromised daemon keyring = real credentials exposed. But there is no
  keyring today; this risk arrives with the design.

## Dependencies (designed)

- `castellan-core` (EnvelopeProfile, TrustTier)
- `castellan-daemon` (keyring, proxy lifecycle)
- `castellan-canary` (canary planting, honeypot wiring — BUILT)
- `castellan-broker` (B8 TCP/UDP policy — BUILT)
- NO owned primitive here — greenfield.

## Status

Designed, not built. The built egress mechanisms are: the B8 seccomp broker
(deny-by-IP-allowlist for TCP/UDP), the canary honeypot (detect-and-freeze), and
the cold/tier floor. A credential-injecting proxy and daemon keyring are future
work. The reliary-agent HTTP proxy (pass-through, no credential injection) was
REMOVED in v0.8.0 and is NOT reusable — different threat model.
