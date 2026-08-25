# Egress proxy

All network egress from an agent session flows through the daemon's proxy. The proxy holds real credentials and injects them server-side. The envelope contains only canary credentials. **Any credential the agent can read is a canary by definition.** This closes the credential-theft surface that the envelope alone can't (the credentials would be inside the writable boundary).

## Why this exists (Threat B3, C2)

Without the proxy: the agent reads `~/.aws/credentials`, exfils the key. Envelope can't stop this — the file is in `$HOME` which is read-allowed, and the agent has network.

With the proxy: `~/.aws/credentials` is NOT in the envelope. The envelope has a canary `~/.aws/credentials` instead. Real AWS calls go via the proxy, which has the real key (in the daemon's keyring, outside any envelope) and injects it. The agent never sees a real credential.

## Mechanism

- The envelope's network capability is set to "loopback only" (Landlock ABI v4 TCP bind/connect restriction). The agent can only reach localhost.
- The proxy listens on a localhost port (e.g., 127.0.0.1:8443).
- The agent's `HTTP_PROXY` / `HTTPS_PROXY` env vars point to the proxy.
- The agent makes an HTTP request to `https://api.github.com/...` — the client library uses the proxy.
- The proxy intercepts, strips any `Authorization` header the agent set (the agent only has canary creds, which would be invalid), injects the real `Authorization: Bearer <real-key>` from the daemon's keyring, and forwards.
- Responses flow back through the proxy.

## Allowlist (per trust tier)

- **tier 0-1:** no egress. Proxy refuses all forwarding.
- **tier 2:** allowlist = LLM provider + package registries (npm, crates, pypi, arch mirrors) + git hosts (github, gitlab, bitbucket).
- **tier 3:** broader allowlist (configurable per project).
- **tier 4:** broad allowlist + per-domain approval flow via bless broker.

The allowlist is the egress policy; the proxy enforces it. The agent cannot bypass (loopback-only envelope).

## Credential keyring

The daemon holds real credentials in a keyring:
- Linux: `keyring` crate (Secret Service / kwallet / plaintext fallback) OR a sealed file at `~/.local/state/castellan/keys/` (encrypted with a machine key in the kernel keyring).
- The keyring is OUTSIDE any envelope (daemon path, not agent path).
- Credentials are injected by the proxy, never written to disk in plaintext, never passed to the agent process.

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

## Antagonism survivors

- B3 (agent uses real credential): closed — no real credentials in envelope.
- C2 (malicious MCP exfils): closed — MCP server inherits loopback-only envelope; exfil attempts hit canary or proxy allowlist.
- A8 (slow-drip → egress): mitigated — even at tier 4, egress goes through the proxy with allowlist + logging. Worst case is egress to an allowed domain, not arbitrary exfil.

## Residual risks

- Tools that bypass `HTTP_PROXY` (raw sockets, custom TLS) — flagged, per-tool bless required.
- DNS-based exfiltration: the proxy handles HTTP, not DNS. A separate DNS allowlist (via `/etc/hosts` override in the user namespace, or a custom resolver) is needed for full coverage. v0 documents this as a known gap; v1 adds DNS restriction.
- A compromised daemon keyring = real credentials exposed. Daemon is the trusted core; compromise here is game over (same as kernel compromise, documented).

## Dependencies

- `castellan-core` (EnvelopeProfile, TrustTier)
- `castellan-daemon` (keyring, proxy lifecycle)
- `castellan-canary` (canary planting, honeypot wiring)
- `hyper` or hand-rolled minimal HTTP parser (auditability)
- NO owned primitive here — greenfield.

## Status

Greenfield. The reliary-agent HTTP proxy (pass-through, no credential injection) was REMOVED in v0.8.0 and is NOT reusable — different threat model. Phase 2 (v0: loopback-only, canary-only, no real egress) → Phase 3 (v1: real egress via proxy with allowlist).
