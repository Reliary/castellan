# Canary credentials

Fake credentials planted in the envelope, wired to a localhost honeypot listener. **Using OR probing a canary IS the trigger.** There is no "is this key real?" step that does not trip the wire. This is the clean inversion that closes the credential-theft surface.

## The inversion

Normal honeypots: plant a fake, watch for someone using it. The agent can probe before using, so a naive honeypot has a safe-probe path. (Prior art: Thinkst Canarytokens ships AI Agent Guardrail Triggers and an MCP token: alert-only tripwires, no auto-freeze. AWS injects synthetic honeypot cases that trigger demotion. Neither wires canaries into an OS envelope with auto-freeze; see PRIOR_ART.md.)

Castellan's inversion: real credentials never enter the envelope (commitment #4). Every credential the agent can read is a canary by definition. The planted FILES carry no marker: P15 (2026-10-01) removed the self-labels (the dir was `canary/`, the hosts.yml username was `castellan-canary`, the ledger was `canary.jsonl`; now `dotfiles/`, a neutral username, `registry.jsonl` with legacy migration), and the content is valid-format, so a read of the *files* still cannot distinguish canary from real. **Limit:** the secret values remain structurally readable (reads are `/`; the ledger must live on agent-readable disk or restarts would silently disarm canaries, C40c), and the source is public. A sophisticated in-envelope agent that reads the defender's state or source can identify and avoid every canary; this mechanism catches the naive and prompt-injected exfil population it was built for, not a motivated reader auditing the trap inventory. The only way an *uninformed* agent can test whether a key is real is to use it, and using it IS the trigger.

So: there is no probe-then-decide path. Every credential the agent reaches for is a canary, and every canary is wired.

## Mechanism

**Attribution (P15/C40):** the honeypot identifies the *sender* at
accept time (`/proc/net/tcp` → socket fd → cgroup session scope), not
the secret's owner. A session that sends a canary registered to another
session trips as `canary_framing`: the SENDER freezes and is scored;
the owner stays clean (pre-fix the owner froze and the attacker walked
free — THREAT_MODEL C40a). A non-session sender (daemon drill, human
shell) keeps owner attribution (D2 contract); a sender that vanished
before fd mapping records `canary_unattributed` and freezes nobody.


At session spawn, `castellan-canary` (daemon-side) plants canary files in the envelope:

| Real credential (in daemon keyring) | Canary file (in envelope) |
|---|---|
| AWS | `~/.aws/credentials` with `AKIA<fake>...` |
| GitHub | `~/.config/gh/hosts.yml` with `ghp_<fake>...` |
| Git | `~/.netrc` with fake entries |
| npm | `~/.npmrc` with `//registry.npmjs.org/:_authToken=<fake>` |
| Cargo | `~/.cargo/credentials.toml` with fake token |
| PyPI | `~/.pypirc` with fake token |
| Heroku / DigitalOcean / etc. | as discovered |

Each canary key is a valid-format but non-functional credential that, when used against any endpoint, routes to the **localhost honeypot listener** (not the real cloud API). The honeypot:

1. Accepts the connection (so the agent's tool sees "a server responded").
2. Logs the attempt (which canary, which session, what action was attempted).
3. Signals the daemon → **auto-freeze the session** (deterministic; not sentinel, see D4).
4. Returns a plausible-looking error or empty response (so the agent doesn't immediately know it was caught, though it's frozen and doesn't get to react anyway).

## Routing to the honeypot

Two mechanisms:

1. **DNS override in the user namespace:** the agent's `/etc/hosts` (inside the user namespace) maps `api.github.com`, `api.aws.amazon.com`, etc. to `127.0.0.1`. The agent's HTTPS client connects to localhost, hits the honeypot's TLS listener (with a self-signed cert for the expected domain; the agent's tool may reject the cert, but the connection attempt itself is the trigger).
2. **Proxy interception (when egress proxy is active):** the proxy sees the request, recognizes the canary auth header, and routes to the honeypot instead of forwarding.

Both mechanisms together: DNS override catches raw-socket tools, proxy catches HTTP_PROXY-respecting tools.

## Auto-freeze on hit

Canary hit → `castellan-freeze all <session>` → session frozen, notification fired. This is deterministic (not sentinel). The user is told: "Agent attempted to use a canary credential. Session frozen. Review / Thaw / Undo / Kill."

Trust impact: −50 (canary hit is the heaviest negative signal short of forging a bless nonce).

## What about legitimate egress?

Legit egress (the agent calling the LLM provider, fetching a package from a registry) goes through the **egress proxy** with **real credentials injected server-side**. The agent doesn't use the canary for these: the agent's HTTP client uses the proxy (via `HTTP_PROXY`), the proxy adds the real `Authorization` header from the keyring. The canary in `~/.aws/credentials` is never touched by the legit path.

The canary is only touched if the agent (or an injected instruction) tries to use a credential directly, bypassing the proxy. That's the attack signature.

## Antagonism survivors

- B3 (agent uses real credential): closed: there are none in the envelope.
- B3-variant (agent probes first): closed: probing IS using IS the trigger.
- C2 (malicious MCP exfils creds): closed: MCP server reads canary, trips wire.
- A8 (slow-drip → egress → exfil): mitigated: exfil via canary trips wire; exfil via proxy hits allowlist.

## Residual risks

- Tools that bypass both DNS and HTTP_PROXY (raw socket to a hard-coded IP) — these reach the real internet if Landlock network restriction is not active. Mitigation: Landlock ABI v4 restricts TCP bind/connect to loopback only, so raw-socket tools also can't escape (they can only connect to localhost, where the honeypot catches them). This is why Landlock network restriction (not just filesystem) matters for full canary coverage.
- An agent that reads the canary but doesn't use it (just `cat ~/.aws/credentials`) — read alone is not the trigger; use is. A read-only scan by an indexer or backup tool doesn't trip. This is the correct behavior (high specificity).

## Dependencies

- `castellan-core` (SessionId)
- `castellan-daemon` (keyring, honeypot listener lifecycle)
- `castellan-envelope` (loopback-only network restriction for full coverage)
- `castellan-freezer` (auto-freeze on hit)
- Greenfield: honeypot listener, DNS override, canary file generation.

## Status

Greenfield. Phase 2.
