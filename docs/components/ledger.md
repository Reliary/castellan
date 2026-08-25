# Ledger

The kernel-witnessed record of what a session wrote. Primary substrate: overlayfs upper layer (atomic, no race — commitment #2). Fallback substrate: inotify on allowed paths (when overlayfs/user-ns unavailable). Feeds undo, trust, proofs, and radar.

## Two sources of truth, clearly separated

- **Kernel truth** (`source: kernel`): inotify events on allowed paths, overlayfs upper-layer enumeration, seccomp-audit denials. These are what actually happened. Cannot be faked by the agent.
- **Agent advisory** (`source: agent`): events the agent declares via agent-audit-trail. These are what the agent claims happened. Cross-checked against kernel truth; mismatches decrement trust and weaken ProofCertificates.

This split is the core honesty move: the agent is the prover, the kernel is the verifier, the daemon is the recorder. No trust decision rests on agent-reported data alone.

## Event spine schema

Per session: `~/.local/state/castellan/sessions/<uuid>/events.jsonl`, append-only, one event per line:

```json
{"ts": 1234567890, "session": "uuid", "cgroup": "castellan-uuid.scope", "type": "write", "target": "/path", "before_hash": "blake3", "after_hash": "blake3", "source": "kernel"}
{"ts": 1234567891, "session": "uuid", "type": "exec", "target": "/usr/bin/cargo", "args_hash": "blake3", "source": "kernel"}
{"ts": 1234567892, "session": "uuid", "type": "net", "target": "api.github.com:443", "source": "kernel"}
{"ts": 1234567893, "session": "uuid", "type": "claim", "claim": "tests_passed", "claim_ok": true, "source": "agent"}
{"ts": 1234567894, "session": "uuid", "type": "deny", "target": "/home/john/.ssh/id_rsa", "syscall": "openat", "source": "kernel"}
```

## Blob store

Before-images (file content before a session modified it) are content-addressed with blake3 and stored in `~/.local/state/castellan/blobs/<blake3-prefix>/<blake3>`. Dedup across sessions (two sessions touching the same pre-state file share the blob). GC removes unreferenced blobs; pinning prevents GC of blobs for sessions marked pinned.

## overlayfs substrate (primary)

When overlayfs is available:
- The agent's writes land in the upper layer.
- Enumerating the upper layer at session end gives the complete set of created/modified files.
- For each file in upper, the lower layer has the pre-session version (or "did not exist").
- before_hash = blake3 of lower version; after_hash = blake3 of upper version.
- No inotify needed — the upper layer IS the ledger.

## inotify substrate (fallback, degrade tier 3)

When overlayfs / user namespaces are unavailable:
- inotify watches every path in the envelope's allow-set.
- On `IN_MODIFY` / `IN_CREATE` / `IN_DELETE`, the daemon reads the file, hashes it, records the event.
- **Known race (D9):** an agent can write+delete faster than the watcher fires, losing the before-image. Documented. This is why overlayfs is the primary substrate.
- The fallback is marked in the event spine as `substratum: inotify-fallback` so downstream consumers (trust, proofs) know the ledger is not race-free.

## Antagonism survivors

- A10 (corrupt the ledger): closed — lower layer is read-only mount; blob store is outside envelope.
- B2 (agent lies about what it touched): closed — kernel truth cross-checked against agent claims.
- D9 (inotify race): closed by overlayfs; documented for the fallback.

## Dependencies

- `castellan-core` (SessionId, Event)
- `castellan-undo` (blob store shared)
- `nix` crate (inotify)
- `blake3` (hashing)
- Owned primitive: `agent-audit-trail` (BUILT, PASS) for the advisory layer.

## Status

Greenfield (inotify watcher, overlayfs enumeration, blob store). The advisory layer (agent-audit-trail) is owned. Phase 1 (inotify) → Phase 2 (overlayfs).
