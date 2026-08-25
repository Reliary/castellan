# Undo

Surgical, per-session reversal of agent writes. No reboot, no whole-disk snapshot, no nuking the user's unrelated edits. Reverses exactly the files one session touched, restored to their pre-session content for those files only.

## Mechanism (commitment #2)

The agent runs inside a user namespace with an overlayfs mount over the project directory:

- **lowerdir:** the real project directory, bind-mounted read-only.
- **upperdir:** `~/.local/state/castellan/sessions/<uuid>/upper/` — where the agent's writes land.
- **workdir:** `~/.local/state/castellan/sessions/<uuid>/work/` — kernel work dir for overlayfs.

The agent sees a writable filesystem that looks like the project; every write goes to the upper layer. The lower layer is immutable (read-only mount), so the agent cannot corrupt pre-session state.

**Undo = discard the upper layer.** The project directory reverts to the lower layer = pre-session state. Atomic at the filesystem level, no race (this is why overlayfs won over inotify — see D9).

## The ledger falls out for free

Enumerating the upper layer gives the complete set of files the session created or modified. For each file, the lower layer has the pre-session version (or "did not exist"). This IS the kernel-witnessed ledger — no separate inotify watcher needed when overlayfs is available. inotify is the fallback substrate when user namespaces / overlayfs are unavailable (degrade tier 3).

Before-images are content-addressed (blake3) and stored in a shared dedup blob store at `~/.local/state/castellan/blobs/` so multiple sessions that touch the same file don't re-snapshot. GC with pinning (a session can be pinned to prevent blob eviction).

## 3-way merge UX

Naive restore is wrong when the user has edited unrelated files after the session. The undo UI shows a 3-way diff:

- **base:** pre-session state (lower layer)
- **session:** post-session state (upper layer)
- **current:** what's on disk now (user's edits since the session ended, to other files)

Undo applies the inverse of (base → session) to (current), preserving the user's unrelated edits. Conflicts (user edited a file the session also edited) are surfaced for manual resolution. This is `git revert` semantics applied to filesystem state.

## Freeze-before-undo sequencing

Undoing a running session is a race. Protocol:

1. Freeze the session (cgroup.freeze).
2. Snapshot the upper layer state for diff.
3. Apply the 3-way merge to the lower layer (now writable by the daemon, NOT by the agent — the agent is frozen).
4. Kill the session (SIGKILL all PIDs).
5. Clean up the scope.

The agent is frozen throughout; it cannot interfere with its own undo.

## `castellan undo <session>` CLI

- `castellan undo <uuid>` — interactive 3-way merge UI (default).
- `castellan undo <uuid> --dry-run` — show what would change.
- `castellan undo <uuid> --force` — apply without manual conflict resolution (conflicts left as `.orig` files).
- `castellan undo <uuid> --only <path>` — undo only files matching a path prefix.
- `castellan undo --last` — undo the most recent session.

## Pinned GC

- Sessions auto-expire after 30 days (configurable).
- A session can be pinned (`castellan pin <uuid>`) to prevent expiry.
- Blob store GC removes unreferenced blobs.
- The always-on deny-list paths are never in any upper layer (Landlock prevents the writes), so undo never accidentally restores something the agent shouldn't have touched.

## DoS defense

- A misbehaving agent could fill the upper layer with garbage. Mitigation: per-session RLIMIT_FSIZE or upper-layer quota (configurable, default 2 GB).
- Quota exceeded → daemon freezes the session and notifies.

## Antagonism survivors

- A10 (corrupt the ledger): closed — lower layer is read-only mount; blob store is outside the envelope.
- D9 (inotify race): closed — overlayfs is atomic.
- B2 (agent lies about what it touched): closed — ledger is kernel-witnessed (upper layer enumeration), not agent-reported.

## Residual risks

- Sessions that need to write OUTSIDE the project dir (e.g., to a global config they legitimately expanded into via bless broker) — those writes aren't under the overlayfs. Tracked separately in the event spine via inotify on those expanded paths; undo-able on a best-effort basis. Documented.
- Workspace persistence attacks (C4) — undo doesn't help here; the malicious file is in the workspace and the user's shell runs it later. Detected by post-session relay-vuln scan and skein diff, not prevented by undo.

## Dependencies

- `castellan-core` (SessionId)
- `castellan-freezer` (freeze-before-undo)
- `castellan-ledger` (event spine, blob store)
- `nix` crate (user namespaces, overlayfs mounts, RLIMIT)
- Owned primitives: `skein` + `carrion` (integrity checks on restored state — fingerprint diff before/after undo to verify correctness).

## Status

Greenfield. No overlayfs or user-namespace code anywhere in our repos. Phase 2, ~2 weeks.
