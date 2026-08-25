# Harness-state watcher

Monitors `~/.claude/skills/`, `~/.codex/skills/`, `~/.pi/agent/skills/`, `~/.gemini/config/skills/`, `~/.agents/skills/` (and harness hook dirs) for changes. The harness state dir MUST be writable for the harness to function — so the envelope allows writes there — which means it's the persistence vector Landlock can't close. This watcher closes it.

## The hole

A malicious skill (or a prompt-injected agent writing a skill) persists across sessions: the harness loads it next time, even in a fresh envelope. Datadog documented this (malicious Claude Code skills bypass model-level injection defenses via dynamic-context `!ls` commands that execute before the model reviews the skill). The envelope can't deny writes to `~/.claude/skills/` without breaking Claude Code. So we watch instead.

## Mechanism

At castellan install (and at each daemon start), `castellan-watch` baselines the harness state dirs:
- Walks each skills/hooks dir.
- For each file, computes a skein vocabulary fingerprint (sha256 of sorted extracted phrases) and a carrion dead-code-style identifier inventory.
- Stores the baseline at `~/.local/state/castellan/harness-state-baseline.json`.

At each session end (and on a 60s inotify poll of the harness state dirs during sessions), the watcher recomputes fingerprints and diffs against baseline:
- **New file:** NEW_SKILL_DETECTED → notify + quarantine (move to `~/.local/state/castellan/quarantine/<uuid>/` and symlink a stub back) pending human approval.
- **Modified existing file:** fingerprint delta above threshold → notify + show diff, pending approval.
- **Deleted file:** notify (a deleted skill is suspicious — could be an attacker clearing defensive skills).

## Quarantine flow

1. New/modified skill detected.
2. Watcher moves the file to quarantine, replaces with a stub that does nothing (or warns on load).
3. Notification: "New Claude skill detected: `<name>`. Preview / Approve / Reject."
4. Preview shows the skein fingerprint diff + the file content.
5. Approve → restore the file, update baseline.
6. Reject → keep in quarantine, baseline unchanged.

This is analogous to how Omarchy's migrations work — explicit, reviewed, reversible.

## Integration with Omarchy

Omarchy symlinks its default skill into all the harness skill dirs. The watcher treats the Omarchy-shipped skill as part of the baseline (it's expected). New skills added by an agent or by `pi install <skill>` trigger the quarantine flow unless they match the baseline.

`omarchy-skill-trust <name>` command: explicitly trust a skill (updates baseline without quarantine).

## skein + carrion roles

- **skein:** vocabulary fingerprint of the skill file. Fast, grammar-free. Detects "this file's content changed semantically" even if line-by-line edits are sneaky.
- **carrion:** identifier inventory. Detects "this file references new symbols" (e.g., a skill that suddenly imports `requests` and `subprocess` is suspicious).

Both are built, both Rust, both linked as workspace crates (skein, carrion) — no subprocess spawn.

## Antagonism survivors

- C3 (poisoned skill): closed — new/modified skill quarantined pending approval.
- C1 (compromised harness writing skills): closed — same quarantine flow.

## Residual risks

- A harness that loads skills from a path outside the watched set (e.g., a custom `--skills-dir`). Mitigation: the watcher enumerates harness config to discover skill paths; if undiscovered, document the gap.
- An attacker who modifies the baseline file directly — the baseline is in `~/.local/state/castellan/` which is OUTSIDE the envelope (daemon path). The agent cannot modify it.
- Race: attacker writes + harness loads in the 60s poll window. Mitigation: inotify is event-driven (not polling); the 60s is a fallback. The race window is sub-second.

## Dependencies

- `castellan-core` (SessionId)
- `castellan-daemon` (baseline storage, quarantine dir, inotify lifecycle)
- Owned primitives: `skein` (BUILT, 203 LOC), `carrion` (BUILT, 227 LOC).

## Status

Wired from owned primitives. Phase 1 (ships with the envelope, since it closes the envelope's harness-state hole).
