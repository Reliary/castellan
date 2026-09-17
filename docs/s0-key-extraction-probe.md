# S0 probe — can a same-uid agent extract the signing key?

Run 2026-09-17 on kernel 7.0.3, `yama ptrace_scope=1`, the daemon and the
probe both uid 1000, the probe run **inside an enforced castellan session**
(`launch --enforce -- python3 probe.py`). This gates chapter 5's claim.

| Vector | Host shell | Inside enforced session | Mechanism |
|---|---|---|---|
| `/proc/<daemon>/mem` | denied | denied | `ptrace_scope=1` |
| `process_vm_readv` | denied | denied | Yama |
| `ptrace(PTRACE_ATTACH)` | denied | denied | Yama + seccomp |
| **`coredump` (`kill -6`)** | **EXTRACTED** | (same uid can signal) | `core_pattern=systemd-coredump`, `RLIMIT_CORE=unlimited`, process dumpable |
| **disk key 0600 (read)** | readable | **readable** | read roots are `/` — a same-uid file is readable |
| disk key 0600 (write) | — | denied | Landlock write roots exclude the state dir |
| spine / `sessions/` / `trust.db` (write) | — | **denied** | Landlock |

## What this means

1. **A key persisted to disk is readable by the agent.** The agent's Landlock
   policy allows reads from `/` (reads are deliberately broad), so any file the
   daemon writes under the state dir is readable. Writing it is denied, but
   reading is enough to sign arbitrary certificates. A disk key is worthless
   against the agent's own uid.

2. **A memory-only key is *also* extractable, via coredump.** A same-uid
   process can `SIGABRT` the daemon; `systemd-coredump` writes the full memory
   image (verified: the planted secret string was found in the resulting core).
   So "hold it in memory" is not sufficient on its own.

3. **The closure exists and is cheap:** `prctl(PR_SET_DUMPABLE, 0)` +
   `RLIMIT_CORE=0` makes the daemon non-dumpable (verified: no core produced,
   memory search impossible). Combined with never writing the key to disk, the
   key becomes unreachable to a same-uid agent while the process runs.

   Verified on the live daemon (2026-09-17): with the hardening applied,
   `/proc/<daemon>/status` is served **owned by `root:root`** (the kernel's
   non-dumpable rule), so a same-uid agent cannot read `maps`, `mem`, or
   `status`; `RLIMIT_CORE` is `0`; and `SIGABRT` produces **no core**
   (`coredumpctl` count unchanged). The S0 finding below predates the fix —
   both the leak and the closure are recorded so the claim is reproducible.

4. **The anchor is already safe.** The spine, `sessions/`, and `trust.db` are
   all write-denied under the agent's envelope. The agent cannot rewrite the
   evidence the certificate is assembled from. This is the property that makes
   hash-chaining meaningful.

## The honest claim

With a memory-only, non-dumpable key and an agent-unwritable spine:

- **Against the agent's own uid (while the daemon runs):** the key is not
  reachable by any probed vector. The residual is a kernel-level attack
  (ptrace bypass, `/proc/pid/mem` via a setuid helper, a future coredump
  vector) — out of scope, documented.
- **Against cross-machine fabrication and post-hoc edits by another user:**
  signatures hold. This is the claim the certificate can make.
- **Against a same-uid attacker who restarts the daemon:** the key must not
  survive restart (a persisted key is readable). So the key is per-boot; a
  restart invalidates prior signatures' *freshness* but not their integrity
  (the public key is embedded in each certificate and can be pinned per boot).

What the certificate therefore proves is **integrity and provenance within a
boot**, not non-repudiation against a same-uid adversary with kernel access.
That is the honest scope and it is written into the cert's factor text.
