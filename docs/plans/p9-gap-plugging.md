# P9 Gap-Plugging Plan (2026-08-28)

Closes the four gaps from the "does it work?" audit. Order is load-bearing:
1 → 2 (can't live-verify a gameable path), 3 before 5 (the stack suite calls
policycheck), 4 anytime.

## Step 1 — Close the 9.4 gaming vector (prereq for its live-verify)

`.stria/phrases.sqlite` lives inside the agent's write roots and the hub
weight is read at KEEP — an agent can rewrite the index mid-session to make
its touched files look like hubs and inflate positive signals (bounded by
the +1 tier/day ceiling, but real).

- Capture `sha256(phrases.sqlite)` at spawn (alongside `config_sha`); at
  keep, weight = **1.0 (neutral, not refused)** on missing/mismatched index
  — weighting is advisory, so neutral-fail is the right failure mode
  (unlike test_cmd's refuse).
- Unit test: tamper index between spawn and keep → weight neutral.
- ~40 lines + test.

## Step 2 — Live-verify 9.4 through the daemon

- Fresh project with a real stria index: one hub file (referenced by
  many), one isolated leaf. `stria build` pre-session.
- **Two separate fresh projects** (avoids trust contamination — scan-proj
  is already polluted at tier 1): keep a leaf-edit session → expect exactly
  `+1×0.5 = 50.5`; hub-edit session on the other project → `+2×2.0 = 52.0`.
  Assert exact arithmetic (apply is plain addition), not eyeballing.
- ~30 min including index builds.

## Step 3 — Wire 9.6 into a verb

- Core: `PolicyCheck { project, candidate_project }`; daemon handler calls
  `check_policy_for_project` (harness from durable session records,
  `claude` fallback — same pattern as replay); CLI
  `castellan policycheck <project> <candidate>` with
  verdict/sessions/newly-denied render.
- **Live-verify against existing state**: scan-proj already has kept
  sessions in trust.db from the P9.2 testing — narrower candidate root →
  `FALSE_NEW_DENIES` with the out-of-root paths; identical root →
  `NO_FALSE_NEW_DENIES`.
- Acceptance script `test/shell.d/p9-policycheck.sh` (both directions),
  matching the P8 suite pattern.
- ~120 lines across core/daemon/CLI.

## Step 4 — Semgrep live verification

**Found: semgrep 1.172.0 IS installed** (`~/.local/bin/semgrep` shim +
`~/.local/lib/python3.14/site-packages/semgrep`). The OCaml wrapper fails
with `execvp pysemgrep` because `pysemgrep` is not on PATH; the Python
entrypoint `~/.local/bin/pysemgrep --version` works (1.172.0).

- Capability detection must check BOTH `semgrep` and `pysemgrep` (the
  wrapper needs the latter on PATH; the adapter should prefer whichever
  runs).
- **Offline deterministic config**: one local rule file (e.g., `gets(`
  detection), `--config <file> --json` — never `--config auto` (phones
  home, non-deterministic).
- One live keep with a `gets()` file via the semgrep adapter → trust
  signal + cert `scanner=semgrep`. Parser unit tests already exist; this
  verifies the subprocess + delta path.

## Step 5 — The stack as a stack (the workflow-rule violation)

New acceptance suite `test/shell.d/p9-stack.sh` — one fresh project, one
daemon, everything composed in **single sessions**:

- Session A (good): stria-indexed project, canary+decoys planted, agent
  fixes a real bug in the hub file → keep asserts: overlay committed,
  placebo passed **with hub weight**, scan baseline (spawn) + clean/vuln
  delta correct, decoys untouched (no signal), cert carries
  bounds+placebo+artifact+census, trust score exact.
- Session B (bad): touches session A's file after (trace exposure),
  weaponizes a decoy → DECOY TRIP, trace shows B exposed.
- Then `policycheck` narrower-root flag on the composed history.
- Every assertion PASS/FAIL with latency, like the P8 drill suite. Results
  dated in ROADMAP (status: "composed-verified 2026-08-28" or the failures
  recorded).

## Docs at the end

- ROADMAP Phase 9 not-built list corrected per outcomes (semgrep
  live-verified; composition verified).
- THREAT_MODEL C21 gains the index-poisoning note (found-then-fixed).
- CRATES unchanged.

## Kill criteria

- Step 1: tampered index → weight 1.0 (unit test).
- Step 2: leaf 50.5 vs hub 52.0 exact (live).
- Step 3: regression flagged + no-change clean (live + script).
- Step 4: semgrep finding → trust signal + cert scanner=semgrep (live).
- Step 5: all stack assertions PASS (live).
