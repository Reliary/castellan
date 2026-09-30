# P13 — Escape sweep: second-pass potential classification

Status: EXECUTED (2026-09-30) — probe battery PASS, all must-fix closed
Branch: `escape-sweep`
Pre-registered: classification below was frozen BEFORE probes ran.
Steelman tolerance is the operating rule: bounded, rate-limited, observable
residuals are acceptable; one-shot, zero-cost vectors are not.

## Results (post-execution)

| ID | Probe verdict | Action taken |
|----|---------------|--------------|
| E-a | **CONFIRMED**: default `--enforce` connected to 127.0.0.1:22 from inside a session (first fix was scoped to `with_llm_only` only — a real bug in yesterday's fix) | `EgressPolicy::new()` now calls `deny_loopback_ssh()`; `Default` impl routes through `new()` (the derived Default would have skipped every deny flag); b8 section 1 asserts DENIED (3 ports) |
| E-b | **CONFIRMED**: `/run/docker.sock` CONNECTED (uid in docker group), podman/libvirt paths denied (absent) | `deny_deputy_sockets` default-on: docker/podman/lxd/libvirt socks denied by suffix pattern; benign desktop sockets (wayland, pipewire, gpg-agent) proven unaffected by unit test |
| E-c | **CONFIRMED one-shot**: `pkcheck` rc=0 (NO auth) for `udisks2.loop-setup` + `filesystem-mount`; systemd1 `manage-units` measured auth_admin_keep (rc=2, NOT the trigger); udisks2 runs as UID 0 | `deny_system_bus` default-on (`/dbus/system_bus_socket` suffix); systemd1 system route measured non-callable — recorded, not fixed (auth_admin is polkit's job) |
| E-d | **REFUTED by code**: daemon binds only a UnixListener; no TCP/9090/axum exists (the 9090 memory is from reliary, not castellan) | nothing — no surface |
| E-e | **PASSED on this box**: `sudo -n` → password required (rc=1) | launcher advisory fires only when `sudo -n` succeeds (positive branch verified with a PATH-faked `sudo`) |
| E-i | **PASSED**: spine jsonl, other-session spine, durable meta, sessions dir — all EACCES/EISDIR from inside a session (sibling-of-write-root by construction, now proven not assumed) | nothing |
| E-f | wayland-0 CONNECTED | within tolerance — documented in THREAT_MODEL |
| E-g | not probed (same-human grant) | documented in THREAT_MODEL |
| E-h | advisory: project ⊇ $HOME fires warning (verified both directions) | launcher warning, never a launch block |
| E-j | CUPS 631, LLMNR 5355, local services reachable under loopback blanket | documented in THREAT_MODEL (data/API class, tolerance) |

Probe battery: `test/shell.d/p13-escape-probe.sh` — **15 PASS / 0 FAIL / 1 NOTE**
(post-fix run; pre-fix run showed E-a/E-b open as recorded above).
b8: **19/19** (3 new default-posture ssh assertions). Workspace: 199 tests,
clippy 0/48 (= baseline), deny x4 ok. p0: 12/3 — **identical 12/3 on the
stashed pre-change tree** (pre-existing R7-tty local misses, not this change).

## Classification (frozen pre-probe, as executed)

### OUTSIDE tolerance — one-shot, zero-cost, must fix

| ID | Vector | Layer gap | Probe (attempt only, no state change) | Gate |
|----|--------|-----------|----------------------------------------|------|
| E-a | `ssh localhost` under plain `--enforce` | `deny_loopback_ssh()` only in `with_llm_only()`; `EgressPolicy::new()` has no ssh deny (code-confirmed) | b8 section 1: connect 127.0.0.1:22/2222/2200, expect CONNECTED today | fix: `new()` calls `deny_loopback_ssh()` (hard-deny, no opt-out, systemd-socket precedent); b8 section 1 flips to DENIED; audit-posture unit test inverted |
| E-b | `/run/docker.sock` deputy → root container | unix verdict denylist does not name docker/podman/lxd/libvirt socks; Landlock does not gate unix connect | from session: `connect("/run/docker.sock")` — EACCES = safe, success = fix | fix: default unix denylist gains `*.sock` deputy paths; kill if fix breaks a legit docker workflow (must be explicit grant) |
| E-c | System D-Bus `system_bus_socket` (world-rw) | `is_user_bus` requires `ends_with("/bus") && contains("/run/user/")` — system bus matches neither predicate | on .227: `busctl --system` introspect; attempt `udisks2 loop-setup` / logind call | any one-shot-class callable action → default-deny system bus + grant; if all actions `auth_admin` → reclassify down (advisory) |
| E-d | Daemon TCP :9090 control RPC | loopback blanket allows 127.0.0.1:9090 in EVERY posture; TCP has no SO_PEERCRED | from session: issue freeze/bless/spawn over TCP, compare classification vs unix socket call | any non-`human-only`-denied response → control RPCs over TCP denied or unix-only; health/metrics unchanged |
| E-e | NOPASSWD sudo | wheel + nopasswdlogin groups present (host config) | `sudo -n true` — rc=0 = one-shot root | **probed on this box: rc=1, password required — PASSES here**. `doctor` warns iff `sudo -n` succeeds (castellan cannot fix sudoers; false-confidence boundary) |
| E-i | Spine/meta forgery | `state/castellan/events/` and `sessions/<session>.json` are SIBLINGS of the agent write root `sessions/<session>/` (code-read: policy.rs:146, core.rs:440, daemon.rs:493) — appears safe by construction | from session: write-attempt spine jsonl + `<session>.json` — expect EACCES | any success = critical (threat class 2 evidence forgery); likely clean, verify don't assume |

### WITHIN tolerance — probe once, document, no enforcement

| ID | Vector | Why tolerated |
|----|--------|---------------|
| E-f | wayland-0 UI injection into human seat | blind keystrokes, no feedback loop, no tty visibility from session (ptmx denied), human watches the seat; compositor policy probe only |
| E-g | sibling proxy port borrowing | same-human grants bounded to sibling allowlist; delegation not escalation |
| E-h | deferred workspace poisoning (git hooks, .envrc, authorized_keys if project ⊆ HOME) | agent writing the workspace IS the product; advisory: `doctor` warns project==HOME; spine signal (score decrement, never freeze) on new executables under .git/hooks at keep |
| E-j | loopback deputy sweep (CUPS 631, opencode API, python, libvirt DNS 192.168.122.1:53, …) | enumerate reachable listeners from session; classify exec-yielding (out of tolerance) vs data/print/API (tolerance). opencode API line goes in THREAT_MODEL either way |

### Already closed (do not burn probe time)

systemd user manager + user bus, abstract sockets, sendmmsg/TOCTOU/signal scope,
DNS stub, netlink/mount/fanotify/ptmx, memfd (contained), cron/at (write roots),
cross-session signals (seccomp), cgroup membership EPERM, O_PATH re-open.

## Execution order

1. Local probes: E-a, E-b, E-d, E-e (done: rc=1), E-i, E-j (attempt-only).
2. Fixes in probe-confirmed order: E-a first (code-confirmed), then E-b/E-d per probe.
3. .227: E-c (destructive-adjacent call sanctioned there) + full regression battery.
4. Advisories: `doctor` gains E-e (NOPASSWD) and E-h (project==HOME) warnings.
5. THREAT_MODEL: E-f/E-g/E-j residuals with probe evidence; E-c result either way.
6. Regression: b8 suite, drill gate, `cargo test --workspace`, deny x4.

## Kill gates

- Any fix that breaks the b8 suite's legit-workflow assertions (git, ordinary unix
  sockets, non-ssh loopback) is reverted, not patched around.
- E-b fix must not deny `/run/user/N/wayland-0` or other benign desktop sockets.
- E-d fix must not break the P12 proxy (agent needs its loopback proxy port) or the
  canary honeypot (arbitrary loopback port).
- Probe scripts are attempt-only: they must not create containers, loop devices, or
  modify spine/state. The one exception (E-c `loop-setup`) runs on .227 only.
