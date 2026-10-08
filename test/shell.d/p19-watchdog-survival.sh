#!/usr/bin/env bash
# castellan P19 — watchdog survival probe.
#
# Open question (2026-10-08): the fail-closed-on-daemon-loss watchdog lives in
# the launcher supervisor, not the daemon. It therefore only protects
# `castellan launch` sessions, and only while the supervisor is alive. The
# supervisor is the launcher's child; if its controlling terminal closes, it
# may get SIGHUP and die, silently dropping the fail-closed promise.
#
# This is a PROBE: it reports what the running kernel/build actually does.
# Run it on a box with a real user cgroup slice (the exercise box), not the
# dev box. CASTELLAN_BIN overrides the target directory.
#
# Arms:
#   A. daemon dies while a launch session runs -> session must freeze (built).
#   B. the launcher's terminal closes, THEN the daemon dies -> does the
#      supervisor/watchdog survive to freeze? (this is the open question)

set -u

BIN="${CASTELLAN_BIN:-$(cd "$(dirname "$0")/../.." && pwd)/target/release}"
UID_=$(id -u)
SOCK="${XDG_RUNTIME_DIR:-/run/user/$UID_}/castellan.sock"
SLICE="/sys/fs/cgroup/user.slice/user-$UID_.slice/user@$UID_.service/castellan.slice"
PASS=0; FAIL=0; NOTE=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
note() { echo "  NOTE: $1"; NOTE=$((NOTE+1)); }

DAPID=""
cleanup() {
  [[ -n "$DAPID" ]] && kill "$DAPID" 2>/dev/null
  pkill -9 -f "castellan-daemon" 2>/dev/null
  pkill -9 -f "castellan launch -- sleep" 2>/dev/null
  rm -f "$SOCK"
}
trap cleanup EXIT

proc_alive() { [[ -d "/proc/$1" ]]; }
frozen() { grep -q '^frozen 1$' "$SLICE/$1.scope/cgroup.events" 2>/dev/null; }

echo "== pre-clean =="
pkill -9 -f "castellan-daemon" 2>/dev/null
rm -f "$SOCK"
if [[ -d "$SLICE" ]]; then
  for d in "$SLICE"/*.scope; do
    [[ -d "$d" ]] || continue
    for pid in $(cat "$d/cgroup.procs" 2>/dev/null); do kill -9 "$pid" 2>/dev/null; done
    rmdir "$d" 2>/dev/null
  done
fi
sleep 0.3

start_daemon() {
  pkill -9 -f "castellan-daemon" 2>/dev/null
  rm -f "$SOCK"
  sleep 0.3
  "$BIN/castellan-daemon" >/dev/null 2>&1 &
  DAPID=$!
  # Wait on a REAL connection, not on the socket file existing: a stale
  # socket from a previous arm satisfies `-S` instantly, which made the
  # first version of this probe race a not-yet-bound daemon (harness bug,
  # not a product defect). `castellan status` only exits 0 when connected.
  for _ in $(seq 1 50); do
    "$BIN/castellan" status >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  return 1
}

echo
echo "===== ARM A: daemon loss with terminal intact (the built property) ====="
start_daemon || { bad "daemon failed to start"; exit 1; }
mkdir -p /tmp/cast-p19
# launch a long-lived session under its own pty; keep it attached.
setsid script -qec "$BIN/castellan launch --project /tmp/cast-p19 -- sleep 300" /dev/null \
  >/tmp/cast-p19/armA.log 2>&1 &
SCRIPT_A=$!
sleep 3
SID_A=$(grep -oE 's[0-9a-f]{16,24}' /tmp/cast-p19/armA.log | head -1)
SUP_A=$(pgrep -f "castellan launch --project /tmp/cast-p19" | head -1)
if [[ -n "$SID_A" && -n "$SUP_A" ]]; then
  ok "launch session active (sid=$SID_A sup=$SUP_A)"
else
  bad "could not establish launch session (sid=$SID_A sup=$SUP_A)"; cat /tmp/cast-p19/armA.log
fi
frozen "$SID_A" && bad "session frozen before daemon death (unexpected)" || ok "session not frozen with daemon alive"

echo "  -- killing daemon, waiting >grace (5s) --"
kill -9 "$DAPID" 2>/dev/null; wait "$DAPID" 2>/dev/null
for _ in $(seq 1 20); do frozen "$SID_A" && break; sleep 0.5; done
if frozen "$SID_A"; then ok "ARM A: supervisor watchdog froze the session on daemon loss"
else bad "ARM A: session NOT frozen after daemon loss (watchdog did not fire)"; fi
kill -9 "$SCRIPT_A" "$SUP_A" 2>/dev/null
pkill -9 -f "sleep 300" 2>/dev/null
sleep 0.5

echo
echo "===== ARM B: agent survives its terminal, THEN daemon loss (the open question) ====="
# An agent that ignores SIGHUP (or otherwise outlives its tty) is reparented,
# not killed, when the launcher's terminal closes. The watchdog lives in the
# launcher supervisor, which dies with the terminal — so the orphaned agent
# has no guard left. This arm proves or disproves that.
start_daemon || { bad "daemon (B) failed to start"; exit 1; }
setsid script -qec "$BIN/castellan launch --project /tmp/cast-p19 -- python3 -c 'import signal,time; signal.signal(signal.SIGHUP, signal.SIG_IGN); time.sleep(300)'" \
  /dev/null >/tmp/cast-p19/armB.log 2>&1 &
sleep 3
SID_B=$(grep -oE 's[0-9a-f]{16,24}' /tmp/cast-p19/armB.log | head -1)
AGENT_B=$(pgrep -f 'time.sleep' | tail -1)
SCRIPT_B=$(pgrep -f 'script -qec' | head -1)
[[ -n "$SID_B" && -n "$AGENT_B" ]] && ok "launch session active (sid=$SID_B agent=$AGENT_B)" \
  || { bad "could not establish session B"; cat /tmp/cast-p19/armB.log; }

echo "  -- closing the launcher's terminal (SIGKILL the pty wrapper) --"
kill -9 "$SCRIPT_B" 2>/dev/null
sleep 2
if [[ -n "$AGENT_B" ]] && proc_alive "$AGENT_B"; then
  note "agent SURVIVED the terminal close (ignores SIGHUP) and is now orphaned"
  ORPHAN=1
else
  note "agent died with the terminal (no orphan to protect)"
  ORPHAN=0
fi

echo "  -- killing daemon, waiting >grace --"
kill -9 "$DAPID" 2>/dev/null
for _ in $(seq 1 20); do frozen "$SID_B" && break; sleep 0.5; done
if [[ "$ORPHAN" == "1" ]]; then
  if frozen "$SID_B"; then
    ok "ARM B: orphaned agent froze on daemon loss (guard reached it)"
  else
    bad "ARM B GAP: orphaned agent survived terminal close and ran UNFROZEN after daemon loss"
  fi
else
  note "ARM B: no orphan — terminal close removed the agent, so nothing to freeze"
fi
pkill -9 -f 'time.sleep' 2>/dev/null

echo
echo "RESULT: $PASS passed, $FAIL failed, $NOTE notes"
exit $((FAIL > 0))
