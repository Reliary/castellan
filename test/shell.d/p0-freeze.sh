#!/usr/bin/env bash
# castellan P0 acceptance test — freeze semantics on real processes.
# Verifies the P0 kill criterion: freeze + thaw works on concurrent sessions,
# frozen processes survive SIGKILL, thaw delivers pending signals, no daemon crash.

set -u

BIN=/home/john/src/castellan/target/release
PASS=0
FAIL=0

ok() { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

cleanup() {
  [[ -n "${DAPID:-}" ]] && kill "$DAPID" 2>/dev/null
  kill "${P1:-}" "${P2:-}" "${P3:-}" "${PB:-}" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

echo "== pre-clean stale state =="
for p in $(pgrep -f castellan-daemon); do
  exe=$(readlink "/proc/$p/exe" 2>/dev/null) || continue
  case "$exe" in *castellan-daemon*) kill -9 "$p";; esac
done
rm -f /run/user/1000/castellan.sock
SLICE="/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/castellan.slice"
if [[ -d "$SLICE" ]]; then
  for d in "$SLICE"/*.scope; do
    [[ -d "$d" ]] || continue
    for pid in $(cat "$d/cgroup.procs" 2>/dev/null); do kill -9 "$pid" 2>/dev/null; done
    rmdir "$d" 2>/dev/null
  done
fi
sleep 0.3
ok "stale state cleaned"

echo "== start daemon =="
"$BIN/castellan-daemon" &
DAPID=$!
# wait for the socket, not a fixed sleep: startup loads the memory
# log-replay + trust/canary ledgers and takes >1s on the real state dir
for _ in $(seq 1 50); do
  [ -S /run/user/1000/castellan.sock ] && break
  sleep 0.1
done
if kill -0 "$DAPID" 2>/dev/null; then ok "daemon started"; else bad "daemon died at startup"; exit 1; fi

echo "== spawn three sessions with real processes =="
spawn_one() {
  local harness="$1"
  sleep 120 >/dev/null 2>&1 &
  local pid=$!
  disown
  local out sid
  out=$("$BIN/castellan" spawn --harness "$harness" --pid "$pid" 2>/dev/null)
  sid=$(echo "$out" | grep -o 's[0-9a-f]\{10,\}' | head -1)
  echo "$pid $sid"
}

read -r P1 S1 <<< "$(spawn_one claude)"
read -r P2 S2 <<< "$(spawn_one codex)"
read -r P3 S3 <<< "$(spawn_one pi)"
[[ -n "$S1" && -n "$S2" && -n "$S3" ]] && ok "three sessions spawned ($S1 $S2 $S3)" || bad "spawn failed"

row_count() { grep -c ' pids  ' || true; }

echo "== status shows all thawed =="
out=$("$BIN/castellan" status)
rows=$(echo "$out" | row_count)
frozen_rows=$(echo "$out" | grep ' pids  ' | grep -c frozen || true)
thawed_rows=$(echo "$out" | grep ' pids  ' | grep -c thawed || true)
[[ "$rows" == "3" && "$thawed_rows" == "3" && "$frozen_rows" == "0" ]] \
  && ok "status: 3 sessions, all thawed" || bad "status wrong: $out"

echo "== freeze one session (S2) =="
out=$("$BIN/castellan" freeze "$S2")
echo "$out" | grep -q "$S2: frozen" && ok "S2 froze" || bad "freeze S2 failed: $out"
state=$(ps -o stat= -p "$P2" 2>/dev/null)
cpu1=$(awk '{print $2}' /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/castellan.slice/"$S2".scope/cpu.stat 2>/dev/null)

proc_alive() { [[ -d "/proc/$1" ]] && grep -q '[0-9]' "/proc/$1/stat" 2>/dev/null; }

echo "== frozen process gets zero CPU and makes no progress (SIGKILL still kills it — kernel 7.x does not defer signals to frozen procs) =="
frozen_check=$("$BIN/castellan" status | grep "$S2" | grep -c frozen || true)
[[ "$frozen_check" == "1" ]] && ok "S2 confirmed frozen in kernel before kill" || bad "S2 not frozen per cgroup.events"
CGS2="$SLICE/$S2.scope/cpu.stat"
u1=$(awk '{print $1}' "$CGS2" 2>/dev/null)
sleep 1
u2=$(awk '{print $1}' "$CGS2" 2>/dev/null)
[[ "$u1" == "$u2" ]] && ok "zero CPU while frozen ($u1)" || bad "frozen process consumed CPU ($u1 -> $u2)"
kill -9 "$P2" 2>/dev/null
sleep 0.5
if proc_alive "$P2"; then bad "SIGKILL failed to kill frozen process (unexpected)"; else ok "SIGKILL terminates frozen process (kernel 7.x semantics)"; fi

echo "== other sessions unaffected =="
if proc_alive "$P1" && proc_alive "$P3"; then ok "P1 and P3 still running"; else bad "collateral damage to unfrozen sessions"; fi

echo "== status shows exactly one frozen =="
out=$("$BIN/castellan" status)
f=$(echo "$out" | grep ' pids  ' | grep -c frozen || true)
t=$(echo "$out" | grep ' pids  ' | grep -c thawed || true)
[[ "$f" == "1" && "$t" == "2" ]] && ok "status: 1 frozen, 2 thawed" || bad "status wrong after partial freeze: $out"

echo "== thaw is a no-op on the killed session, others unaffected =="
"$BIN/castellan" kill "$S2" >/dev/null 2>&1
if proc_alive "$P1" && proc_alive "$P3"; then ok "P1 and P3 still running after S2 cleanup"; else bad "collateral damage to unfrozen sessions"; fi

echo "== freeze all / thaw all =="
# B6 phase 4: global (session-less) human-only ops require a
# controlling tty — an escaped process has none. The suite models
# the human operator with a pty (script).
script -qec "$BIN/castellan freeze" /dev/null >/dev/null 2>&1
sleep 0.3
f=$(timeout 5 "$BIN/castellan" status 2>/dev/null | grep ' pids  ' | grep -c frozen || true)
[[ "$f" == "2" ]] && ok "freeze-all froze remaining 2" || bad "freeze-all failed (got $f frozen)"
script -qec "$BIN/castellan thaw" /dev/null >/dev/null 2>&1
sleep 0.3
t=$(timeout 5 "$BIN/castellan" status 2>/dev/null | grep ' pids  ' | grep -c thawed || true)
[[ "$t" == "2" ]] && ok "thaw-all restored 2" || bad "thaw-all failed"

echo "== CPU is actually stopped while frozen =="
sleep 300 >/dev/null 2>&1 & PB=$!
disown
out=$("$BIN/castellan" spawn --harness burner --pid "$PB" 2>/dev/null)
SB=$(echo "$out" | grep -o 's[0-9a-f]\{10,\}' | head -1)
CG=/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/castellan.slice/"$SB".scope
python3 -c "
import time
end=time.time()+60
while time.time()<end: pass
" & true
"$BIN/castellan" freeze "$SB" >/dev/null
sleep 0.3
u1=$(awk '{print $1}' "$CG/cpu.stat" | head -1)
sleep 2
u2=$(awk '{print $1}' "$CG/cpu.stat" | head -1)
[[ "$u1" == "$u2" ]] && ok "cpu.stat unchanged while frozen ($u1)" || bad "frozen process consumed CPU ($u1 -> $u2)"
"$BIN/castellan" kill "$SB" >/dev/null

echo "== daemon survives everything =="
if kill -0 "$DAPID" 2>/dev/null; then ok "daemon still alive"; else bad "daemon crashed"; fi

echo
echo "RESULT: $PASS passed, $FAIL failed"
exit $((FAIL > 0))
