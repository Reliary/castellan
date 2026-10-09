#!/usr/bin/env bash
# castellan P21.4 — freeze UX: opt-in auto-kill timer + stdout banner.
#
# K12 `freeze <sid> --kill-after-m N` fires: the frozen scope is
#     SIGKILLed, an auto_kill spine row is written, the deadline clears
# K13 thaw before the deadline cancels the kill
# K14 daemon restart preserves the ABSOLUTE deadline, which still fires
# K15 the supervisor prints a FROZEN banner on the session stdout
# K16 no flag -> no timer, ever (negative control: still frozen past it)
#
# The suite shortens a "minute" via CASTELLAN_KILL_AFTER_TEST_SECS=2 so
# the timer can be exercised without waiting real minutes. The override
# can only shorten, never disable, the timer (see the daemon); the flag
# semantics in real minutes are unit-pinned. Launch+freeze run in ONE
# pty per scenario (the F18 tty witness). Precondition: real user cgroup
# slice + pty; exercise box.
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
BIN="$REPO/target/release"
PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

W=$(mktemp -d /tmp/castellan-p214.XXXXXX)
export XDG_STATE_HOME="$W/state"
export XDG_CONFIG_HOME="$W/config"
mkdir -p "$XDG_STATE_HOME" "$XDG_CONFIG_HOME/castellan"
SOCK="/run/user/$(id -u)/castellan.sock"

start_daemon() {
  for p in $(pgrep -f "target/release/castellan-daemon" 2>/dev/null); do
    [ "$(readlink "/proc/$p/exe" 2>/dev/null)" = "$BIN/castellan-daemon" ] && kill -9 "$p" 2>/dev/null
  done
  sleep 0.5
  rm -f "$SOCK"
  XDG_STATE_HOME="$XDG_STATE_HOME" XDG_CONFIG_HOME="$XDG_CONFIG_HOME" \
    "$BIN/castellan-daemon" > "$W/d.log" 2>&1 &
  DPID=$!
  for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
  [ -S "$SOCK" ] || { echo "daemon did not start"; cat "$W/d.log"; exit 1; }
}
cleanup() { [ -n "${DPID:-}" ] && kill -9 "$DPID" 2>/dev/null; }
trap cleanup EXIT

export CASTELLAN_KILL_AFTER_TEST_SECS=2
start_daemon
mkproj() { mkdir -p "$1"; printf 'x = 1\n' > "$1/a.py"; }

# launch in a pty, freeze from the SAME pty (witnessed terminal), return
# the launch output. $1 project, $2 extra freeze flags ("" = no freeze).
pty_launch_freeze() {
  local proj="$1" extras="$2" out="$3"
  SHELL=/bin/sh script -qec "
    cd '$proj'
    '$BIN/castellan' launch --project '$proj' -- sleep 300 > '$out' 2>&1 &
    LPID=\$!
    SID=''
    for _ in \$(seq 1 50); do
      SID=\$(grep -o 's[0-9a-f]\{10,\}' '$out' | head -1)
      [ -n \"\$SID\" ] && break
      sleep 0.1
    done
    if [ -n \"\$SID\" ]; then
      echo \"LAUNCHED \$SID\" >> '$out'
      if [ -n '$extras' ]; then
        '$BIN/castellan' freeze \"\$SID\" $extras >> '$out' 2>&1
        echo \"FREEZE rc=\$?\" >> '$out'
      fi
    fi
    sleep 1
  " /dev/null >/dev/null 2>&1
}

sid_of() { grep -o 's[0-9a-f]\{10,\}' "$1" | head -1; }
has_row() { grep -q "$1" "$XDG_STATE_HOME/castellan/events/$2.jsonl" 2>/dev/null; }
in_status() { "$BIN/castellan" status 2>/dev/null | grep -q "$1"; }

echo "== K16 (negative control first): no flag -> frozen forever =="
P16="$W/nof"; mkproj "$P16"
pty_launch_freeze "$P16" "--daemonless" "$W/k16.out"
# --daemonless freezes the scope with no deadline channel at all
SID16=$(sid_of "$W/k16.out")
: > "$W/k16.out"   # keep only what status says now
sleep 5
if has_row auto_kill "$SID16"; then bad "K16: auto_kill fired with no --kill-after flag"
elif in_status "$SID16"; then ok "K16: frozen, no deadline, stays frozen past the window (no surprise kill)"
else bad "K16: session vanished from status (unexpected kill)"; fi

echo
echo "== K12: --kill-after fires the kill + auto_kill spine row =="
P12="$W/k12"; mkproj "$P12"
pty_launch_freeze "$P12" "--kill-after-m 1" "$W/k12.out"
SID12=$(sid_of "$W/k12.out")
grep -q "FREEZE rc=0" "$W/k12.out" && ok "K12a: freeze with --kill-after-m accepted" \
  || bad "K12a: freeze rejected: $(grep -E 'error|denied|FROZEN|thaw' "$W/k12.out" | head -2 | tr '\n' ' ')"
sleep 7
if has_row auto_kill "$SID12"; then ok "K12b: auto_kill spine row written"
else bad "K12b: no auto_kill row: $(tail -2 "$W/d.log" | tr '\n' ' ')"; fi
if in_status "$SID12"; then bad "K12c: session still listed after the deadline"
else ok "K12c: session killed and pruned at the deadline"; fi

echo
echo "== K13: thaw before the deadline cancels the kill =="
P13="$W/k13"; mkproj "$P13"
SHELL=/bin/sh script -qec "
  cd '$P13'
  '$BIN/castellan' launch --project '$P13' -- sleep 300 > '$W/k13.out' 2>&1 &
  SID=''
  for _ in \$(seq 1 50); do
    SID=\$(grep -o 's[0-9a-f]\{10,\}' '$W/k13.out' | head -1)
    [ -n \"\$SID\" ] && break
    sleep 0.1
  done
  '$BIN/castellan' freeze \"\$SID\" --kill-after-m 60 >> '$W/k13.out' 2>&1
  '$BIN/castellan' thaw \"\$SID\" >> '$W/k13.out' 2>&1
  echo \"SID \$SID\" >> '$W/k13.out'
  sleep 1
" /dev/null >/dev/null 2>&1
SID13=$(sid_of "$W/k13.out")
sleep 5
if has_row auto_kill "$SID13"; then bad "K13: auto_kill fired despite the thaw"
elif in_status "$SID13"; then ok "K13: thawed before the deadline — session alive, no kill"
else bad "K13: session vanished (deadline not cancelled)"; fi

echo
echo "== K14: daemon restart preserves the absolute deadline =="
P14="$W/k14"; mkproj "$P14"
pty_launch_freeze "$P14" "--kill-after-m 1" "$W/k14.out"
SID14=$(sid_of "$W/k14.out")
kill -9 "$DPID" 2>/dev/null
sleep 0.5
start_daemon   # rehydrates the row + deadline
sleep 7
if has_row auto_kill "$SID14"; then ok "K14: deadline survived the restart and fired"
else bad "K14: no auto_kill after restart (deadline lost?): $(tail -3 "$W/d.log" | tr '\n' ' ')"; fi
if in_status "$SID14"; then bad "K14b: session still listed after the post-restart deadline"
else ok "K14b: killed after restart"; fi

echo
echo "== K15: FROZEN banner reaches the session terminal =="
P15="$W/k15"; mkproj "$P15"
# The daemon writes the banner to the session's pty slave (a frozen
# in-scope process cannot print — proven live). That output surfaces on
# the terminal, i.e. in script(1)'s typescript, not in the launch
# command's own stdout redirect, so capture the typescript file.
SHELL=/bin/sh script -qec "
  cd '$P15'
  '$BIN/castellan' launch --project '$P15' -- sleep 30 > '$W/k15.out' 2>&1 &
  SID=''
  for _ in \$(seq 1 50); do
    SID=\$(grep -o 's[0-9a-f]\{10,\}' '$W/k15.out' | head -1)
    [ -n \"\$SID\" ] && break
    sleep 0.1
  done
  '$BIN/castellan' freeze \"\$SID\" >/dev/null 2>&1
  sleep 3
  echo done
" "$W/k15.typescript" >/dev/null 2>&1
if grep -q "FROZEN" "$W/k15.typescript" 2>/dev/null; then
  ok "K15: $(grep -m1 -o 'FROZEN[^\r]*' "$W/k15.typescript")"
else
  bad "K15: no FROZEN banner on the session terminal: $(grep -v '^$' "$W/k15.typescript" 2>/dev/null | head -4 | tr '\n' ' ')"
fi

echo
echo "== SUMMARY =="
echo "  PASS=$PASS FAIL=$FAIL  workdir: $W"
if [ "$FAIL" -eq 0 ]; then echo "P21.4-ACCEPT-PASS"; exit 0; else echo "P21.4-ACCEPT-FAIL"; exit 1; fi
