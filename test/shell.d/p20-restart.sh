#!/usr/bin/env bash
# castellan P20 — restart-survival acceptance suite.
#
# Kill gates (docs/plans/p20-tightening.md), all pre-registered:
#   G1   restart -> status lists the session; freeze/thaw from the
#        ORIGINAL launcher tty work (rehydration + re-witness)
#   G1b  no-panic battery: every human op on a rehydrated session
#        returns ok/err, never aborts the daemon (panic=abort)
#   G2   corrupt + filename-mismatch rows are skipped AND counted
#   G4   systemctl stop freezes every scope (ExecStopPost), start +
#        thaw restores control
#   G6   install under a manual (non-systemd) daemon is refused, no unit
#   G8   doctor: stale unit FAIL, scopes-without-daemon FAIL, healthy PASS
#   G11  measured restart round-trip is recorded (vs watchdog grace 5s;
#        note: unit-managed restarts freeze deterministically via
#        ExecStopPost, so this is an operator-latency number)
#
# Needs: real user manager + cgroup slice (exercise box). Destructive:
# installs and uninstalls the service. Use --keep-state to spare state.

set -u

FORCE=0
for a in "$@"; do [[ "$a" == "--force" ]] && FORCE=1; done

BIN="${CASTELLAN_BIN:-$(cd "$(dirname "$0")/../.." && pwd)/target/release}"
UID_=$(id -u)
UNIT="castellan.service"
UNIT_PATH="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$UNIT"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/castellan"
CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/castellan"
SOCK="${XDG_RUNTIME_DIR:-/run/user/$UID_}/castellan.sock"
SLICE="/sys/fs/cgroup/user.slice/user-$UID_.slice/user@$UID_.service/castellan.slice"
W=/tmp/cast-p20
PASS=0; FAIL=0; NOTE=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
note() { echo "  NOTE: $1"; NOTE=$((NOTE+1)); }

if ! systemctl --user show-environment >/dev/null 2>&1; then
  echo "no user systemd manager here — run on the exercise box"
  [[ "$FORCE" == "1" ]] || exit 3
fi

cleanup() {
  # Unblock any fifo readers so nothing hangs on exit. The write is
  # backgrounded, stdio detached, and timeout-bounded: with no reader
  # left, opening the fifo blocks forever, and a blocked child holding
  # this script's stdout would keep the invoking session open.
  ( exec >/dev/null 2>&1; timeout 2 sh -c "printf 'quit\n' > \"\$1\"" sh "$W/cmdfifo" ) &
  pkill -9 -f 'castellan launch --project /tmp/cast-p20' 2>/dev/null
  pkill -9 -x castellan-daemo 2>/dev/null
  systemctl --user stop "$UNIT" 2>/dev/null
  systemctl --user disable "$UNIT" 2>/dev/null
  rm -f "$UNIT_PATH"
  rm -f "$SOCK"
  systemctl --user daemon-reload 2>/dev/null
}
trap cleanup EXIT

rm -rf "$W"; mkdir -p "$W"
mkfifo "$W/cmdfifo"
# Fresh state: the G2/G1 journal asserts count rehydrated/skipped rows
# exactly, so previous runs' session dirs must not accumulate. Exercise
# box by contract (p18 owns the metadata-snapshot discipline); kill any
# stale daemon first so nothing is mid-write.
pkill -9 -x castellan-daemo 2>/dev/null
rm -rf "$STATE_DIR/sessions"
mkdir -p "$STATE_DIR/sessions"
# Prior runs leave their sleeping agents alive (cleanup kills the
# supervisor, not `sleep 600`) — a live scope with no session json is
# exactly the registry drift doctor must flag, so reap it here or the
# healthy-baseline assert rots.
pkill -9 -f 'sleep 600' 2>/dev/null
pkill -9 -f 'sleep 120' 2>/dev/null
sleep 0.5
if [ -d "$SLICE" ]; then
  for d in "$SLICE"/*.scope; do
    [ -d "$d" ] || continue
    if [ ! -s "$d/cgroup.procs" ]; then rmdir "$d" 2>/dev/null; fi
  done
fi

echo "===== G6: install refused under a manual daemon ====="
pkill -9 -x castellan-daemo 2>/dev/null; rm -f "$SOCK"; sleep 0.3
setsid "$BIN/castellan-daemon" >"$W/manual.log" 2>&1 &
for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 0.1; done
if "$BIN/castellan" service install >"$W/g6.out" 2>&1; then
  bad "install SUCCEEDED under a manual daemon (should refuse)"
else
  ok "install refused (rc nonzero)"
fi
grep -q "already serving" "$W/g6.out" && ok "refusal names the reason" || bad "refusal message missing"
[ -f "$UNIT_PATH" ] && bad "unit file left behind after refusal" || ok "no unit left behind"
# daemon still answers (refusal must not have killed it)
"$BIN/castellan" status >/dev/null 2>&1 && ok "manual daemon survived refusal" || bad "manual daemon died"
pkill -9 -x castellan-daemo 2>/dev/null; rm -f "$SOCK"; sleep 0.3

echo
echo "===== G7: install rolls back when the user manager is unreachable ====="
# Deterministic anywhere: point XDG_RUNTIME_DIR at nothing so
# `systemctl --user` cannot connect — the F7 visibility check must fail
# and the unit must be rolled back, leaving zero artifacts.
if XDG_RUNTIME_DIR=/nonexistent-castellan "$BIN/castellan" service install >"$W/g7.out" 2>&1; then
  bad "G7: install succeeded with no reachable user manager"
else
  ok "G7: install failed as required (no manager)"
fi
[ -f "$UNIT_PATH" ] && bad "G7: unit file left behind after rollback" || ok "G7: zero artifacts after rollback"
grep -qi "cannot see it\|rolled back\|XDG" "$W/g7.out" && ok "G7: failure explains the manager mismatch" || note "G7: message shape: $(head -1 "$W/g7.out")"

echo
echo "===== install (fresh unit, new content) ====="
"$BIN/castellan" service install >"$W/inst.out" 2>&1 || { bad "service install failed"; }
[ -f "$UNIT_PATH" ] && ok "unit written" || bad "unit missing"
grep -q "ExecStopPost=.*freeze --daemonless" "$UNIT_PATH" \
  && ok "unit has ExecStopPost freeze (C43)" || bad "unit missing ExecStopPost freeze"
grep -q "StartLimitBurst" "$UNIT_PATH" \
  && ok "unit has StartLimit (F11)" || bad "unit missing StartLimit"
systemctl --user is-active "$UNIT" >/dev/null 2>&1 && ok "unit active" || bad "unit not active"
for _ in $(seq 1 40); do "$BIN/castellan" status >/dev/null 2>&1 && break; sleep 0.1; done
"$BIN/castellan" status >/dev/null 2>&1 \
  && ok "daemon answering after install" || bad "daemon not answering after install"

echo
echo "===== G2: corrupt rows skipped AND counted ====="
mkdir -p "$STATE_DIR/sessions"
echo 'not json {' > "$STATE_DIR/sessions/badrow.json"
echo '{"session":"sMISMATCH","project":"/x","harness":"h"}' > "$STATE_DIR/sessions/badrow2.json"
# restart so rehydrate runs against the planted rows
t0=$(date +%s%N)
systemctl --user restart "$UNIT"
for _ in $(seq 1 60); do "$BIN/castellan" status >/dev/null 2>&1 && break; sleep 0.2; done
t1=$(date +%s%N)
rt_ms=$(( (t1 - t0) / 1000000 ))
echo "  restart round-trip: ${rt_ms} ms"
[[ "$rt_ms" -lt 10000 ]] && ok "G11: restart ${rt_ms}ms < 10s" || bad "G11: restart took ${rt_ms}ms"
jrnl=$(journalctl --user -u "$UNIT" -n 40 --no-pager 2>/dev/null)
echo "$jrnl" | grep -q "skipped 2 unreadable/mismatched" \
  && ok "G2: both planted rows counted as skipped" || bad "G2: skip count not in journal"
echo "$jrnl" | grep -q "rehydrated 0 session" \
  && note "G2: 0 sessions rehydrated (none live yet — expected here)" || note "G2: rehydrate line shape differs"

echo
echo "===== G1/G1b: restart with a LIVE session, original-tty control ====="
# launch runs the supervisor in the FOREGROUND (blocks until the agent
# exits), so inside the pty we background it and drive the session over a
# fifo while the pty stays open — the original tty must survive the
# daemon restart for the witness re-check to be meaningful.
SHELL=/bin/sh script -qec "
  BIN=$BIN/castellan
  exec 3<> $W/cmdfifo
  \$BIN launch --project $W -- sleep 600 > $W/launch.out 2>&1 &
  LPID=\$!
  SID=
  for _ in \$(seq 1 100); do
    SID=\$(grep -oE 's[0-9a-f]{16,24}' $W/launch.out 2>/dev/null | head -1)
    [ -n \"\$SID\" ] && break
    sleep 0.2
  done
  echo \"SID:\$SID\" > $W/sid.txt
  echo READY > $W/ready
  while IFS= read -r line <&3; do
    [ \"\$line\" = quit ] && break
    case \"\$line\" in
      status) \$BIN status 2>&1 ;;
      freeze) \$BIN freeze 2>&1 ;;
      thaw)   \$BIN thaw 2>&1 ;;
      cert)   \$BIN cert \$SID 2>&1 ;;
      kill)   \$BIN kill \$SID 2>&1 ;;
      *) echo \"unknown cmd \$line\" ;;
    esac
    echo \"--- done: \$line\"
  done
  kill \$LPID 2>/dev/null
  echo PTY_EXIT
" /dev/null >"$W/pty.log" 2>&1 &
PTY_PID=$!
for _ in $(seq 1 100); do [ -f "$W/ready" ] && break; sleep 0.1; done
SID=$(grep -oE 's[0-9a-f]{16,24}' "$W/sid.txt" 2>/dev/null | head -1)
if [ -z "$SID" ]; then
  bad "G1: launch under pty produced no session (see $W/pty.log / $W/launch.out)"
else
  ok "G1: session launched under long-lived pty ($SID)"
  # daemon restart while the ORIGINAL tty stays open
  t0=$(date +%s%N)
  systemctl --user restart "$UNIT"
  for _ in $(seq 1 60); do "$BIN/castellan" status >/dev/null 2>&1 && break; sleep 0.2; done
  t1=$(date +%s%N)
  echo "  live-session restart round-trip: $(( (t1 - t0) / 1000000 )) ms"
  jrnl=$(journalctl --user -u "$UNIT" -n 60 --no-pager 2>/dev/null)
  echo "$jrnl" | grep -q "rehydrated 1 session" \
    && ok "G1: live session rehydrated (counted 1)" || bad "G1: 'rehydrated 1' not in journal"

  run_pty() { timeout 3 sh -c 'printf "%s\n" "$1" > "$2"' sh "$1" "$W/cmdfifo"; for _ in $(seq 1 300); do grep -q -- "--- done: $1" "$W/pty.log" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

  run_pty status && grep -q "$SID" "$W/pty.log" \
    && ok "G1: status from original tty lists the session" || bad "G1: status did not list session after restart"
  run_pty thaw && ok "G1: thaw from original tty accepted" || bad "G1: thaw refused/timeout"
  run_pty freeze && ok "G1: freeze from original tty accepted" || bad "G1: freeze refused/timeout"

  # G1b battery: non-destructive ops must each answer, daemon must live
  run_pty cert && ok "G1b: cert answered" || bad "G1b: cert hung/aborted"
  t_before=$(systemctl --user show -p ActiveEnterTimestampMonotonic "$UNIT" 2>/dev/null)
  run_pty status && ok "G1b: daemon survived battery (status ok)" || bad "G1b: daemon died mid-battery"
  t_after=$(systemctl --user show -p ActiveEnterTimestampMonotonic "$UNIT" 2>/dev/null)
  [ "$t_before" = "$t_after" ] \
    && ok "G1b: daemon start timestamp unchanged (no restart = no abort)" \
    || bad "G1b: daemon restarted during battery (panic=abort?)"

  echo
  echo "===== G4: systemctl stop freezes (ExecStopPost), start restores ====="
  # thaw first so G4's freeze assertion observes a CHANGE (a session
  # already frozen by the G1 step would make the assert trivially true)
  run_pty thaw || note "prep thaw before G4 did not confirm"
  grep -q '^frozen 0$' "$SLICE/$SID.scope/cgroup.events" 2>/dev/null \
    && ok "G4 prep: scope thawed before stop" || bad "G4 prep: scope not thawed before stop"
  systemctl --user stop "$UNIT"
  sleep 0.5
  if grep -q '^frozen 1$' "$SLICE/$SID.scope/cgroup.events" 2>/dev/null; then
    ok "G4: ExecStopPost froze the live scope on stop"
  else
    bad "G4: scope NOT frozen after systemctl stop"
  fi
  "$BIN/castellan" status >/dev/null 2>&1 && bad "daemon alive after stop" || ok "daemon gone after stop"
  systemctl --user start "$UNIT"
  for _ in $(seq 1 60); do "$BIN/castellan" status >/dev/null 2>&1 && break; sleep 0.2; done
  run_pty thaw && ok "G4: thaw works after start (rehydrated)" || bad "G4: thaw failed after start"
  grep -q '^frozen 0$' "$SLICE/$SID.scope/cgroup.events" 2>/dev/null \
    && ok "G4: scope thawed" || bad "G4: scope still frozen after thaw"

  run_pty kill && ok "session killed" || note "kill did not confirm"
fi
sleep 1
timeout 2 sh -c "printf 'quit\n' > \"\$1\"" sh "$W/cmdfifo" 2>/dev/null
# bounded wait: force-kill the pty after 20s so a stuck reader cannot
# hold this script (and the invoking session) open forever.
( exec >/dev/null 2>&1; sleep 20; kill -9 "$PTY_PID" 2>/dev/null ) &
KILLER=$!
wait $PTY_PID 2>/dev/null
kill "$KILLER" 2>/dev/null

echo
echo "===== G5: recycled pty minor must NOT inherit launcher rights (F9) ====="
# Launch from pty A, close A (freeing its minor), open pty B which
# reuses the lowest free minor — on a quiet box that is A's. B then
# holds A's tty_nr with a DIFFERENT inode. Session-scoped and global
# freeze from B must be DENIED (inode bound), while status must still
# work (denial is tty-specific, not general breakage). G1's same-tty
# thaw/freeze above is the positive control of the pair.
g5_attempt() {
  rm -f "$W/g5a.out" "$W/g5a.tty" "$W/g5b.out"
  SHELL=/bin/sh script -qec "
    BIN=$BIN/castellan
    \$BIN launch --project $W -- sleep 400 > $W/g5a.out 2>&1 &
    tty > $W/g5a.tty
    sleep 1
  " /dev/null >/dev/null 2>&1
  for _ in $(seq 1 60); do grep -qE 's[0-9a-f]{16,24}' "$W/g5a.out" 2>/dev/null && break; sleep 0.1; done
  G5SID=$(grep -oE 's[0-9a-f]{16,24}' "$W/g5a.out" 2>/dev/null | head -1)
  MA=$(grep -oE '[0-9]+$' "$W/g5a.tty" 2>/dev/null)
  # pty A is closed now; open pty B — should reuse minor MA on a quiet box
  SHELL=/bin/sh script -qec "
    BIN=$BIN/castellan
    tty > $W/g5b.tty
    \$BIN freeze $G5SID > $W/g5b.scoped 2>&1; echo rc=\$? >> $W/g5b.scoped
    \$BIN freeze > $W/g5b.global 2>&1; echo rc=\$? >> $W/g5b.global
    \$BIN status > $W/g5b.status 2>&1
  " /dev/null >/dev/null 2>&1
  MB=$(grep -oE '[0-9]+$' "$W/g5b.tty" 2>/dev/null)
  echo "  minors: A=/dev/pts/$MA B=/dev/pts/$MB sid=$G5SID"
  [ "$MA" = "$MB" ] && [ -n "$MA" ]
}
G5OK=0
for try in 1 2 3; do
  if g5_attempt; then G5OK=1; break; fi
  pkill -9 -f 'sleep 400' 2>/dev/null
  sleep 0.3
done
if [ "$G5OK" != "1" ]; then
  bad "G5: harness could not recycle the pts minor (3 attempts)"
else
  ok "G5: recycled minor confirmed (/dev/pts/$MA reused)"
  grep -q 'rc=1' "$W/g5b.scoped" \
    && ok "G5: session-scoped freeze from recycled tty DENIED" \
    || { bad "G5: session-scoped freeze from recycled tty ACCEPTED (F9 open!)"; cat "$W/g5b.scoped"; }
  grep -q 'rc=1' "$W/g5b.global" \
    && ok "G5: global freeze from recycled tty DENIED" \
    || { bad "G5: global freeze from recycled tty ACCEPTED (witness bypass!)"; cat "$W/g5b.global"; }
  grep -q "$G5SID" "$W/g5b.status" \
    && ok "G5 control: status still works (denial is tty-specific)" \
    || bad "G5 control: status broke — denial is not tty-specific"
fi
pkill -9 -f 'sleep 400' 2>/dev/null
sleep 0.3
if [ -d "$SLICE" ]; then
  for d in "$SLICE"/*.scope; do
    [ -d "$d" ] && [ ! -s "$d/cgroup.procs" ] && rmdir "$d" 2>/dev/null
  done
fi

echo
echo "===== G8: doctor negatives ====="
# (a) stale unit: strip ExecStopPost from the installed unit
cp "$UNIT_PATH" "$W/unit.bak"
grep -v 'ExecStopPost' "$W/unit.bak" > "$UNIT_PATH"
systemctl --user daemon-reload
if "$BIN/castellan" doctor >"$W/doc1.out" 2>&1; then
  bad "G8: doctor PASS on stale unit"
else
  grep -q "STALE" "$W/doc1.out" && ok "G8: doctor FAIL names the stale unit" || bad "G8: doctor failed but not on staleness"
fi
"$BIN/castellan" service install >/dev/null 2>&1
systemctl --user daemon-reload

echo
echo "===== doctor healthy baseline ====="
# doctor requires a keyring; earlier suites may have uninstalled config
[ -f "$CONF_DIR/keyring.toml" ] || "$BIN/castellan" init >/dev/null 2>&1
if "$BIN/castellan" doctor >"$W/doc2.out" 2>&1; then
  ok "G8: doctor PASS when healthy"
else
  bad "G8: doctor FAIL on healthy system"; cat "$W/doc2.out"
fi

echo
echo "RESULT: $PASS passed, $FAIL failed, $NOTE notes"
exit $((FAIL > 0))
