#!/usr/bin/env bash
# P2 acceptance: overlayfs undo substrate.
# Needs a real desktop Linux session (user cgroup slice, userns, overlayfs).
set -u
BIN=/home/john/src/castellan/target/release/castellan
DAEMON=/home/john/src/castellan/target/release/castellan-daemon
export XDG_STATE_HOME=/tmp/cast-p2/state
PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2' got '$3')"; fi }

echo "== pre-clean stale state =="
pkill -x castellan-daemon 2>/dev/null; sleep 0.3
rm -rf /tmp/cast-p2/state /run/user/$(id -u)/castellan.sock
mkdir -p "$XDG_STATE_HOME"
ok "stale state cleaned"

echo "== start daemon =="
"$DAEMON" >/tmp/cast-p2/daemon.log 2>&1 &
DPID=$!
# wait for the socket, not a fixed sleep (startup >1s on real state dir)
for _ in $(seq 1 50); do
  [ -S /run/user/1000/castellan.sock ] && break
  sleep 0.1
done
"$BIN" status >/dev/null 2>&1 && ok "daemon started" || { bad "daemon not responding"; exit 1; }

W=$(mktemp -d /tmp/cast-p2/proj.XXXX)
echo original > "$W/keep.txt"
echo v1 > "$W/edit.txt"

echo "== UNDO: session writes are invisible to the real project =="
OUT=$("$BIN" launch --project "$W" --undo -- bash -c "
  echo agent-was-here > new.txt
  rm keep.txt
  echo v2 > edit.txt
" 2>&1)
S=$(grep -o 's[0-9a-f]\{20\}' <<<"$OUT" | head -1)
[ -n "$S" ] && ok "undoable session $S launched" || bad "no session id in launch output"
[ -f "$W/new.txt" ] && bad "new.txt leaked into real project" || ok "no leak: new.txt absent in project"
check "keep.txt survived in project" "original" "$(cat "$W/keep.txt")"
check "edit.txt untouched in project" "v1" "$(cat "$W/edit.txt")"

echo "== DIFF: upper layer records exactly what the agent did =="
DIFF_OUT=$("$BIN" diff "$S")
grep -q "keep.txt" <<<"$DIFF_OUT" && ok "diff names deleted file" || bad "diff missing deletion"
grep -q "new.txt" <<<"$DIFF_OUT" && ok "diff names created file" || bad "diff missing creation"
grep -q "edit.txt" <<<"$DIFF_OUT" && ok "diff names modified file" || bad "diff missing modification"
N=$(grep -c "^[+-d]" <<<"$DIFF_OUT")
[ "$N" -ge 3 ] && ok "diff lists >=3 changes ($N)" || bad "diff too few changes ($N)"

echo "== UNDO DISCARD: upper wiped, project still pristine =="
"$BIN" undo "$S" >/dev/null 2>&1
U="$XDG_STATE_HOME/castellan/sessions/$S/overlay/upper"
[ -z "$(ls -A "$U" 2>/dev/null)" ] && ok "upper layer emptied by discard" || bad "discard left files in upper"
check "project intact after discard" "original" "$(cat "$W/keep.txt")"

echo "== KEEP (commit): materialize session changes onto project =="
OUT=$("$BIN" launch --project "$W" --undo -- bash -c "
  echo committed-line > committed.txt
  rm edit.txt
" 2>&1)
S2=$(grep -o 's[0-9a-f]\{20\}' <<<"$OUT" | head -1)
[ -n "$S2" ] && ok "second session launched" || bad "no second session id"
KEEP_OUT=$("$BIN" keep "$S2")
grep -q "committed" <<<"$KEEP_OUT" && ok "commit reported success" || bad "commit failed: $KEEP_OUT"
check "committed.txt materialized" "committed-line" "$(cat "$W/committed.txt")"
[ ! -e "$W/edit.txt" ] && ok "deletion materialized (edit.txt gone)" || bad "edit.txt should be gone"

echo "== daemon survives everything =="
"$BIN" status >/dev/null 2>&1 && ok "daemon still alive" || bad "daemon died"

kill -9 $DPID 2>/dev/null
pkill -x castellan-daemon 2>/dev/null

echo ""
echo "RESULT: $PASS passed, $FAIL failed"
exit $FAIL
