#!/usr/bin/env bash
# P6 trust-floor acceptance: the tier floor must confine (enforce+undo)
# without deadlocking the agent.
#
# Regression for the 2026-09-16 dogfooding find: the low-trust branch
# forced net=true, which denies the LLM API. The agent could not run,
# produced no edits, got auto-reverted, and the project could never earn
# trust back — an unrecoverable deadlock at tier 0. Composed with the
# B8.2 broker (which reads the same net flag), it became lethal: the
# pre-B8.2 Landlock half silently no-opped because the CLI read the
# honeypot port from the wrong JSON field.
#
# This suite proves BOTH halves:
#   A. a tier-0 project launches a session that actually runs (no net
#      forcing, no API denial)
#   B. the honeypot port is read correctly (the --net path applies when
#      requested, not silently skipped)
set -u
cd "$(dirname "$0")/../.."
BIN="$PWD/target/release"
CASTELLAN="$BIN/castellan"
PASS=0 FAIL=0
ok() { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

cleanup() {
  [[ -n "${DAPID:-}" ]] && kill "$DAPID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

for p in $(pgrep -f castellan-daemon); do
  exe=$(readlink "/proc/$p/exe" 2>/dev/null) || continue
  case "$exe" in *castellan-daemon*) kill -9 "$p";; esac
done
rm -f /run/user/$(id -u)/castellan.sock

WORK=$(mktemp -d /tmp/castellan-p6.XXXXXX)
mkdir -p "$WORK/proj/src"
export XDG_STATE_HOME="$WORK/state"

echo "== start daemon =="
"$BIN/castellan-daemon" > "$WORK/daemon.log" 2>&1 &
DAPID=$!
for _ in $(seq 1 40); do
  grep -q listening "$WORK/daemon.log" 2>/dev/null && break
  sleep 0.1
done
grep -q listening "$WORK/daemon.log" && ok "daemon started" || { bad "daemon failed to start"; exit 1; }

# ---- drive the project to tier 0 with real revert signals ----------
echo "== drive the project to tier 0 =="
# Three real launches + real reverts through the real CLI path. The
# floor is per-project, so this builds a tier-0 project honestly.
for i in 1 2 3; do
  OUT=$(script -qec "
    export XDG_STATE_HOME='$XDG_STATE_HOME'
    '$CASTELLAN' launch --harness pi --project '$WORK/proj' --enforce --undo -- true 2>&1
    SID=\$(ls -t '$XDG_STATE_HOME/castellan/sessions'/*.json | head -1 | xargs basename | sed 's/\.json//')
    '$CASTELLAN' undo \"\$SID\" 2>&1
  " /dev/null)
done
SCORE=$("$CASTELLAN" trust "$WORK/proj" 2>&1 | head -1)
echo "  ($SCORE)"
if echo "$SCORE" | grep -qE "tier 0|tier 1"; then
  ok "project driven to the fail-closed tier"
else
  bad "could not drive trust down: $SCORE"
fi

# ---- A. tier 0 does NOT force net, and the session runs ------------
echo "== tier floor: enforce+undo forced, net NOT forced =="
OUT=$(script -qec "
  export XDG_STATE_HOME='$XDG_STATE_HOME'
  '$CASTELLAN' launch --harness pi --project '$WORK/proj' --enforce -- bash -c 'echo RAN_OK' 2>&1
" /dev/null)
echo "$OUT" > "$WORK/floor.out"
grep -q "RAN_OK" "$WORK/floor.out" && ok "session ran under the floor (no net deadlock)" || bad "session did not run"
grep -q "forcing enforce+undo" "$WORK/floor.out" && ok "enforce+undo forced (banner)" || bad "floor banner missing the expected shape"
if grep -q "forcing enforce+undo+net" "$WORK/floor.out"; then
  bad "net is still forced — the tier-0 API deadlock is back"
else
  ok "net NOT forced (the deadlock regression)"
fi

# ---- B. --net applies when requested (port parse) -------------------
echo "== --net reads the honeypot port and applies the policy =="
# The daemon is up, so the honeypot has a port; the CLI must read it
# from extra.port. A public connect must then be denied.
OUT=$(script -qec "
  export XDG_STATE_HOME='$XDG_STATE_HOME'
  '$CASTELLAN' launch --harness pi --project '$WORK/proj' --enforce --net -- python3 -c \"
import socket
s=socket.socket(); s.settimeout(3)
try:
    s.connect(('1.2.3.4', 443)); print('PUB_OK')
except PermissionError: print('PUB_DENIED')
except OSError as e: print('PUB_OTHER')
\" 2>&1
" /dev/null)
echo "$OUT" > "$WORK/net.out"
if grep -q "honeypot is detached" "$WORK/net.out"; then
  bad "honeypot reported detached although the daemon is up (port parse regression)"
elif grep -q "PUB_DENIED" "$WORK/net.out"; then
  ok "--net denies public TCP (port read correctly, policy applied)"
elif grep -q "PUB_OK" "$WORK/net.out"; then
  bad "--net did not restrict egress"
else
  bad "could not evaluate the --net path: $(tail -2 "$WORK/net.out" | tr '\n' ' ')"
fi

echo "== SUMMARY =="
echo "  PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]] && echo "P6-FLOOR-ACCEPT-PASS" || echo "P6-FLOOR-ACCEPT-FAIL"
exit $FAIL
