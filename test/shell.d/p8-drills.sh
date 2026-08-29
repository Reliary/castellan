#!/usr/bin/env bash
# castellan P8 acceptance test — live-fire drills (Koch criterion).
# A self-test that cannot fail is not a test: inject each of the 5
# known defense regressions and verify the drill suite fails loudly
# for exactly the injected one. Then 20 clean cycles with zero false
# alarms.

set -u

BIN=/home/john/src/castellan/target/release
PASS=0
FAIL=0

ok() { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

cleanup() {
  [[ -n "${DAPID:-}" ]] && kill "$DAPID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

stop_daemon() {
  for p in $(pgrep -f castellan-daemon); do
    exe=$(readlink "/proc/$p/exe" 2>/dev/null) || continue
    case "$exe" in *castellan-daemon*) kill -9 "$p";; esac
  done
  rm -f /run/user/1000/castellan.sock
  sleep 0.3
}

start_daemon() {
  local envs="$1"
  stop_daemon
  # shellcheck disable=SC2086
  env $envs "$BIN/castellan-daemon" > /tmp/castellan-drill-daemon.log 2>&1 &
  DAPID=$!
  sleep 0.6
  if ! kill -0 "$DAPID" 2>/dev/null; then bad "daemon failed to start"; exit 1; fi
}

run_drills() {
  "$BIN/castellan" drill run 2>/dev/null
}

echo "== baseline: all 5 drills pass =="
start_daemon ""
out=$(run_drills)
fails=$(echo "$out" | grep -c FAIL || true)
[[ "$fails" == "0" ]] && ok "baseline: 5/5 drills pass" || bad "baseline has $fails failures: $out"

echo "== Koch: inject each regression, drill must fail loudly =="
declare -A INJECT=(
  [census]="CASTELLAN_TEST_DISABLE_CENSUS=1"
  [honeypot]="CASTELLAN_TEST_DISABLE_HONEYPOT=1"
  [bless]="CASTELLAN_TEST_DISABLE_BLESS=1"
  [envelope]="CASTELLAN_TEST_DISABLE_LANDLOCK=1 CASTELLAN_TEST_DISABLE_SECCOMP=1"
  [freeze]="CASTELLAN_TEST_DISABLE_FREEZE=1"
)

for drill in census honeypot bless envelope freeze; do
  start_daemon "${INJECT[$drill]}"
  out=$(run_drills)
  if echo "$out" | grep -q "drill $drill.*FAIL"; then
    ok "injected $drill regression caught"
  else
    bad "injected $drill regression NOT caught: $out"
  fi
  # the other four must still pass (no collateral false alarms)
  for other in census honeypot bless envelope freeze; do
    [[ "$other" == "$drill" ]] && continue
    if echo "$out" | grep -q "drill $other.*FAIL"; then
      bad "collateral failure: $other failed when $drill was injected"
    fi
  done
done

echo "== 20 clean cycles: zero false alarms =="
start_daemon ""
clean_fails=0
for i in $(seq 1 20); do
  out=$(run_drills)
  n=$(echo "$out" | grep -c FAIL || true)
  if [[ "$n" != "0" ]]; then
    clean_fails=$((clean_fails+1))
    echo "  cycle $i: $out"
  fi
done
[[ "$clean_fails" == "0" ]] && ok "20 clean cycles, zero false alarms" || bad "$clean_fails/20 clean cycles failed"

echo
echo "RESULT: $PASS passed, $FAIL failed"
exit $((FAIL > 0))
