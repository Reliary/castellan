#!/usr/bin/env bash
# B8.3 live acceptance: the periodic escape-shape sweep.
#
# The C36 probe showed the broad census predicate claims legitimate user
# apps (konsole/firefox live under /user.slice parented to the user
# manager). So the periodic sweep is narrowed to the `run-*.service` /
# `run-*.timer` shape that `systemd-run` produces, and is report-only.
#
# This suite proves BOTH halves:
#   1. a transient run-*.service created during a live session window is
#      reported (escape_unit spine event)
#   2. a legitimate app-*.service is NOT reported
#
# The daemon's sweep interval is dropped to 2s for the test.
set -u
cd "$(dirname "$0")/../.."
BIN="$PWD/target/release"
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

WORK=$(mktemp -d /tmp/castellan-b83.XXXXXX)
mkdir -p "$WORK/proj/src"
export XDG_STATE_HOME="$WORK/state"

echo "== start daemon with a 2s sweep =="
CASTELLAN_SWEEP_SECS=2 "$BIN/castellan-daemon" > "$WORK/daemon.log" 2>&1 &
DAPID=$!
for _ in $(seq 1 40); do
  grep -q listening "$WORK/daemon.log" 2>/dev/null && break
  sleep 0.1
done
grep -q listening "$WORK/daemon.log" && ok "daemon started" || { bad "daemon failed to start"; exit 1; }

# Launch an enforced session that stays alive long enough for a sweep.
cat > "$WORK/hold.sh" <<'HOLD'
sleep 25
HOLD
"$BIN/castellan" launch --harness claude --project "$WORK/proj" --enforce \
  -- bash "$WORK/hold.sh" > "$WORK/launch.out" 2>"$WORK/launch.err" &
LAUNCHPID=$!
sleep 2
SID=$(grep -o 's[0-9a-f]\{10,\}' "$WORK/launch.err" | head -1)
[[ -n "$SID" ]] && ok "session $SID live" || bad "no session id"

# 1. escape shape: a transient unit as `systemd-run` actually creates it
#    (no --unit => `run-<pid>-i<invocation>.service`). The broker denies
#    systemd-run from INSIDE a session; here we start it from outside to
#    exercise the *detector*, which keys on the run-* name shape.
systemd-run --user --quiet sleep 20 >/dev/null 2>&1 &
sleep 3

# 2. legit shape: app-*.service (how a desktop app registers).
systemd-run --user --quiet --unit=app-castellan-legit.service sleep 20 >/dev/null 2>&1 &
sleep 4

# let two sweeps run
sleep 5

n_escape=$(grep -c "escape_unit" "$WORK/state/castellan/events/$SID.jsonl" 2>/dev/null); n_escape=${n_escape:-0}
n_legit=$(grep -c "app-castellan-legit" "$WORK/state/castellan/events/$SID.jsonl" 2>/dev/null); n_legit=${n_legit:-0}

echo "  (spine: escape_unit events=$n_escape, app-* mentions=$n_legit)"
[[ "$n_escape" -ge 1 ]] && ok "run-*.service (escape shape) reported" || bad "escape shape not reported"
[[ "$n_legit" -eq 0 ]] && ok "app-*.service (legit shape) NOT reported" || bad "legit app shape falsely reported"

# daemon must survive the sweep
kill -0 "$DAPID" 2>/dev/null && ok "daemon survives the sweep" || bad "daemon died"

kill "$LAUNCHPID" 2>/dev/null
"$BIN/castellan" kill "$SID" >/dev/null 2>&1
for u in $(systemctl --user list-units --type=service --no-legend --plain 2>/dev/null | grep -o 'run-[^ ]*\.service' | head -5); do
  systemctl --user stop "$u" 2>/dev/null
done
systemctl --user stop app-castellan-legit.service 2>/dev/null

echo "== SUMMARY =="
echo "  PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]] && echo "B8.3-ACCEPT-PASS" || echo "B8.3-ACCEPT-FAIL"
exit $FAIL
