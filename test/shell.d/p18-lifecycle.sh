#!/usr/bin/env bash
# castellan P18 — install / service / uninstall lifecycle acceptance suite.
#
# Written BEFORE the features (the spec), so the first run is a red baseline:
# every assertion names a user-visible outcome a clean install/uninstall must
# produce.
#
# WHY REAL STATE, NOT SCRATCH: `systemctl --user` is a singleton bound to the
# real XDG_CONFIG_HOME — a unit written under a scratch $XDG_CONFIG_HOME is
# NOT visible to it (verified on .227: "scratch XDG_CONFIG_HOME unit: NOT
# visible"). Testing "set the service up" therefore requires the real user
# manager and the real state dir. This suite is destructive by design and
# snapshots state metadata before it runs.
#
# Preconditions: a real user cgroup slice + systemctl --user. Refuses to run
# without --force elsewhere (the dev box cannot run the daemon anyway).
#
# This is the exercise-box suite. Run it there.

set -u

FORCE=0; KEEP_STATE=0
for a in "$@"; do
  [[ "$a" == "--force" ]] && FORCE=1
  [[ "$a" == "--keep-state" ]] && KEEP_STATE=1
done

BIN="${CASTELLAN_BIN:-$(cd "$(dirname "$0")/../.." && pwd)/target/release}"
UID_=$(id -u)
UNIT="castellan.service"
UNIT_PATH="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$UNIT"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/castellan"
CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/castellan"
SOCK="${XDG_RUNTIME_DIR:-/run/user/$UID_}/castellan.sock"
SLICE="/sys/fs/cgroup/user.slice/user-$UID_.slice/user@$UID_.service/castellan.slice"
SNAP="${TMPDIR:-/tmp}/castellan-p18-snapshot-$(date +%s).txt"
W=/tmp/cast-p18-work
mkdir -p "$W"
PASS=0; FAIL=0; NOTE=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
note() { echo "  NOTE: $1"; NOTE=$((NOTE+1)); }

# Safety: the lifecycle suite needs a real user manager. Refuse elsewhere
# unless --force, because uninstall deletes real state and config.
if ! systemctl --user show-environment >/dev/null 2>&1; then
  echo "no user systemd manager on this box — run with --force to attempt anyway"
  [[ "$FORCE" == "1" ]] || exit 3
fi

cleanup() {
  systemctl --user stop "$UNIT" 2>/dev/null
  systemctl --user disable "$UNIT" 2>/dev/null
  rm -f "$UNIT_PATH"
  systemctl --user daemon-reload 2>/dev/null
  pkill -9 -x castellan-daemo 2>/dev/null
  pkill -9 -f 'sleep 120' 2>/dev/null
}
trap cleanup EXIT

has_verb() { "$BIN/castellan" help 2>&1 | grep -qE "castellan $1( |$)"; }

echo "===== snapshot state metadata (the real tree is not backed up wholesale) ====="
{
  echo "state=$STATE_DIR"
  echo "config=$CONF_DIR"
  echo "sessions_dir_exists=$([ -d "$STATE_DIR/sessions" ] && echo yes || echo no)"
  echo "session_count=$(ls "$STATE_DIR/sessions" 2>/dev/null | wc -l)"
  echo "size_bytes=$(du -sb "$STATE_DIR" 2>/dev/null | awk '{print $1}')"
  echo "keyring_exists=$([ -e "$CONF_DIR/keyring.toml" ] && echo yes || echo no)"
  echo "unit_exists=$([ -e "$UNIT_PATH" ] && echo yes || echo no)"
} | tee "$SNAP"
note "metadata snapshot written to $SNAP"
if [[ -e "$CONF_DIR/keyring.toml" ]]; then
  note "a REAL keyring.toml exists — uninstall will delete it; back up first if it matters"
fi

echo
echo "===== capability presence ====="
for v in "service" "uninstall" "gc" "init" "doctor"; do
  has_verb "$v" && ok "castellan $v present" || bad "castellan $v missing"
done
"$BIN/castellan" --version >/dev/null 2>&1 && ok "castellan --version" || bad "castellan --version missing"

echo
echo "===== install produces a working unit ====="
"$BIN/castellan" service install >/dev/null 2>&1 && ok "service install exits 0" || bad "service install nonzero"
[[ -f "$UNIT_PATH" ]] && ok "unit written to $UNIT_PATH" || bad "unit not written"
# P20/C43+F11: the generated unit must carry the fail-closed directives.
grep -q "ExecStopPost=.*freeze --daemonless" "$UNIT_PATH" \
  && ok "unit has ExecStopPost freeze-on-stop" || bad "unit missing ExecStopPost freeze"
grep -q "StartLimitBurst" "$UNIT_PATH" \
  && ok "unit has start-limit (no restart thrash)" || bad "unit missing StartLimit"
systemctl --user is-enabled "$UNIT" >/dev/null 2>&1 && ok "unit enabled" || bad "unit not enabled"
for _ in $(seq 1 30); do systemctl --user is-active "$UNIT" >/dev/null 2>&1 && break; sleep 0.2; done
systemctl --user is-active "$UNIT" >/dev/null 2>&1 && ok "unit active" || bad "unit not active"
for _ in $(seq 1 50); do "$BIN/castellan" status >/dev/null 2>&1 && break; sleep 0.2; done
# connect-based, not `-S`: a stale socket file makes existence checks
# lie (measured: p18 launched against ECONNREFUSED against a stale path)
"$BIN/castellan" status >/dev/null 2>&1 \
  && ok "daemon answering after install" || bad "daemon not answering after install"

echo
echo "===== a confined session is visible in status (stays live for the run) ====="
LIVE_PID=""
if [[ -S "$SOCK" ]]; then
  mkdir -p /tmp/cast-p18
  # Long-lived agent: kept alive so later steps exercise stop/uninstall
  # against a REAL live session (P20 G10) instead of planted files.
  # SHELL=/bin/sh: `script -qec` uses $SHELL; on fish boxes (e.g. .227)
  # a POSIX body fails.
  ( SHELL=/bin/sh script -qec "
      BIN=$BIN/castellan
      \$BIN launch --project /tmp/cast-p18 -- sleep 120
    " /dev/null >"$W/p18-live.log" 2>&1 & )
  for _ in $(seq 1 50); do
    grep -qE 's[0-9a-f]{16,24}' "$W/p18-live.log" 2>/dev/null && break
    sleep 0.2
  done
  SID_LIVE=$(grep -oE 's[0-9a-f]{16,24}' "$W/p18-live.log" 2>/dev/null | head -1)
  # the agent execs AFTER the sid line prints — poll for it
  for _ in $(seq 1 30); do
    LIVE_PID=$(pgrep -f 'sleep 120' | head -1)
    [[ -n "$LIVE_PID" ]] && break
    sleep 0.2
  done
  if [[ -n "$SID_LIVE" ]]; then
    ok "session launched live (sid=$SID_LIVE agent=$LIVE_PID)"
    "$BIN/castellan" status 2>/dev/null | grep -q "$SID_LIVE" \
      && ok "status lists the session" || bad "status did not list the session"
  else
    bad "live launch produced no session (see $W/p18-live.log)"
  fi
else
  note "skipped: no daemon running"
fi

echo
echo "===== service logs are non-empty ====="
n=$("$BIN/castellan" service logs 2>/dev/null | wc -l)
[[ "$n" -gt 0 ]] && ok "service logs produced $n lines" || bad "service logs empty"

echo
echo "===== J3: service restart reloads the keyring ====="
# The keyring loads once at daemon start (P12 K5 pins the config sha), so
# editing keyring.toml needs a restart. Write a credential, restart, and
# assert the daemon journal shows it loaded one.
mkdir -p "$CONF_DIR"
cat > "$CONF_DIR/keyring.toml" <<'KEYRING'
[[credential]]
name = "j3"
scheme = "bearer"
token = "J3-RESTART-TOKEN-not-a-secret"
hosts = ["api.example.com"]
KEYRING
restart_out=$("$BIN/castellan" service restart 2>&1)
echo "  $restart_out"
if echo "$restart_out" | grep -q "service restarted"; then
  ok "J3a: service restart exits reporting a restart"
else
  bad "J3a: restart output: $(echo "$restart_out" | head -2 | tr '\n' ' ')"
fi
for _ in $(seq 1 50); do "$BIN/castellan" status >/dev/null 2>&1 && break; sleep 0.2; done
journalctl --user -u "$UNIT" --no-pager -n 40 2>/dev/null | grep -q "keyring loaded (1 credential" \
  && ok "J3b: daemon loaded the edited keyring after restart" \
  || bad "J3b: journal does not show keyring loaded (1 credential): $(journalctl --user -u "$UNIT" --no-pager -n 5 2>/dev/null | tr '\n' ' ' | head -c 200)"
rm -f "$CONF_DIR/keyring.toml"

echo
echo "===== service stop drops the socket ====="
"$BIN/castellan" service stop >/dev/null 2>&1 || note "service stop returned nonzero"
sleep 0.5
systemctl --user is-active "$UNIT" >/dev/null 2>&1 && bad "unit still active after stop" || ok "unit stopped"
[[ -S "$SOCK" ]] && bad "socket still present after stop" || ok "socket removed after stop"
# P20/G8: a live scope with NO reachable daemon is the C43
# running-unmanaged state — doctor must flag it, not wave it through.
if [[ -n "${LIVE_PID:-}" ]] && kill -0 "$LIVE_PID" 2>/dev/null; then
  ok "live agent still running after stop (test subject intact)"
  if "$BIN/castellan" doctor >"$W/doc-drift.out" 2>&1; then
    bad "G8: doctor PASSed with a live scope and no daemon"
  else
    grep -q "UNREACHABLE" "$W/doc-drift.out" \
      && ok "G8: doctor FAILs naming the unreachable scopes" || { bad "G8: doctor failed but not on drift"; cat "$W/doc-drift.out"; }
  fi
else
  note "live agent died before the drift check — G8 drift assert skipped"
fi

echo
echo "===== gc reclaims old session state (mode-000-aware) ====="
if [[ -d "$STATE_DIR/sessions" ]]; then
  before=$(du -sb "$STATE_DIR" 2>/dev/null | awk '{print $1}')
  n=$("$BIN/castellan" gc --keep-last 5 --yes 2>/dev/null | grep -oE 'removed [0-9]+' | awk '{print $2}')
  after=$(du -sb "$STATE_DIR" 2>/dev/null | awk '{print $1}')
  note "gc removed ${n:-0} session dir(s); size $before -> $after bytes"
  [[ "${n:-0}" -gt 0 ]] && ok "gc removed stale sessions" || note "gc removed nothing (state already clean)"
else
  note "skipped: no sessions dir"
fi

echo
echo "===== uninstall removes every artifact ====="
# plant a credential to prove it is deleted
mkdir -p "$CONF_DIR"
echo 'secret = "SENTINEL"' >> "$CONF_DIR/keyring.toml"
"$BIN/castellan" uninstall --yes >/dev/null 2>&1 || note "uninstall returned nonzero"
[[ -e "$CONF_DIR/keyring.toml" ]] && bad "keyring.toml survived uninstall (credential leak)" || ok "credential file removed"
if [[ "$KEEP_STATE" == "1" ]]; then
  note "state kept by request (--keep-state)"
else
  [[ -e "$STATE_DIR" ]] && bad "state dir survived uninstall" || ok "state dir removed"
fi
[[ -S "$SOCK" ]] && bad "socket survived uninstall" || ok "socket removed"
[[ -d "$SLICE" ]] && bad "castellan.slice survived uninstall" || ok "cgroup slice removed"
[[ -f "$UNIT_PATH" ]] && bad "unit file survived uninstall" || ok "unit file removed"
# P20/G10: against the REAL live session, not planted files — the agent
# must be dead once its scope is torn down.
if [[ -n "${LIVE_PID:-}" ]]; then
  sleep 0.5
  kill -0 "$LIVE_PID" 2>/dev/null && bad "G10: live agent SURVIVED uninstall (pid $LIVE_PID)" \
    || ok "G10: live agent killed by uninstall"
else
  note "G10: no live agent recorded — uninstall e2e incomplete"
fi

echo
echo "RESULT: $PASS passed, $FAIL failed, $NOTE notes"
exit $((FAIL > 0))
