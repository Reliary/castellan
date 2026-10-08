#!/usr/bin/env bash
# castellan P18 — install / service / uninstall lifecycle acceptance suite.
#
# Written BEFORE the features (the spec), so the first run is a red baseline:
# every assertion names a user-visible outcome a clean install/uninstall must
# produce. Run on the exercise box (real user cgroup slice + systemctl --user).
#
# Modes:
#   default        — scratch XDG_STATE_HOME/XDG_CONFIG_HOME under $TMP, so the
#                    run is repeatable and never touches real session state.
#   --real-state   — operate on the real state dir (the 180-session / 261 MB
#                    case). Explicit and destructive; used once for the record.
#
# Env: CASTELLAN_BIN overrides the target directory.

set -u

REAL_STATE=0
[[ "${1:-}" == "--real-state" ]] && REAL_STATE=1

BIN="${CASTELLAN_BIN:-$(cd "$(dirname "$0")/../.." && pwd)/target/release}"
UID_=$(id -u)
UNIT="castellan.service"
UNIT_PATH="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/$UNIT"
PASS=0; FAIL=0; NOTE=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
note() { echo "  NOTE: $1"; NOTE=$((NOTE+1)); }

if [[ "$REAL_STATE" == "1" ]]; then
  STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}"
  CONF_DIR="${XDG_CONFIG_HOME:-$HOME/.config}"
  echo "== REAL-STATE MODE: operating on $STATE_DIR/castellan and $CONF_DIR/castellan =="
else
  TMP=$(mktemp -d /tmp/cast-p18.XXXXXX)
  export XDG_STATE_HOME="$TMP/state"
  export XDG_CONFIG_HOME="$TMP/config"
  STATE_DIR="$XDG_STATE_HOME"; CONF_DIR="$XDG_CONFIG_HOME"
  mkdir -p "$STATE_DIR" "$CONF_DIR"
  echo "== scratch state: $TMP =="
fi
SOCK="${XDG_RUNTIME_DIR:-/run/user/$UID_}/castellan.sock"
SLICE="/sys/fs/cgroup/user.slice/user-$UID_.slice/user@$UID_.service/castellan.slice"

cleanup() {
  pkill -9 -x castellan-daemon 2>/dev/null
  systemctl --user stop "$UNIT" 2>/dev/null
  [[ "$REAL_STATE" == "0" && -n "${TMP:-}" ]] && rm -rf "$TMP" 2>/dev/null
}
trap cleanup EXIT

has_verb() { "$BIN/castellan" help 2>&1 | grep -qE "castellan $1( |$)"; }

echo
echo "===== capability presence (red baseline until built) ====="
for v in "service install" "service uninstall" "service status" "service logs" "uninstall" "logs" "init" "doctor" "--version"; do
  if [[ "$v" == "--version" ]]; then
    "$BIN/castellan" --version >/dev/null 2>&1 && ok "castellan --version" || bad "castellan --version missing"
  elif has_verb "$v"; then
    ok "castellan $v present"
  else
    bad "castellan $v missing (not built yet)"
  fi
done

echo
echo "===== install produces a working unit ====="
if has_verb "service install"; then
  "$BIN/castellan" service install >/dev/null 2>&1 && ok "service install exits 0" || bad "service install nonzero"
  [[ -f "$UNIT_PATH" ]] && ok "unit written to $UNIT_PATH" || bad "unit not written"
  systemctl --user is-enabled "$UNIT" >/dev/null 2>&1 && ok "unit enabled" || bad "unit not enabled"
  systemctl --user is-active "$UNIT" >/dev/null 2>&1 && ok "unit active" || bad "unit not active"
  for _ in $(seq 1 30); do [ -S "$SOCK" ] && break; sleep 0.2; done
  [[ -S "$SOCK" ]] && ok "daemon socket present after install" || bad "socket absent after install"
else
  note "skipped: service install not built"
fi

echo
echo "===== a confined session is visible in status ====="
if [[ -S "$SOCK" ]]; then
  # launch a trivial session from a witnessed tty, read status, clean up.
  mkdir -p /tmp/cast-p18
  script -qec "
    BIN=$BIN/castellan
    OUT=\$(\$BIN launch --project /tmp/cast-p18 -- true 2>&1)
    SID=\$(echo \"\$OUT\" | grep -oE 's[0-9a-f]{16,24}' | head -1)
    \$BIN status
    \$BIN kill \$SID >/dev/null 2>&1
  " /dev/null 2>&1 | grep -q 's[0-9a-f]' \
    && ok "status lists the session" || bad "status did not list the session"
else
  note "skipped: no daemon running"
fi

echo
echo "===== service logs are non-empty ====="
if has_verb "service logs"; then
  n=$("$BIN/castellan" service logs 2>/dev/null | wc -l)
  [[ "$n" -gt 0 ]] && ok "service logs produced $n lines" || bad "service logs empty"
else
  note "skipped: service logs not built"
fi

echo
echo "===== service stop freezes sessions and drops the socket ====="
if has_verb "service status"; then
  "$BIN/castellan" service stop >/dev/null 2>&1 || note "service stop returned nonzero"
  sleep 0.5
  systemctl --user is-active "$UNIT" >/dev/null 2>&1 && bad "unit still active after stop" || ok "unit stopped"
  [[ -S "$SOCK" ]] && bad "socket still present after stop" || ok "socket removed after stop"
else
  note "skipped: service stop not built"
fi

echo
echo "===== uninstall removes every artifact ====="
if has_verb "uninstall"; then
  # plant a confined-session file, a keyring credential, and a state dir.
  mkdir -p "$STATE_DIR/castellan/sessions/probe" "$CONF_DIR/castellan"
  echo probe > "$STATE_DIR/castellan/sessions/probe/leaf"
  echo 'secret = "SENTINEL"' > "$CONF_DIR/castellan/keyring.toml"
  "$BIN/castellan" uninstall --yes >/dev/null 2>&1 || note "uninstall returned nonzero"
  [[ -e "$CONF_DIR/castellan/keyring.toml" ]] && bad "keyring.toml survived uninstall (credential leak)" || ok "credential file removed"
  [[ -e "$STATE_DIR/castellan" ]] && bad "state dir survived uninstall" || ok "state dir removed"
  [[ -S "$SOCK" ]] && bad "socket survived uninstall" || ok "socket removed"
  [[ -d "$SLICE" ]] && bad "castellan.slice survived uninstall" || ok "cgroup slice removed"
  [[ -f "$UNIT_PATH" ]] && bad "unit file survived uninstall" || ok "unit file removed"
else
  note "skipped: uninstall not built"
fi

echo
echo "RESULT: $PASS passed, $FAIL failed, $NOTE notes"
exit $((FAIL > 0))
