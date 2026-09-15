#!/usr/bin/env bash
# B8.2 live acceptance: the seccomp user-notification broker closes the
# T4 escape (systemd-run --user reaches the user manager over a unix
# socket no filesystem rule covers) and, with --net, restricts egress by
# destination. Both are verified from INSIDE an enforced session.
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

WORK=$(mktemp -d /tmp/castellan-b82.XXXXXX)
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

echo "== T4 CLOSE: systemd-run --user must FAIL inside an enforced session =="
"$BIN/castellan" launch --harness claude --project "$WORK/proj" --enforce -- bash -c "
  # A) the manager private socket is denied by the broker
  if systemd-run --user --scope --quiet true 2>/dev/null; then
    echo T4_ESCAPE_OK
  else
    echo T4_BLOCKED
  fi
  # B) an ordinary local unix socket is NOT denied (no over-block)
  python3 -c \"
import socket,os
s=socket.socket(socket.AF_UNIX)
p='/run/user/%d/castellan-b82-ok.sock'%os.getuid()
try:
    s.connect(p)
except (FileNotFoundError, ConnectionRefusedError):
    print('UNIX_OK')
except PermissionError:
    print('UNIX_DENIED')
except OSError:
    print('UNIX_OTHER')
\"
  # C) loopback TCP is allowed (broker does not over-block)
  python3 -c \"
import socket
s=socket.socket()
try:
    s.connect(('127.0.0.1', 9))
except ConnectionRefusedError:
    print('LOOP_OK')
except PermissionError:
    print('LOOP_DENIED')
except OSError:
    print('LOOP_OTHER')
\"
" > "$WORK/t4.out" 2>"$WORK/t4.err"
SID=$(grep -o 's[0-9a-f]\{10,\}' "$WORK/t4.err" | head -1)
[[ -n "$SID" ]] && ok "session $SID launched" || bad "no session id"

grep -q T4_BLOCKED "$WORK/t4.out" && ok "systemd-run --user DENIED by broker (T4 closed)" || bad "T4 escape still open (or systemd-run absent)"
grep -q T4_ESCAPE_OK "$WORK/t4.out" && bad "T4 escape succeeded — broker did not block the manager socket" || true
grep -q UNIX_OK "$WORK/t4.out" && ok "ordinary unix socket still allowed (no over-block)" || bad "ordinary unix socket wrongly denied"
grep -q LOOP_OK "$WORK/t4.out" && ok "loopback TCP still allowed" || bad "loopback TCP wrongly denied"
"$BIN/castellan" kill "$SID" >/dev/null 2>&1

echo "== --net: destination-scoped egress restriction =="
"$BIN/castellan" launch --harness claude --project "$WORK/proj" --enforce --net -- bash -c "
  python3 -c \"
import socket
# public TCP 443 -> must be denied by the broker's IP restriction
s=socket.socket()
s.settimeout(3)
try:
    s.connect(('1.2.3.4', 443))
    print('PUB_OK')
except PermissionError:
    print('PUB_DENIED')
except OSError as e:
    print('PUB_OTHER:%s'%e.errno)
\"
  # systemd socket still denied under --net
  systemd-run --user --scope --quiet true 2>/dev/null && echo T4_ESCAPE_OK || echo T4_BLOCKED
" > "$WORK/net.out" 2>"$WORK/net.err"
SID2=$(grep -o 's[0-9a-f]\{10,\}' "$WORK/net.err" | head -1)
grep -q PUB_DENIED "$WORK/net.out" && ok "--net denies public TCP by destination" || { bad "--net did not deny public TCP"; echo "    (got: $(grep PUB "$WORK/net.out"))"; }
grep -q T4_BLOCKED "$WORK/net.out" && ok "--net keeps the manager socket denied" || bad "--net leaked the manager socket"
[[ -n "$SID2" ]] && "$BIN/castellan" kill "$SID2" >/dev/null 2>&1

echo "== SUMMARY =="
echo "  PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]] && echo "B8.2-ACCEPT-PASS" || echo "B8.2-ACCEPT-FAIL"
exit $FAIL
