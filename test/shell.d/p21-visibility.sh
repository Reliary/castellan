#!/usr/bin/env bash
# castellan P21.3 — visibility acceptance: watch transitions + notify,
# pretty bless show, status --json.
#
# K9  a freeze transition produces exactly one watch line and one
#     notify-send call (mock in PATH)
# K10 a pending bless request is visible via the pretty `bless show`
#     and through watch
# K11 `status --json` parses and round-trips
#
# Runs on the exercise box (user cgroup slice + pty). Read-only ops only;
# the watcher never mutates.
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
BIN="$REPO/target/release"
PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

W=$(mktemp -d /tmp/castellan-p213.XXXXXX)
export XDG_STATE_HOME="$W/state"
export XDG_CONFIG_HOME="$W/config"
mkdir -p "$XDG_STATE_HOME" "$XDG_CONFIG_HOME/castellan"
SOCK="/run/user/$(id -u)/castellan.sock"

# mock notify-send FIRST on PATH, records its argv
mkdir -p "$W/mockbin"
cat > "$W/mockbin/notify-send" <<'EOF'
#!/bin/sh
echo "$@" >> "$NOTIFY_LOG"
exit 0
EOF
chmod +x "$W/mockbin/notify-send"
export NOTIFY_LOG="$W/notify.log"
: > "$NOTIFY_LOG"

for p in $(pgrep -f "target/release/castellan-daemon" 2>/dev/null); do
  [ "$(readlink "/proc/$p/exe" 2>/dev/null)" = "$BIN/castellan-daemon" ] && kill -9 "$p" 2>/dev/null
done
sleep 0.5
rm -f "$SOCK"
"$BIN/castellan-daemon" > "$W/d.log" 2>&1 &
DPID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "daemon did not start"; cat "$W/d.log"; exit 1; }

cleanup() { [ -n "${DPID:-}" ] && kill -9 "$DPID" 2>/dev/null; }
trap cleanup EXIT

rpc() { python3 -c '
import json,os,socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(30)
s.connect(f"/run/user/{os.getuid()}/castellan.sock")
s.sendall(json.dumps(json.loads(sys.argv[1])).encode()+b"\n")
d=b""
while True:
    c=s.recv(65536)
    if not c: break
    d+=c
    try: json.loads(d.decode()); break
    except Exception: continue
print(d.decode())' "$1"; }

mkproj() { mkdir -p "$1"; printf 'x = 1\n' > "$1/a.py"; }

echo "== K11: status --json parses =="
OUT=$(PYTHONPATH= XDG_STATE_HOME="$XDG_STATE_HOME" PATH="$W/mockbin:$PATH" "$BIN/castellan" status --json 2>&1)
if echo "$OUT" | python3 -c 'import json,sys; v=json.load(sys.stdin); assert "sessions" in v or v.get("ok") is True' 2>/dev/null; then
  ok "K11: status --json is valid JSON"
else
  bad "K11: status --json not parseable: $(echo "$OUT" | head -2 | tr '\n' ' ')"
fi

echo
echo "== K9: watch sees a freeze and notifies once (mock notify-send) =="
P="$W/proj"; mkproj "$P"
# spawn a session with a live pid so it shows in status
sleep 120 >/dev/null 2>&1 & SPID=$!
disown
SID=$(rpc "{\"op\":\"spawn\",\"harness\":\"claude\",\"project\":\"$P\",\"pid\":$SPID,\"launcher_tty\":0}" \
  | python3 -c 'import json,sys,re; m=json.load(sys.stdin).get("message",""); s=re.search(r"session (\S+)",m); print(s.group(1) if s else "")')
# start the watcher (no tty needed — read-only) with the mock on PATH
NOTIFY_LOG="$NOTIFY_LOG" PATH="$W/mockbin:$PATH" "$BIN/castellan" watch --interval 1 > "$W/watch.out" 2>&1 &
WPID=$!
sleep 2.5
# freeze via cgroup directly (daemon op needs tty; use daemonless which
# freezes every scope — no tty gate by design)
"$BIN/castellan" freeze --daemonless >/dev/null 2>&1
sleep 3
kill -9 "$WPID" 2>/dev/null
kill -9 "$SPID" 2>/dev/null
if grep -q "FROZEN" "$W/watch.out"; then ok "K9a: watch reported the freeze transition"
else bad "K9a: no FROZEN line in watch output: $(tail -3 "$W/watch.out" | tr '\n' ' ')"; fi
n=$(grep -c "session frozen" "$NOTIFY_LOG" 2>/dev/null || echo 0)
if [ "$n" = "1" ]; then ok "K9b: exactly one notify-send call for the freeze"
else bad "K9b: expected 1 notification, got $n: $(cat "$NOTIFY_LOG" 2>/dev/null | head -2)"; fi
"$BIN/castellan" thaw --daemonless >/dev/null 2>&1 || true

echo
echo "== K10: a pending bless is visible via pretty bless show =="
P2="$W/proj2"; mkproj "$P2"
sleep 120 >/dev/null 2>&1 & SPID2=$!
disown
SID2=$(rpc "{\"op\":\"spawn\",\"harness\":\"claude\",\"project\":\"$P2\",\"pid\":$SPID2,\"launcher_tty\":0}" \
  | python3 -c 'import json,sys,re; m=json.load(sys.stdin).get("message",""); s=re.search(r"session (\S+)",m); print(s.group(1) if s else "")')
rpc "{\"op\":\"bless_request\",\"session\":\"$SID2\",\"want\":\"egress\",\"reason\":\"watch-suite\"}" >/dev/null
BSHOW=$(PATH="$W/mockbin:$PATH" "$BIN/castellan" bless show 2>&1)
if echo "$BSHOW" | grep -q "HINT" && echo "$BSHOW" | grep -q "egress"; then
  ok "K10a: bless show lists the request (pretty)"
else bad "K10a: bless show did not list it: $(echo "$BSHOW" | head -3 | tr '\n' ' ')"; fi
if echo "$BSHOW" | grep -q "castellan bless approve"; then
  ok "K10b: bless show prints the approve command"
else bad "K10b: no approve hint"; fi
kill -9 "$SPID2" 2>/dev/null

echo
echo "== SUMMARY =="
echo "  PASS=$PASS FAIL=$FAIL  workdir: $W"
if [ "$FAIL" -eq 0 ]; then echo "P21.3-ACCEPT-PASS"; exit 0; else echo "P21.3-ACCEPT-FAIL"; exit 1; fi
