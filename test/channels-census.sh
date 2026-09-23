#!/usr/bin/env bash
# Run the D6 channel census in both postures against a live daemon.
#   audit      — Landlock + seccomp only (the historical posture)
#   restricted — under the tier floor's destination policy (broker IP
#                allowlist: loopback only, resolver excluded)
# A channel that flips OPEN -> DENIED between them is one the destination
# policy actually closes.
set -u
D=/home/john/src/castellan/target/release/castellan-daemon
BIN=/home/john/src/castellan/target/release/castellan
W=$(mktemp -d /tmp/castellan-channels.XXXXXX)
export XDG_STATE_HOME="$W/state"
mkdir -p "$XDG_STATE_HOME"
SOCK="/run/user/$(id -u)/castellan.sock"

for p in $(pgrep -f "target/release/castellan-daemon" 2>/dev/null); do
  [ "$(stat -c %u /proc/$p 2>/dev/null)" = "$(id -u)" ] && kill -9 "$p" 2>/dev/null
done
sleep 0.5
rm -f "$SOCK"
"$D" > "$W/d.log" 2>&1 &
DPID=$!
for _ in $(seq 1 100); do
  [ -S "$SOCK" ] && break
  sleep 0.2
done
if [ ! -S "$SOCK" ]; then echo "daemon failed to start:"; cat "$W/d.log"; exit 1; fi

ask() {
  python3 - "$1" <<'PY'
import json, os, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(45)
s.connect(f"/run/user/{os.getuid()}/castellan.sock")
s.sendall((json.dumps({"op": "channels_run", "net_restrict": sys.argv[1] == "1"}) + "\n").encode())
data = b""
while True:
    c = s.recv(65536)
    if not c:
        break
    data += c
    try:
        json.loads(data.decode()); break
    except Exception:
        continue
r = json.loads(data.decode())
for e in r.get("extra", {}).get("channels", {}).get("inventory", []):
    print(f"  {e['channel']:<14} {e['verdict']}")
PY
}

echo "=== AUDIT posture (Landlock + seccomp only) ==="
ask 0
echo
echo "=== RESTRICTED posture (tier floor destination policy) ==="
ask 1

kill "$DPID" 2>/dev/null
wait "$DPID" 2>/dev/null
