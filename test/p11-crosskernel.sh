#!/usr/bin/env bash
# P11 cross-kernel check: run the tier-gated egress floor on this kernel.
# Copy to the target, run there. The two kernels that matter are 7.0.3
# (dev) and 7.1.8 (.227); a destination-policy mechanism that works on
# one and not the other is not a mechanism.
set -u
BIN_DIR=${BIN_DIR:-/tmp}
BIN="$BIN_DIR/castellan"
PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

W=$(mktemp -d /tmp/castellan-p11x.XXXXXX)
export XDG_STATE_HOME="$W/state"
mkdir -p "$XDG_STATE_HOME"
SOCK="/run/user/$(id -u)/castellan.sock"
unset CASTELLAN_EGRESS_ALLOW_HOSTS

rm -f "$SOCK"
"$BIN_DIR/castellan-daemon" > "$W/d.log" 2>&1 &
DPID=$!
for _ in $(seq 1 100); do [ -S "$SOCK" ] && break; sleep 0.2; done
[ -S "$SOCK" ] || { echo "daemon did not start"; tail -5 "$W/d.log"; exit 1; }

cat > "$W/probe.py" <<'PY'
import socket
out = []
def cls(e):
    return f"E{e.errno}" if getattr(e, "errno", None) else "ETIMEOUT"
try:
    s = socket.create_connection(("1.2.3.4", 443), timeout=3); s.close(); out.append("tcp=CONNECTED")
except OSError as e: out.append(f"tcp={cls(e)}")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.connect(("1.2.3.4", 53)); s.send(b"x"); out.append("udp=SENT")
except OSError as e: out.append(f"udp={cls(e)}")
try:
    s = socket.create_connection(("127.0.0.1", 22), timeout=2); s.close(); out.append("loop=CONNECTED")
except OSError as e: out.append(f"loop={cls(e)}")
print(" ".join(out))
PY

P="$W/low"; mkdir -p "$P"; echo 'x = 1' > "$P/a.py"

# NOTE: the target's login shell may be fish, and `script -qec` uses the
# LOGIN shell — fish parses the whole command line before exec'ing
# anything, so an inline POSIX body never reaches bash. Every pty here
# therefore runs a SCRIPT FILE, which no shell has to parse.
cat > "$W/launch_undo.sh" <<EOF
#!/usr/bin/env bash
export XDG_STATE_HOME='$XDG_STATE_HOME'
'$BIN' launch --harness claude --project '$P' -- bash -c 'true' >/dev/null 2>&1
S=\$(ls -t '$XDG_STATE_HOME/castellan/sessions'/*.json 2>/dev/null | head -1 | xargs basename | sed 's/\.json//')
[ -n "\$S" ] && '$BIN' undo "\$S" >/dev/null 2>&1 && echo REVERTED
EOF
chmod +x "$W/launch_undo.sh"
cat > "$W/launch_probe.sh" <<EOF
#!/usr/bin/env bash
export XDG_STATE_HOME='$XDG_STATE_HOME'
cd '$P' || exit 1
exec '$BIN' launch --harness claude --project '$P' -- python3 '$W/probe.py'
EOF
chmod +x "$W/launch_probe.sh"
PTY() { script -qec "$1" /dev/null; }

# The undo must run from the SAME pty that launched: the B7 witnessed-tty
# gate rejects a human-only op from a different terminal. The script file
# does both inside one pty.
for _ in 1 2 3 4 5; do
  echo 'x = 1' > "$P/a.py"
  PTY "$W/launch_undo.sh" 2>/dev/null | tr -d '\r'
done
TIER=$("$BIN" trust "$P" 2>/dev/null | sed -n 's/.*tier \([0-9]\).*/\1/p' | head -1)
echo "  kernel: $(uname -r)   tier: ${TIER:-?}"
case "$TIER" in 0|1) ok "tier $TIER reached on this kernel" ;; *) bad "tier ${TIER:-?} (expected 0/1)" ;; esac

echo 'x = 1' > "$P/a.py"
PTY "$W/launch_probe.sh" > "$W/o.txt" 2>&1
R=$(tr -d '\r' < "$W/o.txt" | grep -oE '(tcp|udp|loop)=[A-Za-z0-9]+' | tr '\n' ' ')
echo "  probe: $R"
echo "$R" | grep -qE "tcp=(E1|ETIMEOUT)" && ok "public TCP not connected on this kernel ($R)" || bad "public TCP: $R"
echo "$R" | grep -qE "udp=(E1|ETIMEOUT)" && ok "public UDP not sent on this kernel ($R)" || bad "public UDP: $R"
echo "$R" | grep -qE "loop=(CONNECTED|E[0-9]+)" && ok "loopback still reachable (honeypot path alive)" || bad "loopback broken: $R"

echo "== census: both postures =="
"$BIN" channels run 2>/dev/null | grep -E "^  (udp|dns) " | sed 's/^/  audit  /'
"$BIN" channels run --net-restrict 2>/dev/null | grep -E "^  (udp|dns) " | sed 's/^/  restrict /'

kill "$DPID" 2>/dev/null
echo "  PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]] && echo "P11-XKERNEL-PASS" || echo "P11-XKERNEL-FAIL"
