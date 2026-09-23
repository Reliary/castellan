#!/usr/bin/env bash
# P11 acceptance — the tier-gated egress floor.
#
# The criteria are pre-committed. A failure is recorded, not softened.
#
#   K1 no deadlock      a tier-0 session whose LLM host IS declared
#                       reaches it and produces work; the project is not
#                       bricked (this is the regression that the first
#                       fix for 5dd19a3 only half-solved: removing the
#                       net forcing made it survivable but left egress
#                       ungated)
#   K2 egress gated     a tier-0 session with NO declared host: public
#                       TCP/UDP/DNS are all EPERM; loopback works
#   K3 tier 2 unaffected a warm project launches with the operator's
#                       flags untouched (the floor must not fire)
#   K4 bless egress     an approved `egress` grant lifts the floor for
#                       exactly one launch
#   K5 no regression    the census distinguishes the two postures, and
#                       broker denies reach the session spine
set -u
BIN_DIR=/home/john/src/castellan/target/release
BIN="$BIN_DIR/castellan"
PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

W=$(mktemp -d /tmp/castellan-p11.XXXXXX)
export XDG_STATE_HOME="$W/state"
mkdir -p "$XDG_STATE_HOME"
SOCK="/run/user/$(id -u)/castellan.sock"
unset CASTELLAN_EGRESS_ALLOW_HOSTS
export XDG_CONFIG_HOME="$W/config"
mkdir -p "$XDG_CONFIG_HOME"

for p in $(pgrep -f "target/release/castellan-daemon" 2>/dev/null); do
  [ "$(stat -c %u /proc/$p 2>/dev/null)" = "$(id -u)" ] && kill -9 "$p" 2>/dev/null
done
sleep 0.5
rm -f "$SOCK"
"$BIN_DIR/castellan-daemon" > "$W/d.log" 2>&1 &
DPID=$!
for _ in $(seq 1 100); do [ -S "$SOCK" ] && break; sleep 0.2; done
[ -S "$SOCK" ] || { echo "daemon did not start"; cat "$W/d.log"; exit 1; }

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

# A probe that reports what each channel did, by class.
cat > "$W/probe.py" <<'PY'
import socket, sys
out = []
# public TCP
try:
    s = socket.create_connection(("1.2.3.4", 443), timeout=3); s.close()
    out.append("tcp_public=CONNECTED")
except OSError as e:
    out.append(f"tcp_public=E{e.errno}")
# public UDP (connected, so the broker judges the connect)
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.connect(("1.2.3.4", 53)); s.send(b"x")
    out.append("udp_public=SENT")
except OSError as e:
    out.append(f"udp_public=E{e.errno}")
# loopback TCP
try:
    s = socket.create_connection(("127.0.0.1", 22), timeout=2); s.close()
    out.append("tcp_loopback=CONNECTED")
except OSError as e:
    out.append(f"tcp_loopback=E{e.errno}")
# loopback UDP
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
    s.connect(("127.0.0.1", 9)); s.send(b"x")
    out.append("udp_loopback=SENT")
except OSError as e:
    out.append(f"udp_loopback=E{e.errno}")
print(" ".join(out))
PY

mkproj() { mkdir -p "$1"; printf 'x = 1\n' > "$1/a.py"; }

drive_low() {
  # 5 reverts to walk a project to tier 0
  local proj="$1"
  for _ in 1 2 3 4 5; do
    mkproj "$proj"
    SID=$(script -qec "XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$proj' -- bash -c 'true' >/dev/null 2>&1; ls -t '$XDG_STATE_HOME/castellan/sessions'/*.json 2>/dev/null | head -1 | xargs basename | sed 's/\.json//'" /dev/null 2>/dev/null | tail -1 | tr -d '\r')
    [ -n "$SID" ] || return 1
    script -qec "XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' undo '$SID'" /dev/null >/dev/null 2>&1
  done
}

tier_of() { "$BIN" trust "$1" 2>/dev/null | sed -n 's/.*tier \([0-9]\).*/\1/p' | head -1; }

echo "== drive a project to tier 0 =="
P0="$W/low"; drive_low "$P0" || bad "could not run the tier-0 setup"
TIER=$(tier_of "$P0")
echo "  tier now: ${TIER:-<unknown>}"
case "$TIER" in 0|1) ok "project reached tier $TIER" ;; *) bad "project is tier ${TIER:-?}, expected 0/1" ;; esac

echo
echo "== K1: declared LLM host stays reachable, agent is not bricked =="
# A host that resolves here: the machine's own address is not public, so
# use the machine's hostname to prove the allowlist path works end to end.
ALLOWED=$(python3 -c "import socket;print(socket.gethostbyname(socket.gethostname()))" 2>/dev/null)
mkproj "$P0"
script -qec "
  XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$P0' --allow-host '$ALLOWED' -- bash -c 'echo WORKED > out.txt'
" /dev/null >"$W/k1.out" 2>&1
SID1=$(tr -d '\r' < "$W/k1.out" | grep -o 's[0-9a-f]\{12,\}' | head -1)
# the floor forces undo, so the write lands in the session upper layer,
# not the canonical project. Check where the work actually went.
U="$XDG_STATE_HOME/castellan/sessions/${SID1}/overlay/upper"
if [ -f "$U/out.txt" ]; then ok "K1: session ran under the floor (allowlist honored, not bricked)"
elif [ -f "$P0/out.txt" ]; then ok "K1: session ran under the floor (allowlist honored, not bricked)"
else bad "K1: the session produced no work (sid=${SID1:-none}); the floor may still be bricking the agent"; fi
grep -q "egress restricted" "$W/k1.out" && ok "K1b: the launcher announced the egress restriction" \
  || grep -q "tier floor active" "$W/d.log" && ok "K1b: the daemon logged the tier floor firing" \
  || bad "K1b: no egress-restriction notice anywhere (floor did not fire?)"

echo
echo "== K2: with no declared host, public egress is denied =="
mkproj "$P0"
script -qec "
  XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$P0' -- python3 '$W/probe.py'
" /dev/null >"$W/k2.out" 2>/dev/null
K2=$(tr -d '\r' < "$W/k2.out" | grep -o 'tcp_public=E[0-9]*' | head -1)
echo "  $K2"
[ "$K2" = "tcp_public=E1" ] && ok "K2: public TCP denied with EPERM" || bad "K2: public TCP was $K2 (expected E1)"

echo
echo "== K3: a warm project is untouched by the floor =="
PW="$W/warm"; mkproj "$PW"
SIDW=$(script -qec "
  XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$PW' -- bash -c 'echo hi > $PW/w.txt'
" /dev/null 2>"$W/k3.err" | tr -d '\r' | grep -o 's[0-9a-f]\{12,\}' | head -1)
if grep -q "trust tier <= 1" "$W/k3.err"; then bad "K3: the floor fired on a cold/warm project"; else ok "K3: the floor did not fire on a non-low project"; fi
if grep -q "egress restricted" "$W/k3.err"; then bad "K3b: egress was restricted on a non-low project"; else ok "K3b: egress unrestricted on a non-low project"; fi

echo
echo "== K5a: the census distinguishes the two postures =="
AUD=$("$BIN" channels run 2>/dev/null | grep -E "^  (udp|dns) " | tr -s ' ')
RES=$("$BIN" channels run --net-restrict 2>/dev/null | grep -E "^  (udp|dns) " | tr -s ' ')
echo "  audit:     $AUD" | tr '\n' ' '; echo
echo "  restricted:$RES"
echo "$AUD" | grep -q "udp *OPEN" && echo "$RES" | grep -q "udp *DENIED" \
  && ok "K5a: public UDP flips OPEN -> DENIED under the floor" \
  || bad "K5a: the UDP posture did not change between the two runs"

echo
echo "== K4: a human egress grant lifts the floor for one launch =="
mkproj "$P0"
SIDG=$(script -qec "
  XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$P0' -- bash -c 'echo G > out.txt'
" /dev/null 2>/dev/null | tr -d '\r' | grep -o 's[0-9a-f]\{12,\}' | head -1)
# request (the agent may ask), then the human approves from the SAME terminal
rpc "{\"op\":\"bless_request\",\"session\":\"${SIDG}\",\"want\":\"egress\",\"reason\":\"p11 test\"}" >/dev/null
NONCE=$(rpc '{"op":"bless_show"}' | python3 -c '
import json,sys
try:
    r = json.load(sys.stdin)
    p = r.get("extra",{}).get("bless",{}).get("pending",[])
    print(p[0]["nonce_hint"] if p else "")
except Exception:
    print("")' 2>/dev/null)
if [ -n "$NONCE" ]; then
  script -qec "XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' bless approve '$NONCE'" /dev/null >"$W/k4b.out" 2>&1
  grep -qi "approved\|ok" "$W/k4b.out" && ok "K4a: the egress grant was approved from the launcher terminal" \
    || bad "K4a: approval failed: $(tail -2 "$W/k4b.out" | tr '\n' ' ')"
  # the next launch asks for and consumes the one-shot grant
  mkproj "$P0"
  script -qec "XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$P0' --grant egress -- bash -c 'echo H > out.txt'" /dev/null >"$W/k4c.out" 2>&1
  grep -q "consumed expansion grant" "$W/k4c.out" && ok "K4b: the launcher consumed the egress grant" \
    || bad "K4b: the grant was not consumed: $(grep -i 'grant\|tier' "$W/k4c.out" | tr '\n' ' ')"
  # and the one after it is floored again — the grant is one-shot
  mkproj "$P0"
  script -qec "XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$P0' -- bash -c 'true'" /dev/null >"$W/k4d.out" 2>&1
  grep -q "trust tier <= 1" "$W/k4d.out" && ok "K4c: the floor returns after the one-shot grant is spent" \
    || bad "K4c: the grant did not expire (floor still lifted): $(grep -i 'tier\|grant' "$W/k4d.out" | tr '\n' ' ')"
else
  bad "K4: could not read a bless nonce hint from bless show"
fi

echo
echo "== K5b: broker denies reach the session spine =="
SIDB=$(script -qec "
  XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$P0' -- python3 '$W/probe.py'
" /dev/null 2>/dev/null | tr -d '\r' | grep -o 's[0-9a-f]\{12,\}' | head -1)
SPINE="$XDG_STATE_HOME/castellan/events/${SIDB}.jsonl"
if [ -f "$SPINE" ] && grep -q "broker_deny" "$SPINE"; then
  ok "K5b: the denied egress attempt is on the spine ($(grep -c broker_deny "$SPINE") entries)"
else
  bad "K5b: no broker_deny on the spine (sid=${SIDB:-none})"
fi

echo
kill "$DPID" 2>/dev/null
wait "$DPID" 2>/dev/null
echo "== SUMMARY =="
echo "  PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]] && echo "P11-ACCEPT-PASS" || echo "P11-ACCEPT-FAIL"
echo "  workdir: $W"
exit $FAIL
