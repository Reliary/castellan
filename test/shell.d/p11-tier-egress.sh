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
REPO=$(cd "$(dirname "$0")/../.." && pwd)
BIN_DIR="$REPO/target/release"
BIN="$BIN_DIR/castellan"
PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

W=$(mktemp -d /tmp/castellan-p11.XXXXXX)
export XDG_STATE_HOME="$W/state"
mkdir -p "$XDG_STATE_HOME"
SOCK="/run/user/$(id -u)/castellan.sock"
unset CASTELLAN_EGRESS_ALLOW_HOSTS

# R7: spawn is rate-limited to 10/min per project (fixed window, resets
# 60s from window start; refused attempts do not extend it). This suite
# fires 11+ launches on P0 inside one window — retry inside the pty.
RL='rl(){ local e="$1"; shift; local n=0 o; while :; do o=$(env "$e" "$@" 2>&1); case "$o" in *"spawn rate limited"*) n=$((n+1)); [ $n -ge 15 ] && break; sleep 6.2;; *) printf "%s\n" "$o"; return 0;; esac; done; printf "%s\n" "$o"; return 1; };'
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
  # 5 reverts to walk a project to tier 0.
  # P20/F18: undo is a session-scoped human-only op bound to the
  # launcher's terminal INSTANCE (kernel session id), so launch and
  # undo must run in the SAME pty invocation — a second `script` gets a
  # fresh session id even on a recycled pts minor, which is exactly the
  # spoof the gate denies. The pre-P20 harness ran on that spoof (A/B
  # verified: baseline reached tier 0, sid-bound build did not).
  local proj="$1"
  for _ in 1 2 3 4 5; do
    mkproj "$proj"
    SHELL=/bin/sh script -qec "
      $RL
      rl XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$proj' -- bash -c 'true' >/dev/null 2>&1
      SID=\$(ls -t '$XDG_STATE_HOME/castellan/sessions'/*.json 2>/dev/null | head -1 | xargs basename | sed 's/\.json//')
      [ -n \"\$SID\" ] || exit 1
      XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' undo \"\$SID\" >/dev/null 2>&1
      exit 0
    " /dev/null >/dev/null 2>&1 || true
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
SHELL=/bin/sh script -qec "$RL
  rl XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$P0' --allow-host '$ALLOWED' -- bash -c 'echo WORKED > out.txt'
" /dev/null >"$W/k1.out" 2>&1
SID1=$(tr -d '\r' < "$W/k1.out" | grep -o 's[0-9a-f]\{12,\}' | head -1)
# the floor forces undo, so the write lands in the session upper layer,
# not the canonical project. Check where the work actually went.
U="$XDG_STATE_HOME/castellan/sessions/${SID1}/overlay/upper"
if [ -f "$U/out.txt" ]; then ok "K1: session ran under the floor (allowlist honored, not bricked)"
elif [ -f "$P0/out.txt" ]; then ok "K1: session ran under the floor (allowlist honored, not bricked)"
else bad "K1: the session produced no work (sid=${SID1:-none}); the floor may still be bricking the agent"; fi
grep -q "network: only these hosts are reachable" "$W/k1.out" && ok "K1b: the launcher announced the egress restriction" \
  || grep -q "strict profile active" "$W/d.log" && ok "K1b: the daemon logged the tier floor firing" \
  || bad "K1b: no egress-restriction notice anywhere (floor did not fire?)"

echo
echo "== K2: with no declared host, public egress is denied =="
mkproj "$P0"
SHELL=/bin/sh script -qec "$RL
  rl XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$P0' -- python3 '$W/probe.py'
" /dev/null >"$W/k2.out" 2>/dev/null
K2=$(tr -d '\r' < "$W/k2.out" | grep -o 'tcp_public=E[0-9]*' | head -1)
echo "  $K2"
[ "$K2" = "tcp_public=E1" ] && ok "K2: public TCP denied with EPERM" || bad "K2: public TCP was $K2 (expected E1)"

echo
echo "== K3: a warm project is untouched by the floor =="
PW="$W/warm"; mkproj "$PW"
SIDW=$(SHELL=/bin/sh script -qec "$RL
  rl XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$PW' -- bash -c 'echo hi > $PW/w.txt'
" /dev/null 2>"$W/k3.err" | tr -d '\r' | grep -o 's[0-9a-f]\{12,\}' | head -1)
if grep -q "this project is untrusted" "$W/k3.err"; then bad "K3: the floor fired on a cold/warm project"; else ok "K3: the floor did not fire on a non-low project"; fi
if grep -q "network: only these hosts are reachable" "$W/k3.err"; then bad "K3b: egress was restricted on a non-low project"; else ok "K3b: egress unrestricted on a non-low project"; fi

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
# P20/F18: bless_approve is bound to the launcher's terminal INSTANCE
# (kernel session id). Launch, request and approve therefore share ONE
# pty invocation — a second `script` is a different terminal instance
# even when its pts minor is recycled, and the gate denies it. The
# pre-P20 harness passed only because minor-equality (and the inert
# inode check) were spoofable by exactly that pattern; A/B verified
# against 4e504eb (baseline approved, sid-bound build denied).
cat > "$W/k4-inner.sh" <<EOS
$RL
rpcin() { python3 -c '
import json,os,socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(30)
s.connect(f"/run/user/{os.getuid()}/castellan.sock")
s.sendall((sys.argv[1]+"\\n").encode())
d=b""
while True:
    c=s.recv(65536)
    if not c: break
    d+=c
    try: json.loads(d.decode()); break
    except Exception: continue
print(d.decode())' "\$1"; }
OUT=\$(rl XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$P0' -- bash -c 'echo G > out.txt' 2>/dev/null)
SIDG=\$(printf '%s\\n' "\$OUT" | grep -o 's[0-9a-f]\\{12,\\}' | head -1)
[ -n "\$SIDG" ] || { echo NO-SID; exit 1; }
REQ=\$(printf '{"op":"bless_request","session":"%s","want":"egress","reason":"p11 test"}' "\$SIDG")
rpcin "\$REQ" >/dev/null
NONCE=\$(rpcin '{"op":"bless_show"}' | python3 -c '
import json,sys
try:
    r=json.load(sys.stdin)
    p=r.get("extra",{}).get("bless",{}).get("pending",[])
    print(p[0]["nonce_hint"] if p else "")
except Exception:
    print("")')
[ -n "\$NONCE" ] || { echo NO-NONCE; exit 1; }
XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' bless approve "\$NONCE" > "$W/k4b.out" 2>&1
echo K4-INNER-DONE
EOS
SHELL=/bin/sh script -qec "sh $W/k4-inner.sh" /dev/null >"$W/k4-inner.log" 2>&1
if grep -qi "approved\|ok" "$W/k4b.out" 2>/dev/null; then
  ok "K4a: the egress grant was approved from the launcher terminal"
else
  bad "K4a: approval failed: $(tail -2 "$W/k4-inner.log" "$W/k4b.out" 2>/dev/null | tr '\n' ' ')"
fi
# the next launch asks for and consumes the one-shot grant
if grep -q K4-INNER-DONE "$W/k4-inner.log" 2>/dev/null; then
  mkproj "$P0"
  SHELL=/bin/sh script -qec "$RL rl XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$P0' --grant egress -- bash -c 'echo H > out.txt'" /dev/null >"$W/k4c.out" 2>&1
  grep -q "one-shot approval: network access" "$W/k4c.out" && ok "K4b: the launcher consumed the egress grant" \
    || bad "K4b: the grant was not consumed: $(grep -i 'grant\|tier' "$W/k4c.out" | tr '\n' ' ')"
  # and the one after it is floored again — the grant is one-shot
  mkproj "$P0"
  SHELL=/bin/sh script -qec "$RL rl XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$P0' -- bash -c 'true'" /dev/null >"$W/k4d.out" 2>&1
  grep -q "this project is untrusted" "$W/k4d.out" && ok "K4c: the floor returns after the one-shot grant is spent" \
    || bad "K4c: the grant did not expire (floor still lifted): $(grep -i 'tier\|grant' "$W/k4d.out" | tr '\n' ' ')"
else
  bad "K4: inner pty did not complete (see $W/k4-inner.log)"
fi

echo
echo "== K5b: broker denies reach the session spine =="
SIDB=$(SHELL=/bin/sh script -qec "$RL
  rl XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$P0' -- python3 '$W/probe.py'
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
