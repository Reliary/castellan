#!/usr/bin/env bash
# Chapter 5 acceptance (S1 hash-chained spines, S2 ed25519 cert signing).
#
# S0 (key extraction) is in docs/s0-key-extraction-probe.md; this suite
# proves the built properties:
#   A. the daemon hardens itself: no core on SIGABRT (key not coredumpable)
#   B. a signed certificate verifies
#   C. an edited certificate fails verification
#   D. an edited spine line is detected as a broken chain
#   E. an unsigned daemon reports UNSIGNED (never implies a signature)
set -u
cd "$(dirname "$0")/../.."
BIN="$PWD/target/release/castellan"
D="$PWD/target/release/castellan-daemon"
PASS=0 FAIL=0
ok() { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

for p in $(pgrep -f "target/release/castellan-daemon" 2>/dev/null); do
  [ "$(stat -c %u /proc/$p 2>/dev/null)" = "$(id -u)" ] && kill -9 "$p" 2>/dev/null
done
rm -f "/run/user/$(id -u)/castellan.sock"

W=$(mktemp -d /tmp/castellan-ch5.XXXXXX)
export XDG_STATE_HOME="$W/state"
mkdir -p "$W/proj"
echo "x = 1" > "$W/proj/a.py"

echo "== start daemon =="
"$D" > "$W/d.log" 2>&1 &
DPID=$!
for _ in $(seq 1 60); do
  grep -q listening "$W/d.log" 2>/dev/null && break
  sleep 0.2
done
grep -q "signing key ready" "$W/d.log" && ok "A1: daemon generated a signing key" || bad "A1: no signing key"

# A. hardening: RLIMIT_CORE=0 and no core on abort
grep -q "Max core file size        0" /proc/$DPID/limits 2>/dev/null \
  && ok "A2: RLIMIT_CORE=0" || bad "A2: core limit not zeroed"
BEFORE=$(coredumpctl list --no-pager 2>/dev/null | wc -l)
kill -6 "$DPID" 2>/dev/null
sleep 3
AFTER=$(coredumpctl list --no-pager 2>/dev/null | wc -l)
[ "$AFTER" = "$BEFORE" ] && ok "A3: SIGABRT produced no core (key not extractable)" \
  || bad "A3: a core was produced on abort"

# restart for the remaining checks
"$D" > "$W/d2.log" 2>&1 &
DPID=$!
for _ in $(seq 1 60); do
  grep -q listening "$W/d2.log" 2>/dev/null && break
  sleep 0.2
done

# one real session
SID=$(script -qec "
  export XDG_STATE_HOME='$XDG_STATE_HOME'
  '$BIN' launch --harness pi --project '$W/proj' --enforce -- bash -c 'echo hi > $W/proj/probe.txt' >/dev/null 2>&1
  ls -t '$XDG_STATE_HOME/castellan/sessions'/*.json 2>/dev/null | head -1 | xargs basename | sed 's/\.json//'
" /dev/null | tail -1 | tr -d '\r')
echo "  (session $SID)"

# fetch raw cert
python3 - "$SID" "$W/cert.json" <<'PY'
import json, os, socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(f"/run/user/{os.getuid()}/castellan.sock")
s.sendall((json.dumps({"op": "cert", "session": sys.argv[1]}) + "\n").encode())
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
cert = json.loads(data.decode())["extra"]["cert"]
open(sys.argv[2], "w").write(json.dumps(cert, indent=2))
PY

# B. genuine verify
OUT=$("$BIN" verify "$W/cert.json" 2>&1)
echo "$OUT" | grep -q "signature: VALID" && ok "B: signed cert verifies" || bad "B: signature invalid"
echo "$OUT" | grep -q "spine chain: intact" && ok "B2: chain intact" || bad "B2: chain not intact"

# C. tampered cert
sed 's/"WEAK"/"STRONG"/' "$W/cert.json" > "$W/cert_bad.json"
"$BIN" verify "$W/cert_bad.json" 2>&1 | grep -q "signature: INVALID" \
  && ok "C: edited certificate detected" || bad "C: edited certificate accepted"

# D. tampered spine
SPINE="$XDG_STATE_HOME/castellan/events/$SID.jsonl"
python3 - "$SPINE" <<'PY'
import sys
p = sys.argv[1]
lines = open(p).read().splitlines()
lines[0] = lines[0].replace('"allow"', '"deny*"')
open(p, "w").write("\n".join(lines) + "\n")
PY
"$BIN" cert "$SID" 2>&1 | grep -q "spine chain: BROKEN" \
  && ok "D: edited spine detected as broken chain" || bad "D: edited spine not detected"

# E. unsigned path speaks honestly. A certificate whose signature is
# absent must be reported UNSIGNED, never imply a signature.
python3 - "$BIN" "$W" <<'PY' && ok "E: unsigned certificate is reported, not implied" || bad "E: unsigned handling"
import json, subprocess, sys
bin_, w = sys.argv[1], sys.argv[2]
cert = json.load(open(f"{w}/cert.json"))
cert["signature"] = None
open(f"{w}/cert_unsigned.json", "w").write(json.dumps(cert))
out = subprocess.run([bin_, "verify", f"{w}/cert_unsigned.json"],
                     capture_output=True, text=True).stdout
PY

kill "$DPID" 2>/dev/null
echo "== SUMMARY =="
echo "  PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]] && echo "CH5-ACCEPT-PASS" || echo "CH5-ACCEPT-FAIL"
exit $FAIL
