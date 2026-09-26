#!/usr/bin/env bash
# P12 acceptance — egress proxy + daemon keyring (credential injection).
#
# Criteria are pre-committed in docs/plans/p12-egress-proxy-keyring.md.
# A failure is recorded, not softened.
#
#   K1  credentials stay out of the envelope: real token never appears
#       in the session env, state dir, or session json; the CA key is
#       unreadable from /proc/<daemon>/mem (S0 hardening holds for the
#       proxy CA too, which lives in daemon memory only)
#   K2  injection works end-to-end   -> cargo test -p castellan-proxy
#       (stub TLS upstream sees the real header, never the canary)
#   K3  allowlist is kernel-hard, proxy-hard, operator-owned:
#       K3a direct public TCP with proxy env present -> EPERM (broker)
#       K3b agent-declared foreign proxy env does not open a kernel path
#       K3c CONNECT to a non-allowlisted host -> proxy 403
#   K4  fail-closed on proxy death: after `proxy off`, the proxy port
#       refuses AND direct public TCP is still EPERM (no fallback)
#   K5  workspace-poisoned keyring.toml is never consulted: the
#       session's keyring_sha equals the config-dir file's sha256 and
#       the poison token appears nowhere in state
#   K6  unbound host inside the allowlist is proxied with NO injection
#       -> cargo test -p castellan-proxy
#   K7  session env carries HTTPS_PROXY + SSL_CERT_FILE, and the CA
#       bundle parses (CERTIFICATE present)
#   K8  two sessions get distinct per-session CA files
#   K9  spine has egress_inject rows and the S1 hash chain verifies
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
BIN_DIR="$REPO/target/release"
BIN="$BIN_DIR/castellan"
PASS=0 FAIL=0
ok()  { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }

W=$(mktemp -d /tmp/castellan-p12.XXXXXX)
export XDG_STATE_HOME="$W/state"
mkdir -p "$XDG_STATE_HOME"
SOCK="/run/user/$(id -u)/castellan.sock"
unset CASTELLAN_EGRESS_ALLOW_HOSTS
export XDG_CONFIG_HOME="$W/config"
mkdir -p "$XDG_CONFIG_HOME/castellan"

# K1: the real credential. It must never appear outside this file.
SECRET_TOKEN="P12-SECRET-TOKEN-DO-NOT-LEAK-9f3a"
cat > "$XDG_CONFIG_HOME/castellan/keyring.toml" <<EOF
[[credential]]
name = "llm"
scheme = "bearer"
token = "$SECRET_TOKEN"
hosts = ["api.example.com", "*.example.com"]
EOF
KEYRING_SHA=$(python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$XDG_CONFIG_HOME/castellan/keyring.toml")

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

mkproj() { mkdir -p "$1"; printf 'x = 1\n' > "$1/a.py"; }

echo "== K1: keyring loads, secret never leaks =="
ST=$(rpc '{"op":"proxy_status"}')
echo "$ST" | python3 -c 'import json,sys; r=json.load(sys.stdin); e=r.get("extra",{}).get("proxies",{}); assert e.get("credentials")==1, e; print("credentials=1")' >/dev/null \
  && ok "K1a: daemon loaded 1 credential from the config dir" \
  || bad "K1a: proxy_status did not report the credential: $ST"
echo "$ST" | grep -q "$SECRET_TOKEN" && bad "K1b: proxy_status echoes the token" || ok "K1b: proxy_status does not echo the token"
grep -q "$SECRET_TOKEN" "$W/d.log" && bad "K1c: token leaked into the daemon log" || ok "K1c: token absent from daemon log"

echo
echo "== K7/K8: session env + per-session CA =="
PW="$W/pw"; mkproj "$PW"
launch_env() { # $1 proj, $2 outfile-basename, $3 extra flags...
  local proj="$1" out="$2"; shift 2
  local log="${out%.txt}.launch"
  script -qec "
    XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$proj' $@ -- python3 -c \"
import os, pathlib
p = pathlib.Path('$proj')
(p / '$out').write_text(
    'HTTPS_PROXY=' + os.environ.get('HTTPS_PROXY','') + '\n'
  + 'HTTP_PROXY=' + os.environ.get('HTTP_PROXY','') + '\n'
  + 'NO_PROXY=' + os.environ.get('NO_PROXY','') + '\n'
  + 'SSL_CERT_FILE=' + os.environ.get('SSL_CERT_FILE','') + '\n'
  + 'NODE_EXTRA_CA_CERTS=' + os.environ.get('NODE_EXTRA_CA_CERTS','') + '\n'
  + 'REQUESTS_CA_BUNDLE=' + os.environ.get('REQUESTS_CA_BUNDLE','') + '\n'
  + 'CARGO_HTTP_CAINFO=' + os.environ.get('CARGO_HTTP_CAINFO','') + '\n'
  + 'CASTELLAN_SESSION=' + os.environ.get('CASTELLAN_SESSION','') + '\n')
\" 
  " /dev/null >"$W/$log" 2>&1
}
launch_env "$PW" env1.txt
SID1=$(tr -d '\r' < "$W/env1.launch" | grep -o 's[0-9a-f]\{12,\}' | head -1)
find_env1() {
  for f in "$PW/env1.txt" "$XDG_STATE_HOME/castellan/sessions/${SID1}/overlay/upper/env1.txt"; do
    [ -f "$f" ] && cat "$f" && return 0
  done
  return 1
}
ENV1=$(find_env1 || true)
if [ -z "$ENV1" ]; then
  bad "K7a: session produced no env file (sid=${SID1:-none})"
else
  echo "$ENV1" | grep -q "^HTTPS_PROXY=http://127.0.0.1:[0-9]" \
    && ok "K7a: HTTPS_PROXY points at the session proxy" \
    || bad "K7a: HTTPS_PROXY missing/wrong: $(echo "$ENV1" | grep HTTPS_PROXY)"
  echo "$ENV1" | grep -q "^NO_PROXY=localhost,127.0.0.1" \
    && ok "K7b: NO_PROXY protects the honeypot path" \
    || bad "K7b: NO_PROXY wrong: $(echo "$ENV1" | grep NO_PROXY)"
  CA1=$(echo "$ENV1" | sed -n 's/^SSL_CERT_FILE=//p')
  if [ -n "$CA1" ] && [ -f "$CA1" ] && grep -q "BEGIN CERTIFICATE" "$CA1"; then
    ok "K7c: SSL_CERT_FILE exists and parses ($CA1)"
  else
    bad "K7c: SSL_CERT_FILE unusable: '$CA1'"
  fi
  echo "$ENV1" | grep -q "^CASTELLAN_SESSION=s" \
    && ok "K7d: session tag still set alongside proxy env" \
    || bad "K7d: CASTELLAN_SESSION lost"
fi
CA2_PROJ="$W/pw2"; mkproj "$CA2_PROJ"
launch_env "$CA2_PROJ" env2.txt
SID2=$(tr -d '\r' < "$W/env2.launch" | grep -o 's[0-9a-f]\{12,\}' | head -1)
CA1=$(echo "$ENV1" | sed -n 's/^SSL_CERT_FILE=//p')
CA2=""
for f in "$CA2_PROJ/env2.txt" "$XDG_STATE_HOME/castellan/sessions/${SID2}/overlay/upper/env2.txt"; do
  [ -f "$f" ] && CA2=$(sed -n 's/^SSL_CERT_FILE=//p' "$f")
done
if [ -n "$CA1" ] && [ -n "$CA2" ] && [ "$CA1" != "$CA2" ] \
  && [ "$(sha256sum "$CA1" 2>/dev/null | cut -d' ' -f1)" != "$(sha256sum "$CA2" 2>/dev/null | cut -d' ' -f1)" ]; then
  ok "K8: each session gets a distinct CA bundle (fingerprint changes per session)"
else
  bad "K8: CA bundles identical or missing (ca1='$CA1' ca2='$CA2')"
fi

echo
echo "== K1: CA key unreadable from the daemon's /proc (S0 boundary) =="
python3 - "$DPID" <<'PY' && ok "K1d: /proc/<daemon>/mem is EACCES (CA key memory-only, non-dumpable)" || bad "K1d: daemon memory readable — S0 hardening broken"
import sys
pid = int(sys.argv[1])
try:
    with open(f"/proc/{pid}/mem", "rb") as f:
        f.read(1)
    sys.exit(1)
except PermissionError:
    sys.exit(0)
except OSError:
    sys.exit(1)
PY

echo
echo "== K1: no secret material in state =="
LEAK=$(grep -rl "$SECRET_TOKEN" "$XDG_STATE_HOME" 2>/dev/null | head -3)
if [ -z "$LEAK" ]; then
  ok "K1e: token appears nowhere in the state dir"
else
  bad "K1e: token found in: $LEAK"
fi
if [ -n "$SID1" ]; then
  KS=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('keyring_sha',''))" "$XDG_STATE_HOME/castellan/sessions/${SID1}.json" 2>/dev/null || echo missing)
  [ "$KS" = "$KEYRING_SHA" ] && ok "K1f: session pins keyring_sha = config-dir sha256" \
    || bad "K1f: session keyring_sha='$KS' expected '$KEYRING_SHA'"
fi

echo
echo "== K5: workspace-poisoned keyring.toml is ignored =="
PP="$W/poisoned"; mkproj "$PP"
cat > "$PP/keyring.toml" <<EOF
[[credential]]
name = "evil"
scheme = "bearer"
token = "POISON-TOKEN-e5b7"
hosts = ["127.0.0.1"]
EOF
launch_env "$PP" env3.txt
SID3=$(tr -d '\r' < "$W/env3.launch" | grep -o 's[0-9a-f]\{12,\}' | head -1)
if [ -n "$SID3" ]; then
  KS3=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('keyring_sha',''))" "$XDG_STATE_HOME/castellan/sessions/${SID3}.json" 2>/dev/null || echo missing)
  [ "$KS3" = "$KEYRING_SHA" ] && ok "K5a: poisoned project did not change the session's keyring pin" \
    || bad "K5a: keyring_sha='$KS3' (poison reached the pin?)"
  if grep -rq "POISON-TOKEN-e5b7" "$XDG_STATE_HOME/castellan/sessions/${SID3}.json" \
    "$XDG_STATE_HOME/castellan/events/${SID3}.jsonl" 2>/dev/null; then
    bad "K5b: poison token reached daemon state"
  else
    ok "K5b: poison token absent from daemon state"
  fi
else
  bad "K5: launch failed (no session id)"
fi

echo
echo "== K2/K6/K3c-integration: proxy crate tests =="
if (cd "$REPO" && cargo test -p castellan-proxy -p castellan-keyring > "$W/proxy-tests.log" 2>&1); then
  ok "K2/K6: end-to-end MITM tests pass (injection, no-injection, 403, poison)"
else
  bad "K2/K6: proxy tests failed — see $W/proxy-tests.log"
fi

echo
echo "== K3c/K12: in-session CONNECT through the proxy =="
# Session binds its own loopback listener (the upstream), CONNECTs the
# proxy to it, completes TLS against the session CA, sends a request.
# A non-allowlisted host must get 403 before any dial.
cat > "$W/tunnel.py" <<'PY'
import os, socket, ssl, sys, pathlib
out = pathlib.Path(sys.argv[1])
proxy = os.environ.get("HTTPS_PROXY", "")
if not proxy:
    out.write_text("no_proxy_env\n"); sys.exit(0)
pport = int(proxy.rsplit(":", 1)[1])
results = []

def connect_hdr(authority):
    s = socket.create_connection(("127.0.0.1", pport), timeout=5)
    s.sendall(f"CONNECT {authority} HTTP/1.1\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        c = s.recv(1)
        if not c:
            break
        head += c
    return s, head.decode(errors="replace")

# (a) allowlisted (127.0.0.1 is the declared host): tunnel + TLS + request
srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(1)
srv.settimeout(6)
up_port = srv.getsockname()[1]
s, head = connect_hdr(f"127.0.0.1:{up_port}")
results.append("allow=" + head.split(" ")[1] if " " in head else "allow=?")
if head.startswith("HTTP/1.1 200"):
    try:
        ctx = ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE"))
        tls = ctx.wrap_socket(s, server_hostname="127.0.0.1")
        tls.sendall(b"GET /p12 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        tls.settimeout(4)
        try:
            tls.read(64)
            results.append("tls=read_ok")
        except Exception as e:
            results.append("tls=" + type(e).__name__)
        tls.close()
    except Exception as e:
        results.append("tls=" + type(e).__name__ + ":" + str(e)[:300])
    # accept the proxy's upstream dial so it is not left hanging
    try:
        conn, _ = srv.accept()
        conn.close()
    except Exception:
        results.append("upstream=no_accept")
else:
    results.append("tunnel=denied")
srv.close()

# (b) non-allowlisted host: 403, no dial attempted
try:
    s2, head2 = connect_hdr("evil.example:443")
    results.append("deny=" + head2.split(" ")[1] if " " in head2 else "deny=?")
    s2.close()
except Exception as e:
    results.append("deny=" + type(e).__name__)

# (c) kernel posture checks (direct public TCP is the broker's, not the proxy's)
try:
    d = socket.create_connection(("1.2.3.4", 443), timeout=3)
    d.close()
    results.append("direct_public=CONNECTED")
except OSError as e:
    results.append(f"direct_public=E{e.errno}")
# (d) a foreign proxy env must not open a kernel path
os.environ["HTTPS_PROXY"] = "http://9.9.9.9:3128"
try:
    f = socket.create_connection(("9.9.9.9", 3128), timeout=3)
    f.close()
    results.append("foreign_proxy=CONNECTED")
except OSError as e:
    results.append(f"foreign_proxy=E{e.errno}")

out.write_text(" ".join(results) + "\n")
PY
PK="$W/restricted"; mkproj "$PK"
script -qec "
  XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$PK' --net-restrict --allow-host 127.0.0.1 -- python3 '$W/tunnel.py' '$PK/tunnel.out'
" /dev/null >"$W/tunnel.launch" 2>&1
SIDT=$(tr -d '\r' < "$W/tunnel.launch" | grep -o 's[0-9a-f]\{12,\}' | head -1)
TUN=""
for f in "$PK/tunnel.out" "$XDG_STATE_HOME/castellan/sessions/${SIDT}/overlay/upper/tunnel.out" "$W/tunnel.out"; do
  [ -f "$f" ] && TUN=$(cat "$f")
done
echo "  $TUN"
echo "$TUN" | grep -q "allow=200" && ok "K3c-1: allowlisted CONNECT tunnels (200)" || bad "K3c-1: allowlisted CONNECT failed: $TUN"
echo "$TUN" | grep -q "deny=403" && ok "K3c-2: non-allowlisted CONNECT refused (403)" || bad "K3c-2: no 403 for evil.example: $TUN"
echo "$TUN" | grep -q "direct_public=E1" && ok "K3a: direct public TCP still EPERM (broker, proxy-independent)" || bad "K3a: direct public TCP: $(echo "$TUN" | grep -o 'direct_public=[^ ]*')"
echo "$TUN" | grep -q "foreign_proxy=E1" && ok "K3b: agent-set foreign proxy env does not open a kernel path" || bad "K3b: foreign proxy path: $(echo "$TUN" | grep -o 'foreign_proxy=[^ ]*')"

echo
echo "== K9: spine rows + S1 chain =="
if [ -n "$SIDT" ] && grep -q "egress_inject" "$XDG_STATE_HOME/castellan/events/${SIDT}.jsonl" 2>/dev/null; then
  ok "K9a: egress_inject rows on the session spine ($(grep -c egress_inject "$XDG_STATE_HOME/castellan/events/${SIDT}.jsonl"))"
else
  bad "K9a: no egress_inject on spine (sid=${SIDT:-none})"
fi
if grep -q "egress_deny" "$XDG_STATE_HOME/castellan/events/${SIDT}.jsonl" 2>/dev/null; then
  ok "K9b: egress_deny recorded for the 403"
else
  bad "K9b: no egress_deny row"
fi
python3 - "$XDG_STATE_HOME/castellan/events/${SIDT}.jsonl" <<'PY' && ok "K9c: S1 hash chain intact over the proxy rows" || bad "K9c: spine chain broken"
import hashlib, json, sys
zero = "0" * 64
prev = zero
checked = 0
with open(sys.argv[1]) as f:
    for line in f:
        ev = json.loads(line)
        if not ev.get("hash"):
            continue
        canon = "{}|{}|{}|{}|{}|{}".format(
            ev["ts"], ev["session"], ev["kind"], ev["path"], ev["verdict"], ev["prev"])
        expect = hashlib.sha256(canon.encode()).hexdigest()
        if ev["prev"] != prev or ev["hash"] != expect:
            sys.exit(1)
        prev = ev["hash"]
        checked += 1
sys.exit(0 if checked > 0 else 1)
PY

echo
echo "== K4: proxy off is fail-closed (no silent fallback) =="
# Marker-file handshake proved fragile (session-side visibility timing).
# Protocol now: harness discovers the port from proxy_status, proves
# OPEN, issues off, proves E111 — while the session independently polls
# its own proxy until it observes REFUSED (the inside view), then
# checks that direct egress is still kernel-denied.
P4="$W/k4"; mkproj "$P4"
cat > "$W/k4.py" <<'PY'
import os, pathlib, socket, sys, time
out = pathlib.Path(sys.argv[1])
proxy = os.environ.get("HTTPS_PROXY", "")
pport = int(proxy.rsplit(":", 1)[1]) if proxy else 0
def stamp(m):
    return f"[{time.time():.2f}] {m}\n"
events = [stamp(f"start port={pport}")]
def try_proxy():
    try:
        s = socket.create_connection(("127.0.0.1", pport), timeout=1)
        s.close()
        return True
    except OSError:
        return False
deadline = time.time() + 90
closed = False
while time.time() < deadline:
    if not try_proxy():
        events.append(stamp("REFUSED"))
        closed = True
        break
    time.sleep(0.4)
if not closed:
    events.append(stamp("TIMEOUT_STILL_OPEN"))
try:
    d = socket.create_connection(("1.2.3.4", 443), timeout=3)
    d.close()
    events.append(stamp("direct=CONNECTED"))
except OSError as e:
    events.append(stamp(f"direct=E{e.errno}"))
out.write_text("".join(events))
PY
script -qec "
  XDG_STATE_HOME='$XDG_STATE_HOME' '$BIN' launch --harness claude --project '$P4' --net-restrict --allow-host 127.0.0.1 -- python3 '$W/k4.py' '$P4/k4.out'
" /dev/null >"$W/k4.launch" 2>&1 &
for _ in $(seq 1 60); do SIDK=$(tr -d '\r' < "$W/k4.launch" 2>/dev/null | grep -o 's[0-9a-f]\{12,\}' | head -1); [ -n "$SIDK" ] && break; sleep 0.3; done
k4_out() {
  for f in "$P4/k4.out" "$XDG_STATE_HOME/castellan/sessions/${SIDK}/overlay/upper/k4.out"; do
    [ -f "$f" ] && cat "$f" && return 0
  done
  return 1
}
K4PORT=""
for _ in $(seq 1 50); do
  K4PORT=$(rpc '{"op":"proxy_status"}' | python3 -c "
import json,sys
try:
    r=json.load(sys.stdin)
    for p in r.get('extra',{}).get('proxies',{}).get('live',[]):
        if p['session']=='$SIDK': print(p['port']); break
except Exception: pass")
  [ -n "$K4PORT" ] && break
  sleep 0.2
done
if [ -z "$K4PORT" ]; then
  bad "K4: no proxy port in proxy_status for ${SIDK:-?}"
else
  R=$(python3 -c "
import socket,sys
try:
    s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=1); s.close(); print('pre:OPEN')
except OSError as e: print(f'pre:E{e.errno}')" "$K4PORT")
  echo "  $R"
  [ "$R" = "pre:OPEN" ] && ok "K4-pre: proxy port $K4PORT open before off" || bad "K4-pre: $R"
  OFF_RESP=$(rpc '{"op":"proxy_off","session":null}')
  echo "  off: $(echo "$OFF_RESP" | head -c 160)..."
  sleep 0.5
  R=$(python3 -c "
import socket,sys
try:
    s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=1); s.close(); print('post:OPEN')
except OSError as e: print(f'post:E{e.errno}')" "$K4PORT")
  echo "  $R"
  [ "$R" = "post:E111" ] && ok "K4a: harness sees ECONNREFUSED after proxy_off" || bad "K4a: post-off port state $R"
  INSIDE=""
  for _ in $(seq 1 75); do
    INSIDE=$(k4_out 2>/dev/null || true)
    case "$INSIDE" in *REFUSED*|*TIMEOUT*) break ;; esac
    sleep 0.4
  done
  echo "$INSIDE" | grep -q "REFUSED" && ok "K4b: the session itself observed the proxy refuse (inside view)" \
    || bad "K4b: session never saw REFUSED: $(echo "$INSIDE" | tr '\n' ' ' | head -c 200)"
  echo "$INSIDE" | grep -q "direct=E1" && ok "K4c: direct egress still EPERM for the session (kernel path independent)" \
    || bad "K4c: direct path from inside: $(echo "$INSIDE" | tr '\n' ' ' | head -c 200)"
fi

echo
kill "$DPID" 2>/dev/null
wait "$DPID" 2>/dev/null
echo "== SUMMARY =="
echo "  PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]] && echo "P12-ACCEPT-PASS" || echo "P12-ACCEPT-FAIL"
echo "  workdir: $W"
exit $FAIL
