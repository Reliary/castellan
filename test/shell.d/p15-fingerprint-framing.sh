#!/usr/bin/env bash
# P15 — fingerprintability inventory (H3) + cross-session canary framing
# (H1) + forgery-RPC probe. Attempt-only. Plan: docs/plans/p15-fingerprint-framing.md.
#
# Expected PRE-FIX: H1 RED = victim framed (frozen + canary_trip on its
# spine). Expected POST-FIX per K1-K3: attacker frozen (canary_framing),
# victim clean; honest self-use still trips (K2).
set -u
cd "$(dirname "$0")/../.."
BIN="$PWD/target/release"
PASS=0 FAIL=0 NOTE=0
ok()   { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
note() { NOTE=$((NOTE+1)); echo "  NOTE: $1"; }
cleanup() {
  for sid in "${SIDS[@]:-}"; do
    freeze="$SYSFS/user.slice/user-$UID.slice/user@$UID.service/castellan.slice/$sid.scope/cgroup.freeze"
    [ -f "$freeze" ] && echo 0 > "$freeze" 2>/dev/null
    "$BIN/castellan" kill "$sid" >/dev/null 2>&1
  done
  [ -n "${DAPID:-}" ] && kill "$DAPID" 2>/dev/null
}
trap cleanup EXIT
SIDS=()

WORK=$(mktemp -d /tmp/castellan-p15.XXXXXX)
mkdir -p "$WORK/proj" "$WORK/rt" "$WORK/state"
export XDG_STATE_HOME="$WORK/state" XDG_RUNTIME_DIR="$WORK/rt"
SYSFS=/sys/fs/cgroup
STATE="$WORK/state"

"$BIN/castellan-daemon" > "$WORK/daemon.log" 2>&1 &
DAPID=$!
for _ in $(seq 1 40); do grep -q listening "$WORK/daemon.log" 2>/dev/null && break; sleep 0.1; done
grep -q honeypot "$WORK/daemon.log" || { bad "daemon honeypot not up"; echo "P15-PRE-FAIL"; exit 1; }

launch() { # launch <outfile> <python-file|sleep> [args...]
  local out=$1; shift
  local cmd="python3 $1"; shift
  [ $# -gt 0 ] && cmd="$cmd $*"
  local L; L=$(printf '%q launch --harness claude --project %q --enforce -- %s' "$BIN/castellan" "$WORK/proj" "$cmd")
  script -qec "$L" /dev/null > "$out.raw" 2>&1
  tr -d '\r' < "$out.raw" > "$out"
}

sid_of() {
  # `launch` only writes the tr'd outfile after script returns; a
  # backgrounded long-lived session is detected from the raw capture.
  local f="$1" r="$1.raw"
  if [ -f "$f" ]; then grep -oE 's[0-9a-f]{10,}' "$f" | head -1
  elif [ -f "$r" ]; then grep -oE 's[0-9a-f]{10,}' "$r" | head -1
  fi
}

freeze_of() {
  local f="$SYSFS/user.slice/user-$UID.slice/user@$UID.service/castellan.slice/$1.scope/cgroup.freeze"
  [ -f "$f" ] && cat "$f" || echo "absent"
}

echo "== H1 setup: victim B launched + canary registered (inventory needs it) =="
cat > "$WORK/sleep.py" <<'PY'
import time; time.sleep(180)
PY
launch "$WORK/b.out" "$WORK/sleep.py" &
BPID=$!
SIDB=""
for _ in $(seq 1 50); do SIDB=$(sid_of "$WORK/b.out" 2>/dev/null); [ -n "$SIDB" ] && break; sleep 0.2; done
[ -n "$SIDB" ] && SIDS+=("$SIDB")
if [ -z "$SIDB" ]; then bad "victim session B never launched"; else
  ok "victim B launched ($SIDB)"
  "$BIN/castellan" canary "$SIDB" >/dev/null 2>&1 && ok "canary registered for B" || bad "canary register failed for B"
  sleep 1
fi

echo "== H3: fingerprint inventory (from inside an enforced session) =="
cat > "$WORK/inv.py" <<'PY'
import os, re, socket, struct, sys, glob
def show(k, v): print(f"INV {k}={v}")
me = os.environ.get("CASTELLAN_SESSION", "")
show("ENV_SESSION_SET", "yes" if me else "no")
td = os.environ.get("TMPDIR", "")
show("ENV_TMPDIR_CASTELLAN", "yes" if "castellan" in td else "no")
try:
    cg = open("/proc/self/cgroup").read().strip().replace("\n", ";")
    show("CGROUP", cg[:160])
    show("CGROUP_NAMES_TOOL", "yes" if "castellan" in cg else "no")
except Exception as e: show("CGROUP", f"ERR {e}")
try:
    st = open("/proc/self/status").read()
    secc = [l for l in st.splitlines() if l.startswith("Seccomp")]
    nnp = [l for l in st.splitlines() if l.startswith("NoNewPrivs")]
    show("STATUS", (" ".join(secc + nnp))[:80])
except Exception as e: show("STATUS", f"ERR {e}")
p = os.getppid(); chain = []
for _ in range(4):
    try:
        cmd = open(f"/proc/{p}/cmdline", "rb").read().replace(b"\0", b" ").decode(errors="replace")
        chain.append(f"{p}:{cmd[:70]}")
        p = int(open(f"/proc/{p}/stat").read().split()[3])
    except Exception: break
show("ANCESTORS", " | ".join(chain)[:280])
try:
    ux = [l.split()[-1] for l in open("/proc/net/unix") if "castellan" in l]
    show("UNIX_SOCK", ",".join(sorted(set(ux)))[:140])
except Exception as e: show("UNIX_SOCK", f"ERR {e}")
try:
    comms = set()
    for d in glob.glob("/proc/[0-9]*/comm"):
        try:
            c = open(d).read().strip()
            if "castellan" in c or "relay" in c: comms.add(c)
        except Exception: pass
    show("PROC_COMM", ",".join(sorted(comms)) or "none")
except Exception as e: show("PROC_COMM", f"ERR {e}")
ca = os.environ.get("SSL_CERT_FILE", "")
show("ENV_SSL_CERT_FILE", "yes" if ca else "no")
if ca:
    try:
        b = open(ca, "rb").read()
        show("CERT_NAMES_TOOL", "yes" if b"castellan" in b else "no")
        m = re.search(rb"[\x20-\x7e]{0,20}castellan[\x20-\x7e]{0,20}", b)
        show("CERT_MARKER", m.group().decode(errors="replace") if m else "none")
    except Exception as e: show("CERT_NAMES_TOOL", f"ERR {e}")
# EPERM-signature discriminator: io_uring_setup works unprivileged on
# this kernel (host control proves it) but is seccomp-denied in-session.
# Python has no os.syscall — go through libc.
NR = 425
try:
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    r = libc.syscall(ctypes.c_long(NR), ctypes.c_long(0), ctypes.c_long(0))
    if r >= 0: show("IO_URING", f"OK ret={r}")
    else: show("IO_URING", f"ERRNO-{ctypes.get_errno()}")
except Exception as e: show("IO_URING", f"ERR {e}")
# state dir visibility (the ledger + sibling-canary oracle).
# TMPDIR = <state>/castellan/sessions/<sid>/tmp → three dirnames up.
cast_dir = os.path.dirname(os.path.dirname(os.path.dirname(td)))
show("STATE_PARENT", cast_dir or "unset")
if cast_dir and os.path.isdir(cast_dir):
    try:
        entries = os.listdir(cast_dir)
        show("STATE_LISTING", ",".join(sorted(entries))[:160])
        led = None
        for cand in ("registry.jsonl", "canary.jsonl"):
            if os.path.exists(os.path.join(cast_dir, cand)): led = cand; break
        if led:
            lines = open(os.path.join(cast_dir, led)).read().splitlines()
            keys = sorted({k for l in lines if l.startswith("{") for k in __import__("json").loads(l)})
            show("LEDGER_READ", f"{led} lines={len(lines)} keys={','.join(keys)}")
        else: show("LEDGER_READ", "absent")
    except Exception as e: show("STATE_LISTING", f"ERR {e}")
# sibling canary readability + honeypot discovery + forgery RPC + forced
# proxy path — the H1 prerequisites, all from inside the session.
sib = None
try:
    base = os.path.join(cast_dir, "sessions")
    for d in sorted(os.listdir(base)):
        if not d or d == me: continue
        for sub in ("dotfiles", "canary", "cache"):
            p = os.path.join(base, d, sub, "credentials")
            if os.path.exists(p): sib = (d, p); break
        if sib: break
except Exception as e: sib = None
show("SIBLING_CANARY", f"{sib[0]} {sib[1]}" if sib else "not-found")
def rpc(req):
    # Isolated-socket first: /run/user/<uid>/castellan.sock may be a
    # stale or foreign daemon whose honeypot port is NOT ours.
    paths = [os.path.join(os.environ.get("XDG_RUNTIME_DIR", ""), "castellan.sock"),
             f"/run/user/{os.getuid()}/castellan.sock"]
    last = "no-socket"
    for path in paths:
        if not path or not os.path.exists(path): continue
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(3)
            s.connect(path)
            s.sendall((req + "\n").encode())
            return s.recv(4096).decode(errors="replace").strip()
        except Exception as e: last = f"ERR {e}"
    return last
hp = rpc('{"op":"honeypot_port"}')
show("HONEYPOT_RPC", hp[:160])
if sib:
    forg = rpc('{"op":"canary_register","session":"%s","project":"","harness":""}' % sib[0])
    show("FORGERY_RPC_CANARY_REGISTER", forg[:160])
    # the hosts.yml marker lives INSIDE the planted file — read it,
    # otherwise this gate passes without testing anything.
    try:
        hy = os.path.join(os.path.dirname(sib[1]), "hosts.yml")
        ht = open(hy).read()
        show("HOSTS_MARKER", "castellan-canary" if "castellan-canary" in ht else "clean")
        if "castellan-canary" not in ht:
            import re as _r2
            m2 = _r2.search(r"user:\s*(\S+)", ht)
            if m2: show("HOSTS_USER", m2.group(1))
    except Exception as e: show("HOSTS_MARKER", f"ERR {e}")
    try:
        import re as _re
        txt = open(sib[1]).read()
        m = _re.search(r"(AKIA[0-9A-Z]{16,}|ghp_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,})", txt)
        show("SIBLING_SECRET", f"{m.group(1)[:6]}...({len(m.group(1))}ch)" if m else "parse-fail")
    except Exception as e: show("SIBLING_SECRET", f"ERR {e}")
# forced-proxy CONNECT to the honeypot (secondary framing path)
px = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or ""
show("ENV_PROXY", "yes" if px else "no")
if px and hp and '"port"' in hp:
    try:
        import json as _j
        port = int(_j.loads(hp).get("extra", _j.loads(hp)).get("port", 0) or 0)
    except Exception:
        port = 0
    if not port:
        try: port = int(_j.loads(hp)["extra"]["port"])
        except Exception: port = 0
    if port:
        try:
            host = px.split("//")[-1].split(":")[0]; pport = int(px.rsplit(":", 1)[-1].rstrip("/"))
            c = socket.create_connection((host, pport), timeout=3)
            c.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
            st = c.recv(256).decode(errors="replace").split("\r\n")[0]
            show("PROXY_FORCED_LOOPBACK_CONNECT", st); c.close()
        except Exception as e: show("PROXY_FORCED_LOOPBACK_CONNECT", f"ERR {e}")
print("INV-DONE")
PY

launch "$WORK/inv.out" "$WORK/inv.py"
grep -q INV-DONE "$WORK/inv.out" || bad "inventory script did not run"
while IFS= read -r line; do echo "  $line"; done < <(grep '^INV ' "$WORK/inv.out")

echo "== H1: cross-session framing (attacker A sends victim B's canary) =="
if [ -z "$SIDB" ]; then
  bad "no victim B; attack skipped"
else
  cat > "$WORK/attack.py" <<'PY'
import os, socket, json, sys, glob, re
me = os.environ.get("CASTELLAN_SESSION", "")
td = os.environ.get("TMPDIR", "")
# TMPDIR = <state>/castellan/sessions/<sid>/tmp → three dirnames up.
cast_dir = os.path.dirname(os.path.dirname(os.path.dirname(td)))
base = os.path.join(cast_dir, "sessions")
victim = None
for d in sorted(os.listdir(base)):
    if d == me: continue
    for sub in ("dotfiles", "canary", "cache"):
        p = os.path.join(base, d, sub, "credentials")
        if os.path.exists(p): victim = (d, p); break
    if victim: break
if not victim: print("ATTACK no-victim-canary"); sys.exit(1)
txt = open(victim[1]).read()
m = re.search(r"(AKIA[0-9A-Z]{16,}|ghp_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,})", txt)
if not m: print("ATTACK secret-parse-fail"); sys.exit(1)
secret = m.group(1)
def rpc(req):
    paths = [os.path.join(os.environ.get("XDG_RUNTIME_DIR", ""), "castellan.sock"),
             f"/run/user/{os.getuid()}/castellan.sock"]
    for path in paths:
        if not path or not os.path.exists(path): continue
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(3)
            s.connect(path); s.sendall((json.dumps(req) + "\n").encode())
            return json.loads(s.recv(4096).decode())
        except Exception: pass
    return {}
hp = rpc({"op": "honeypot_port"})
port = int((hp.get("extra") or {}).get("port") or (hp.get("port") or 0))
if not port: print("ATTACK no-port"); sys.exit(1)
c = socket.create_connection(("127.0.0.1", port), timeout=3)
c.sendall(secret.encode())
try: c.settimeout(3); resp = c.recv(256)
except Exception: resp = b""
c.close()
print(f"ATTACK sent victim={victim[0]} secret={secret[:6]}... resp={resp[:40]!r}")
print("ATTACK-DONE")
PY
  # background: post-fix the SENDER freezes (K1) — a foreground launch
  # would block on the frozen supervisor forever.
  launch "$WORK/a.out" "$WORK/attack.py" &
  APID=$!
  # With in-loop hit evaluation the freeze can land BEFORE attack.py
  # prints its DONE line (the process is stopped mid-recv) — poll for
  # either signal.
  SIDA=""
  for _ in $(seq 1 80); do
    SIDA=$(sid_of "$WORK/a.out" 2>/dev/null)
    [ -n "$SIDA" ] && [ "$(freeze_of "$SIDA")" = "1" ] && break
    grep -qE 'ATTACK-DONE|ATTACK no-|ATTACK secret' "$WORK/a.out.raw" 2>/dev/null && break
    sleep 0.5
  done
  tr -d '\r' < "$WORK/a.out.raw" > "$WORK/a.out" 2>/dev/null
  AOUT=$(grep -E 'ATTACK' "$WORK/a.out" | tail -3 | tr '\n' ' ')
  [ -n "$SIDA" ] && SIDS+=("$SIDA")
  AFREEZE=$(freeze_of "${SIDA:-none}")
  echo "  attacker output: $AOUT"
  # completion proof: DONE printed, OR the sender is frozen — freezing
  # implies the trip fired implies the secret arrived.
  if grep -q ATTACK-DONE "$WORK/a.out" || [ "$AFREEZE" = "1" ]; then
    ok "attack landed (DONE printed or sender frozen)"
  else
    bad "attack did not complete: $AOUT"
  fi

  BFREEZE=$(freeze_of "$SIDB")
  # NOTE: no `|| echo 0` — grep -c prints 0 AND exits 1 on a clean
  # file, so the fallback would append a second line ("0\n0") and the
  # equality gates below would fail exactly when they should pass.
  BTRIP=$(grep -c canary_trip "$STATE/castellan/events/$SIDB.jsonl" 2>/dev/null)
  BTRIP=${BTRIP:-0}
  ATRIP=$(grep -cE 'canary_framing|canary_trip' "$STATE/castellan/events/${SIDA:-none}.jsonl" 2>/dev/null)
  ATRIP=${ATRIP:-0}
  echo "  victim B freeze=$BFREEZE trips=$BTRIP | attacker A freeze=$AFREEZE trips=$ATRIP"
  echo "  H1-STATE victim_freeze=$BFREEZE victim_trips=$BTRIP attacker_freeze=$AFREEZE attacker_trips=$ATRIP"
  # K1 (asserted, not pass-through): the victim must be clean and the
  # attacker must pay. Post-fix expected: victim 0/0, attacker 1/≥1.
  # Pre-fix negative control: victim 1/1 → this gate goes red.
  if [ "$BFREEZE" = "0" ] && [ "${BTRIP%$'\n'}" = "0" ]; then
    if [ "$AFREEZE" = "1" ] || [ "${ATRIP%$'\n'}" != "0" ]; then
      ok "K1: framing failed closed (victim clean, sender pays)"
    else
      bad "K1: framing unattributed — victim clean but sender did not pay (freeze=$AFREEZE trips=$ATRIP)"
    fi
  else
    bad "K1: VICTIM FRAMED (freeze=$BFREEZE trips=$BTRIP) — sender resolved to owner"
  fi

  # H2 (asserted): no canary marker may identify the trap by name.
  H2DIR=$(grep '^INV SIBLING_CANARY=' "$WORK/inv.out" | head -1)
  if [ -z "$H2DIR" ] || echo "$H2DIR" | grep -q 'not-found'; then
    bad "H2: sibling plant not found (gate vacuous)"
  elif echo "$H2DIR" | grep -qE '/canary/'; then
    bad "H2: plant dir still self-labels (${H2DIR#INV SIBLING_CANARY=})"
  else
    ok "H2: plant dir carries no canary marker"
  fi
  H2HOSTS=$(grep '^INV HOSTS_MARKER=' "$WORK/inv.out" | head -1)
  if [ -z "$H2HOSTS" ]; then
    bad "H2: hosts.yml marker check did not run (gate vacuous)"
  elif echo "$H2HOSTS" | grep -q 'castellan-canary'; then
    bad "H2: hosts.yml username still self-labels"
  else
    ok "H2: hosts.yml carries no canary marker"
  fi
  H2LEDGER=$(grep '^INV LEDGER_READ=' "$WORK/inv.out" | head -1)
  if [ -z "$H2LEDGER" ] || echo "$H2LEDGER" | grep -q 'absent'; then
    bad "H2: ledger not readable (gate vacuous)"
  elif echo "$H2LEDGER" | grep -q 'canary.jsonl'; then
    bad "H2: ledger still self-labels (${H2LEDGER#INV LEDGER_READ=})"
  else
    ok "H2: ledger filename carries no canary marker"
  fi
fi

echo "== K2: honest self-use (session sends its OWN canary) =="
cat > "$WORK/selfuse.py" <<'PY'
import os, socket, json, sys, re, time
td = os.environ.get("TMPDIR", "")
sess = os.path.dirname(td)
p = None
# the host registers our canary right after detecting our session id —
# poll for it (register is an explicit op, not automatic at spawn).
for _ in range(60):
    for sub in ("dotfiles", "canary", "cache"):
        c = os.path.join(sess, sub, "credentials")
        if os.path.exists(c): p = c; break
    if p: break
    time.sleep(0.5)
if not p: print("SELF no-own-canary"); sys.exit(1)
m = re.search(r"(AKIA[0-9A-Z]{16,}|ghp_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,})", open(p).read())
if not m: print("SELF parse-fail"); sys.exit(1)
def rpc(req):
    paths = [os.path.join(os.environ.get("XDG_RUNTIME_DIR", ""), "castellan.sock"),
             f"/run/user/{os.getuid()}/castellan.sock"]
    for path in paths:
        if not path or not os.path.exists(path): continue
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(3)
            s.connect(path); s.sendall((json.dumps(req) + "\n").encode())
            return json.loads(s.recv(4096).decode())
        except Exception: pass
    return {}
hp = rpc({"op": "honeypot_port"})
port = int((hp.get("extra") or {}).get("port") or (hp.get("port") or 0))
if not port: print("SELF no-port"); sys.exit(1)
c = socket.create_connection(("127.0.0.1", port), timeout=3)
c.sendall(m.group(1).encode())
try: c.settimeout(3); resp = c.recv(256)
except Exception: resp = b""
c.close()
print(f"SELF sent own-secret resp={resp[:40]!r}")
print("SELF-DONE")
PY
# background: the script polls for its own canary while the host
# registers it (register needs the session id the launch prints).
launch "$WORK/c.out" "$WORK/selfuse.py" &
CPID=$!
SIDC=""
for _ in $(seq 1 50); do SIDC=$(sid_of "$WORK/c.out" 2>/dev/null); [ -n "$SIDC" ] && break; sleep 0.2; done
[ -n "$SIDC" ] && SIDS+=("$SIDC")
if [ -n "$SIDC" ]; then
  "$BIN/castellan" canary "$SIDC" >/dev/null 2>&1 && ok "canary registered for C" || bad "canary register failed for C"
fi
for _ in $(seq 1 80); do
  [ -n "$SIDC" ] && [ "$(freeze_of "$SIDC")" = "1" ] && break
  grep -qE 'SELF-DONE|SELF no-own|SELF parse|SELF no-port' "$WORK/c.out.raw" 2>/dev/null && break
  sleep 0.5
done
tr -d '\r' < "$WORK/c.out.raw" > "$WORK/c.out" 2>/dev/null
# DONE print or self-freeze both prove the secret arrived (early hit
# evaluation can stop the process before it prints).
if grep -q SELF-DONE "$WORK/c.out" || [ "$(freeze_of "${SIDC:-none}")" = "1" ]; then
  ok "self-use landed (DONE printed or sender frozen)"
else
  bad "self-use failed: $(grep SELF "$WORK/c.out" | tr '\n' ' ')"
fi
sleep 1
if [ -n "$SIDC" ]; then
  CFREEZE=$(freeze_of "$SIDC")
  CTRIP=$(grep -c canary_trip "$STATE/castellan/events/$SIDC.jsonl" 2>/dev/null)
  CTRIP=${CTRIP:-0}
  echo "  self C freeze=$CFREEZE trips=$CTRIP"
  echo "  K2-STATE self_freeze=$CFREEZE self_trips=$CTRIP"
  # K2 (asserted): honest self-use must still trip — attribution must
  # not cost the detection the canary exists for.
  if [ "$CFREEZE" = "1" ] && [ "${CTRIP%$'\n'}" != "0" ]; then
    ok "K2: honest self-use still trips and freezes"
  else
    bad "K2: honest self-use lost (freeze=$CFREEZE trips=$CTRIP)"
  fi
else
  bad "self-use session id not found"
fi

echo "== SUMMARY: PASS=$PASS FAIL=$FAIL NOTE=$NOTE =="
if [ "$FAIL" = "0" ]; then echo "P15-PROBE-PASS"; else echo "P15-PROBE-FAIL"; fi
exit $FAIL
