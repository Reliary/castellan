#!/usr/bin/env bash
# B8.2 live acceptance: the seccomp user-notification broker.
#
# Two structural holes close here:
#   T4 escape  — both routes to the systemd user manager must FAIL from
#                inside an enforced session: the private manager socket
#                AND the session bus (org.freedesktop.systemd1 is
#                exported there too, and systemd-run falls back to it).
#   --net      — destination-scoped egress (Landlock ABI4 net rules are
#                port-scoped and TCP-only).
# Both must close WITHOUT over-blocking ordinary unix sockets, loopback,
# or a git workflow.
#
# Probes live in script files: inline `bash -c "..."` nests three quote
# levels and mangles backslashes (found building this suite).
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

# ---- T4: both manager routes denied, no over-block ----------------
cat > "$WORK/t4.py" <<PY
import socket, os, subprocess

# Route 1: the private manager socket, via systemd-run.
r1 = subprocess.run(["systemd-run", "--user", "--scope", "--quiet", "true"],
                    capture_output=True)
print("ROUTE1_OK" if r1.returncode == 0 else "ROUTE1_BLOCKED")

# Route 2: StartTransientUnit over the SESSION BUS. This is the route
# systemd-run falls back to; deny the private socket alone and this
# still launches an arbitrary command outside the scope.
r2 = subprocess.run([
    "busctl", "--user", "call",
    "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
    "org.freedesktop.systemd1.Manager", "StartTransientUnit",
    r"ssa(sv)a(sa(sv))",
    "castellan-esc-accept.service", "replace",
    "1", "ExecStart", "a(sasb)", "1", "/bin/sh", "1", "/bin/sh",
    "false", "0",
], capture_output=True)
# A successful call prints a job object; a denied bus gives EPERM.
out = r2.stdout.decode() + r2.stderr.decode()
print("ROUTE2_OK" if "job/" in out else "ROUTE2_BLOCKED")
print("ROUTE2_RAW:" + out.strip().replace(chr(10), " ")[:120])

# No over-block: an ordinary (absent) unix socket must fail with
# FileNotFound/Refused, never PermissionError.
s = socket.socket(socket.AF_UNIX)
try:
    s.connect("/run/user/%d/castellan-b82-ok.sock" % os.getuid())
except PermissionError:
    print("UNIX_DENIED")
except OSError:
    print("UNIX_OK")
else:
    print("UNIX_OK")

# No over-block: loopback TCP (non-ssh ports).
t = socket.socket(); t.settimeout(2)
try:
    t.connect(("127.0.0.1", 9))
except PermissionError:
    print("LOOP_DENIED")
except OSError:
    print("LOOP_OK")

# HN ssh-localhost escape (2026-09-30): the broker under --net-restrict
# (with_llm_only) must deny the client connect to loopback ssh ports —
# the command would run in an sshd child outside all three layers.
# Audit posture (this suite's default launch: --enforce without --net)
# leaves ssh alone, so this probe documents the posture boundary rather
# than asserting a deny here; the deny itself is asserted live in the
# --net-restrict section below and in broker unit tests.
for port in (22, 2222, 2200):
    s = socket.socket(); s.settimeout(2)
    try:
        s.connect(("127.0.0.1", port))
    except PermissionError:
        print("SSH22_DENIED_%d" % port)
    except OSError:
        print("SSH22_OTHER_%d" % port)
    else:
        print("SSH22_CONNECTED_%d" % port)
    finally:
        s.close()

# No over-block: git must still work.
import shutil
g = subprocess.run(["git", "-c", "commit.gpgsign=false", "init", "-q", "."],
                   cwd=os.environ["PROBE_CWD"], capture_output=True)
g = subprocess.run(["git", "config", "user.email", "t@t"], cwd=os.environ["PROBE_CWD"], capture_output=True)
g = subprocess.run(["git", "config", "user.name", "t"], cwd=os.environ["PROBE_CWD"], capture_output=True)
open(os.path.join(os.environ["PROBE_CWD"], "f.txt"), "w").write("x")
subprocess.run(["git", "add", "f.txt"], cwd=os.environ["PROBE_CWD"], capture_output=True)
g = subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-qm", "one"],
                   cwd=os.environ["PROBE_CWD"], capture_output=True)
print("GIT_OK" if g.returncode == 0 else "GIT_FAIL")
PY

PROBE_CWD="$WORK/proj" "$BIN/castellan" launch --harness claude --project "$WORK/proj" \
  --enforce -- python3 "$WORK/t4.py" > "$WORK/t4.out" 2>"$WORK/t4.err"
SID=$(grep -o 's[0-9a-f]\{10,\}' "$WORK/t4.err" | head -1)
[[ -n "$SID" ]] && ok "session launched" || bad "no session id"

grep -q ROUTE1_BLOCKED "$WORK/t4.out" && ok "route 1 (private manager socket) DENIED" || { bad "route 1 open"; grep ROUTE1 "$WORK/t4.out"; }
grep -q ROUTE2_BLOCKED "$WORK/t4.out" && ok "route 2 (session bus StartTransientUnit) DENIED" || { bad "route 2 open — bus escape works"; grep ROUTE2_RAW "$WORK/t4.out"; }
grep -q UNIX_OK "$WORK/t4.out" && ok "ordinary unix socket still allowed" || bad "ordinary unix socket wrongly denied"
grep -q LOOP_OK "$WORK/t4.out" && ok "loopback TCP still allowed" || bad "loopback TCP wrongly denied"
grep -q GIT_OK "$WORK/t4.out" && ok "git workflow survives" || bad "git broken"
# A launched unit would leave a job on the manager; assert none.
if systemctl --user is-active castellan-esc-accept.service >/dev/null 2>&1; then
  bad "escaped transient unit is active"
  systemctl --user stop castellan-esc-accept.service 2>/dev/null
else
  ok "no escaped transient unit active"
fi
[[ -n "$SID" ]] && "$BIN/castellan" kill "$SID" >/dev/null 2>&1

# ---- --net: destination-scoped egress restriction -----------------------------
# NOTE on mechanisms: `--net` is Landlock port-scoped (Loopback ports =
# [honeypot, proxy]), so 127.0.0.1:22 dies at LANDLOCK here, not at the
# broker. The broker ssh deny (loopback-ssh) applies under --net-restrict
# (with_llm_only). Both layers must deny; the suite asserts each under
# its own flag so a regression in either layer goes red with the layer
# named in the failure.
echo "== --net: destination-scoped egress restriction =="
cat > "$WORK/net.py" <<'PY'
import socket
s = socket.socket(); s.settimeout(3)
try:
    s.connect(("1.2.3.4", 443))
except PermissionError:
    print("PUB_DENIED")
except OSError as e:
    print("PUB_OTHER:%s" % e.errno)
# HN ssh-localhost escape under --net (Landlock layer): port 22 is not
# in [honeypot, proxy], so Landlock denies with EPERM.
for port in (22, 2222, 2200):
    t = socket.socket(); t.settimeout(2)
    try:
        t.connect(("127.0.0.1", port))
    except PermissionError:
        print("SSH_DENIED_%d" % port)
    except OSError:
        print("SSH_OTHER_%d" % port)
    else:
        print("SSH_CONNECTED_%d" % port)
    finally:
        t.close()
PY
"$BIN/castellan" launch --harness claude --project "$WORK/proj" --enforce --net \
  -- python3 "$WORK/net.py" > "$WORK/net.out" 2>"$WORK/net.err"
SID2=$(grep -o 's[0-9a-f]\{10,\}' "$WORK/net.err" | head -1)
grep -q PUB_DENIED "$WORK/net.out" && ok "--net denies public TCP by destination" || { bad "--net did not deny public TCP"; grep PUB "$WORK/net.out"; }
for port in 22 2222 2200; do
  grep -q "SSH_DENIED_$port" "$WORK/net.out" && ok "--net (Landlock) denies loopback ssh 127.0.0.1:$port" || { bad "--net left loopback ssh 127.0.0.1:$port open"; grep SSH "$WORK/net.out"; }
done
[[ -n "$SID2" ]] && "$BIN/castellan" kill "$SID2" >/dev/null 2>&1

echo "== --net-restrict: broker loopback-ssh deny =="
cat > "$WORK/nr.py" <<'PY'
import socket
# Same ssh probes, now under the broker destination policy (with_llm_only).
# Landlock is Open here, so a deny is PROOF the broker's loopback-ssh rule fired.
for port in (22, 2222, 2200):
    t = socket.socket(); t.settimeout(2)
    try:
        t.connect(("127.0.0.1", port))
    except PermissionError:
        print("NR_SSH_DENIED_%d" % port)
    except OSError:
        print("NR_SSH_OTHER_%d" % port)
    else:
        print("NR_SSH_CONNECTED_%d" % port)
    finally:
        t.close()
# Honeypot-adjacent loopback must survive (no over-block).
t = socket.socket(); t.settimeout(2)
try:
    t.connect(("127.0.0.1", 9))
except PermissionError:
    print("NR_LOOP_DENIED")
except OSError:
    print("NR_LOOP_OK")
PY
"$BIN/castellan" launch --harness claude --project "$WORK/proj" --enforce --net-restrict \
  -- python3 "$WORK/nr.py" > "$WORK/nr.out" 2>"$WORK/nr.err"
SID3=$(grep -o 's[0-9a-f]\{10,\}' "$WORK/nr.err" | head -1)
for port in 22 2222 2200; do
  grep -q "NR_SSH_DENIED_$port" "$WORK/nr.out" && ok "--net-restrict (broker) denies loopback ssh 127.0.0.1:$port" || { bad "--net-restrict left loopback ssh 127.0.0.1:$port open — sshd-child escape works"; grep NR_SSH "$WORK/nr.out"; }
done
grep -q NR_LOOP_OK "$WORK/nr.out" && ok "--net-restrict leaves non-ssh loopback alone" || { bad "--net-restrict over-blocked loopback"; grep NR_LOOP "$WORK/nr.out"; }
[[ -n "$SID3" ]] && "$BIN/castellan" kill "$SID3" >/dev/null 2>&1

echo "== SUMMARY =="
echo "  PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]] && echo "B8.2-ACCEPT-PASS" || echo "B8.2-ACCEPT-FAIL"
exit $FAIL
