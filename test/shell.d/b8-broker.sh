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

# No over-block: loopback TCP.
t = socket.socket(); t.settimeout(2)
try:
    t.connect(("127.0.0.1", 9))
except PermissionError:
    print("LOOP_DENIED")
except OSError:
    print("LOOP_OK")

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

# ---- --net: destination-scoped egress -----------------------------
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
PY
"$BIN/castellan" launch --harness claude --project "$WORK/proj" --enforce --net \
  -- python3 "$WORK/net.py" > "$WORK/net.out" 2>"$WORK/net.err"
SID2=$(grep -o 's[0-9a-f]\{10,\}' "$WORK/net.err" | head -1)
grep -q PUB_DENIED "$WORK/net.out" && ok "--net denies public TCP by destination" || { bad "--net did not deny public TCP"; grep PUB "$WORK/net.out"; }
[[ -n "$SID2" ]] && "$BIN/castellan" kill "$SID2" >/dev/null 2>&1

echo "== SUMMARY =="
echo "  PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]] && echo "B8.2-ACCEPT-PASS" || echo "B8.2-ACCEPT-FAIL"
exit $FAIL
