#!/usr/bin/env bash
# P13 attempt-only probe battery. Creates no containers, no loop devices,
# writes nothing outside $WORK. Every probe is a connect/attempt that the
# kernel or broker must refuse. Verdicts compare against the frozen
# classification in docs/plans/p13-escape-sweep.md.
set -u
cd "$(dirname "$0")/../.."
BIN="$PWD/target/release"
PASS=0 FAIL=0 NOTE=0
ok()   { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
note() { NOTE=$((NOTE+1)); echo "  NOTE: $1"; }

cleanup() {
  [[ -n "${DAPID:-}" ]] && kill "$DAPID" 2>/dev/null
}
trap cleanup EXIT

for p in $(pgrep -f castellan-daemon); do
  exe=$(readlink "/proc/$p/exe" 2>/dev/null) || continue
  case "$exe" in *castellan-daemon*) kill -9 "$p";; esac
done
rm -f "/run/user/$(id -u)/castellan.sock"

WORK=$(mktemp -d /tmp/castellan-p13.XXXXXX)
mkdir -p "$WORK/proj"
export XDG_STATE_HOME="$WORK/state"

echo "== start daemon =="
"$BIN/castellan-daemon" > "$WORK/daemon.log" 2>&1 &
DAPID=$!
for _ in $(seq 1 40); do
  grep -q listening "$WORK/daemon.log" 2>/dev/null && break
  sleep 0.1
done
grep -q listening "$WORK/daemon.log" && ok "daemon started" || { bad "daemon failed"; exit 1; }

cat > "$WORK/probe.py" <<'PY'
import socket, os, errno

def tcp(ip, port, t=2):
    s = socket.socket(); s.settimeout(t)
    try:
        s.connect((ip, port)); return "CONNECTED"
    except PermissionError:
        return "DENIED-EACCES"
    except OSError as e:
        return "ERRNO-%d" % (e.errno or -1)
    finally:
        s.close()

def unix(path, t=2):
    s = socket.socket(socket.AF_UNIX); s.settimeout(t)
    try:
        s.connect(path); return "CONNECTED"
    except PermissionError:
        return "DENIED-EACCES"
    except OSError as e:
        return "ERRNO-%d" % (e.errno or -1)
    finally:
        s.close()

# E-a: loopback ssh ports under default posture (no --net/--net-restrict).
for port in (22, 2222, 2200):
    print("Ea_%d=%s" % (port, tcp("127.0.0.1", port)))
# control: non-ssh loopback still allowed (must stay open under default).
print("Ea_ctrl=%s" % tcp("127.0.0.1", 9))

# E-b: deputy sockets. Attempt-only: a bare AF_UNIX connect, no protocol.
for name, path in (
    ("docker", "/run/docker.sock"),
    ("docker2", "/var/run/docker.sock"),
    ("podman", "/run/podman/podman.sock"),
    ("systembus", "/run/dbus/system_bus_socket"),
    ("libvirt", "/var/lib/libvirt/libvirt-sock"),
):
    print("Eb_%s=%s" % (name, unix(path)))

# E-i: spine / durable-meta write attempts (forgery surface).
state = os.environ["XDG_STATE_HOME"]
session = os.environ.get("CASTELLAN_SESSION", "")
targets = {
    "spine": os.path.join(state, "castellan/events/%s.jsonl" % session),
    "spine_other": os.path.join(state, "castellan/events/p13-other.jsonl"),
    "meta": os.path.join(state, "castellan/sessions/%s.json" % session),
    "sessions_dir": os.path.join(state, "castellan/sessions"),
}
for name, path in targets.items():
    try:
        with open(path, "a") as f:
            f.write('{"p13":"probe"}\n')
        print("Ei_%s=WRITE-OK" % name)
    except PermissionError:
        print("Ei_%s=DENIED-EACCES" % name)
    except OSError as e:
        print("Ei_%s=ERRNO-%d" % (name, e.errno or -1))

# E-j: loopback deputy sweep — classify reachable listeners (attempt-only).
print("Ej_631=%s" % tcp("127.0.0.1", 631))     # CUPS
print("Ej_5355=%s" % tcp("127.0.0.1", 5355))   # LLMNR
print("Ej_2019=%s" % tcp("127.0.0.1", 2019))   # local service
print("Ej_2455=%s" % tcp("127.0.0.1", 2455))   # local python

# E-f (tolerance probe): wayland socket connect — reachability only.
xdg = os.environ.get("XDG_RUNTIME_DIR", "/run/user/%d" % os.getuid())
print("Ef_wayland=%s" % unix(os.path.join(xdg, "wayland-0")))
PY

echo "== launch enforced session (default posture) =="
# R7: the launcher-tty gate rejects a launch with no tty_nr; `script`
# allocates a real pty (same trick as test/drill-gate-prod.sh).
script -qec "$BIN/castellan launch --harness claude --project $WORK/proj --enforce -- python3 $WORK/probe.py" /dev/null \
  > "$WORK/out" 2>"$WORK/err"
SID=$(grep -o 's[0-9a-f]\{10,\}' "$WORK/out" "$WORK/err" 2>/dev/null | head -1)
[[ -n "$SID" ]] && ok "session launched ($SID)" || { bad "no session id"; tail -3 "$WORK/err" "$WORK/out"; }
[[ -n "$SID" ]] && grep -E '^(Ea|Eb|Ei|Ej|Ef)_' "$WORK/out"

echo "== verdicts vs frozen classification =="
# E-a: default posture currently OPEN (known hole) — fix flips to DENIED.
for port in 22 2222 2200; do
  if grep -q "Ea_$port=CONNECTED" "$WORK/out"; then
    note "E-a 127.0.0.1:$port CONNECTED (open — fix required, expected pre-fix)"
  elif grep -q "Ea_$port=DENIED-EACCES" "$WORK/out"; then
    ok "E-a 127.0.0.1:$port DENIED"
  else
    bad "E-a 127.0.0.1:$port unexpected: $(grep "Ea_$port" "$WORK/out")"
  fi
done
grep -qE "Ea_ctrl=(CONNECTED|ERRNO-111)" "$WORK/out" && ok "control non-ssh loopback open" || bad "control loopback wrongly closed: $(grep Ea_ctrl "$WORK/out")"

# E-b: any CONNECTED deputy = must-fix confirmed.
for name in docker docker2 podman systembus libvirt; do
  if grep -q "Eb_$name=CONNECTED" "$WORK/out"; then
    bad "E-b $name CONNECTED (one-shot vector OPEN — fix required)"
  elif grep -q "Eb_$name=DENIED-EACCES" "$WORK/out"; then
    ok "E-b $name denied"
  else
    note "E-b $name: $(grep "Eb_$name" "$WORK/out") (refused/unreachable)"
  fi
done

# E-i: any WRITE-OK on spine/meta = critical.
for name in spine spine_other meta sessions_dir; do
  if grep -q "Ei_$name=WRITE-OK" "$WORK/out"; then
    bad "E-i $name WRITABLE (evidence forgery)"
  else
    ok "E-i $name not writable"
  fi
done

# E-f: tolerance-class; record only.
grep -q "Ef_wayland=CONNECTED" "$WORK/out" && note "E-f wayland reachable (within tolerance, documented)" || note "E-f wayland: $(grep Ef_wayland "$WORK/out")"

[[ -n "$SID" ]] && "$BIN/castellan" kill "$SID" >/dev/null 2>&1

echo "== SUMMARY: PASS=$PASS FAIL=$FAIL NOTE=$NOTE =="
[[ $FAIL -eq 0 ]] && echo "P13-PROBE-PASS" || echo "P13-PROBE-FAIL"
exit $FAIL
