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

# P13 ninja F11: never touch a live daemon. XDG_RUNTIME_DIR isolates the
# socket for BOTH the probe daemon and the CLI (socket_path() honors it),
# so a real daemon on the default socket is neither killed nor stacked
# on (the daemon refuses to stack anyway — exit 3).
WORK=$(mktemp -d /tmp/castellan-p13.XXXXXX)
mkdir -p "$WORK/proj" "$WORK/rt"
export XDG_STATE_HOME="$WORK/state"
export XDG_RUNTIME_DIR="$WORK/rt"

echo "== start daemon (isolated socket) =="
"$BIN/castellan-daemon" > "$WORK/daemon.log" 2>&1 &
DAPID=$!
for _ in $(seq 1 40); do
  grep -q listening "$WORK/daemon.log" 2>/dev/null && break
  sleep 0.1
done
grep -q listening "$WORK/daemon.log" && ok "daemon started on isolated socket" || { bad "daemon failed"; tail -3 "$WORK/daemon.log"; exit 1; }

cat > "$WORK/probe.py" <<'PY'
import socket, os, errno

def tcp(ip, port, t=2):
    s = socket.socket(); s.settimeout(t)
    try:
        s.connect((ip, port)); return "CONNECTED"
    except PermissionError:
        return "DENIED-PERM"
    except OSError as e:
        return "ERRNO-%d" % (e.errno or -1)
    finally:
        s.close()

def unix(path, t=2):
    s = socket.socket(socket.AF_UNIX); s.settimeout(t)
    try:
        s.connect(path); return "CONNECTED"
    except PermissionError:
        return "DENIED-PERM"
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
    ("containerd", "/run/containerd/containerd.sock"),
):
    print("Eb_%s=%s" % (name, unix(path)))

# E-i: forgery surface — NON-DESTRUCTIVE probes (P13 ninja F11/F6).
# A successful write must never land in the real spine (it would corrupt
# the very evidence under test), and a vacuous errno must never count as
# a pass (opening a DIRECTORY O_WRONLY returns EISDIR even when the dir
# is writable — the old sessions_dir probe proved nothing).
state = os.environ["XDG_STATE_HOME"]
session = os.environ.get("CASTELLAN_SESSION", "")
events = os.path.join(state, "castellan/events")
sessions = os.path.join(state, "castellan/sessions")
spine = os.path.join(events, "%s.jsonl" % session)
meta = os.path.join(sessions, "%s.json" % session)
# (a) open the real spine/meta for write WITHOUT writing: open success
#     = writable (finding) with zero bytes touched.
for name, path in (("spine_open", spine), ("meta_open", meta)):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND)
        os.close(fd)
        print("Ei_%s=WRITE-OK" % name)
    except FileNotFoundError:
        print("Ei_%s=ENOENT" % name)
    except PermissionError:
        print("Ei_%s=DENIED-PERM" % name)
    except OSError as e:
        print("Ei_%s=ERRNO-%d" % (name, e.errno or -1))
# (b) create a SIBLING file in events/ and sessions/ (O_EXCL so we never
#     touch a real spine): proves dir writability, auto-unlinked.
for name, d in (("events_create", events), ("sessions_create", sessions)):
    p = os.path.join(d, "p13-probe-%d" % os.getpid())
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        os.unlink(p)
        print("Ei_%s=WRITE-OK" % name)
    except FileExistsError:
        try: os.unlink(p)
        except OSError: pass
        print("Ei_%s=WRITE-OK" % name)  # it was creatable
    except FileNotFoundError:
        print("Ei_%s=ENOENT" % name)
    except PermissionError:
        print("Ei_%s=DENIED-PERM" % name)
    except OSError as e:
        print("Ei_%s=ERRNO-%d" % (name, e.errno or -1))

# E-j: loopback deputy sweep — classify reachable listeners (attempt-only).
print("Ej_631=%s" % tcp("127.0.0.1", 631))     # CUPS
print("Ej_5355=%s" % tcp("127.0.0.1", 5355))   # LLMNR
print("Ej_2019=%s" % tcp("127.0.0.1", 2019))   # local service
print("Ej_2455=%s" % tcp("127.0.0.1", 2455))   # local python

# E-f (tolerance probe): wayland socket connect — reachability only.
# The REAL runtime dir (not the isolated $XDG_RUNTIME_DIR used for the
# probe daemon socket) — wayland-0 lives in the session's real XDG dir.
print("Ef_wayland=%s" % unix("/run/user/%d/wayland-0" % os.getuid()))

# P13 ninja F10: X11 reachability. CONNECTED alone is not injection —
# the server requires MIT-MAGIC-COOKIE; the probe records whether the
# socket answers AND whether a cookie source is readable (read roots
# are /), which together decide the classification.
print("Ef_x11=%s" % unix("/tmp/.X11-unix/X0"))
xa = os.environ.get("XAUTHORITY") or os.path.expanduser("~/.Xauthority")
try:
    with open(xa, "rb") as f:
        data = f.read(8)
    print("Ef_xauth=%s" % ("READABLE" if data else "EMPTY"))
except OSError as e:
    print("Ef_xauth=ERRNO-%d" % (e.errno or -1))
PY

echo "== launch enforced session (default posture) =="
# R7: the launcher-tty gate rejects a launch with no tty_nr; `script`
# allocates a real pty (same trick as test/drill-gate-prod.sh). P13 F11:
# quote the command with %q — unquoted $BIN/$WORK paths break on any
# space in the checkout or temp dir.
LAUNCH_CMD=$(printf '%q launch --harness claude --project %q --enforce -- python3 %q' \
  "$BIN/castellan" "$WORK/proj" "$WORK/probe.py")
script -qec "$LAUNCH_CMD" /dev/null > "$WORK/out" 2>"$WORK/err"
# P13 ninja F11: grep -h across two files — plain grep prefixes each match
# with "file:", which poisoned the SID extraction ("out:s18da..." was not
# a killable id, so sessions leaked after every probe run).
SID=$(grep -oh 's[0-9a-f]\{10,\}' "$WORK/out" "$WORK/err" 2>/dev/null | head -1)
[[ -n "$SID" ]] && ok "session launched ($SID)" || { bad "no session id"; tail -3 "$WORK/err" "$WORK/out"; }
[[ -n "$SID" ]] && grep -E '^(Ea|Eb|Ei|Ej|Ef)_' "$WORK/out"

echo "== verdicts vs frozen classification =="
# E-a: STRICT (P13 ninja F6). CONNECTED means the fix regressed — that
# is a FAIL, not a NOTE. Only a permission error proves the broker denied.
for port in 22 2222 2200; do
  if grep -q "Ea_$port=DENIED-PERM" "$WORK/out"; then
    ok "E-a 127.0.0.1:$port DENIED"
  elif grep -q "Ea_$port=CONNECTED" "$WORK/out"; then
    bad "E-a 127.0.0.1:$port CONNECTED — escape-port deny REGRESSED (sshd-child escape)"
  else
    bad "E-a 127.0.0.1:$port unexpected: $(grep "Ea_$port" "$WORK/out")"
  fi
done
grep -qE "Ea_ctrl=(CONNECTED|ERRNO-111)" "$WORK/out" && ok "control non-ssh loopback open" || bad "control loopback wrongly closed: $(grep Ea_ctrl "$WORK/out")"

# E-b: any CONNECTED deputy = must-fix confirmed. DENIED (broker or
# Landlock) passes; a raw errno on an absent path is "unreachable"
# (note, not pass — it proves nothing about the deny).
for name in docker docker2 podman systembus libvirt containerd; do
  if grep -q "Eb_$name=CONNECTED" "$WORK/out"; then
    bad "E-b $name CONNECTED (one-shot vector OPEN — fix required)"
  elif grep -q "Eb_$name=DENIED-PERM" "$WORK/out"; then
    ok "E-b $name denied"
  else
    note "E-b $name: $(grep "Eb_$name" "$WORK/out") (absent/unreachable — proves nothing)"
  fi
done

# E-i: STRICT (P13 ninja F6): only DENIED-PERM is a pass. WRITE-OK =
# forgery surface open. ENOENT/other errno = probe could not decide —
# never count as "not writable" (the old verdict did exactly that).
for name in spine_open meta_open events_create sessions_create; do
  line=$(grep "Ei_$name=" "$WORK/out" || true)
  if grep -q "Ei_$name=WRITE-OK" "$WORK/out"; then
    bad "E-i $name WRITABLE (evidence forgery surface open)"
  elif grep -q "Ei_$name=DENIED-PERM" "$WORK/out"; then
    ok "E-i $name denied"
  else
    bad "E-i $name inconclusive: $line (a non-permission errno must not pass)"
  fi
done

# E-f: tolerance-class; record only.
grep -q "Ef_wayland=CONNECTED" "$WORK/out" && note "E-f wayland reachable (within tolerance, documented)" || note "E-f wayland: $(grep Ef_wayland "$WORK/out")"
# P13 ninja F10: X11 probe. Pre-fix result (2026-09-30): CONNECTED +
# cookie READABLE — the plan's pre-registered trigger, so /X11-unix/X*
# joined the deputy deny list. STRICT now: CONNECTED = regression.
x11=$(grep "Ef_x11=" "$WORK/out" || true)
xauth=$(grep "Ef_xauth=" "$WORK/out" || true)
if echo "$x11" | grep -q CONNECTED; then
  bad "E-f X11 CONNECTED — seat-input deputy deny REGRESSED ($x11; $xauth)"
elif echo "$x11" | grep -q DENIED-PERM; then
  ok "E-f X11 denied ($xauth)"
else
  note "E-f X11: $x11 ($xauth) — unreachable, proves nothing"
fi

[[ -n "$SID" ]] && "$BIN/castellan" kill "$SID" >/dev/null 2>&1

echo "== SUMMARY: PASS=$PASS FAIL=$FAIL NOTE=$NOTE =="
[[ $FAIL -eq 0 ]] && echo "P13-PROBE-PASS" || echo "P13-PROBE-FAIL"
exit $FAIL
