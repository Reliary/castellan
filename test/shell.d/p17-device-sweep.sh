#!/usr/bin/env bash
# P17 — device/socket escape sweep. Plan: docs/plans/p17-dev-sockets.md.
#
# Phase-1 gates (measured .227 2026-10-03, re-run here):
#   * device ioctls on in-domain fds DENIED (Landlock ACCESS_FS_IOCTL_DEV,
#     handled since P12 with no allow rule on /) — the harm gate;
#   * write-opens on /dev DENIED (WRITE_FILE); read-opens survive but are
#     useless without ioctl (documented residual, gated as OK);
#   * vsock CONNECT denied by the broker's deny_unknown_family arm
#     (81c1a87) — previously never live-verified;
#   * AF_NETLINK exempt arm keeps getifaddrs alive (regression pin);
#   * TIOCSTI on the inherited tty dead kernel-side (legacy_tiocsti=0);
#   * raw socket creation EPERM (kernel caps; P16's "PASS" was a
#     protocol-0 probe bug, errno 93).
# Device-absent hosts skip that group as NOTE (dri card0 is absent on
# the dev box). Suites are dev-box/box-only; CI pins the family arms
# at unit level (broker tests).
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

WORK=$(mktemp -d /tmp/castellan-p17.XXXXXX)
mkdir -p "$WORK/proj" "$WORK/rt" "$WORK/state"
export XDG_STATE_HOME="$WORK/state" XDG_RUNTIME_DIR="$WORK/rt"

SYSFS=/sys/fs/cgroup

echo "== P17 setup: isolated daemon =="
"$BIN/castellan-daemon" > "$WORK/daemon.log" 2>&1 &
DAPID=$!
for _ in $(seq 1 40); do grep -q listening "$WORK/daemon.log" 2>/dev/null && break; sleep 0.1; done
grep -q listening "$WORK/daemon.log" || { bad "daemon not up"; echo "P17-DEVICE-FAIL"; exit 1; }

# probe file (device/socket battery)
PROBE="$WORK/probe.py"
cat > "$PROBE" <<'PYEOF'
import ctypes, errno, fcntl, os, socket, struct, termios

def v(name, fn):
    try:
        r = fn()
        print(f"{name}: OK {r}")
    except OSError as e:
        print(f"{name}: errno={e.errno} ({errno.errorcode.get(e.errno, '?')})")
    except Exception as e:
        print(f"{name}: EXC {type(e).__name__}: {e}")

# G-1: the ioctl probe opens FIRST and reports NOT-REACHED when the
# open fails — a DAC-denied open must never print the same errno line
# the ioctl gate greps for. P17_SEED_OPEN_FAIL forces open failure so
# the suite can prove its own assertions discriminate (seeded control).
_SEED = os.environ.get("P17_SEED_OPEN_FAIL") == "1"

def gate_open(path, flags):
    if _SEED:
        raise OSError(13, "Permission denied (seeded)")
    return os.open(path, flags)

v("kvm_open_rdonly", lambda: os.open("/dev/kvm", os.O_RDONLY))
v("kvm_open_rdwr", lambda: os.open("/dev/kvm", os.O_RDWR))
try:
    fd = gate_open("/dev/kvm", os.O_RDONLY)
except OSError as e:
    print(f"kvm_ioctl_getapi: NOT-REACHED (open errno={e.errno})")
else:
    try:
        fcntl.ioctl(fd, 0xAE00)
        print("kvm_ioctl_getapi: OK (IOCTL NOT GATED)")
    except OSError as e:
        print(f"kvm_ioctl_getapi: errno={e.errno} ({errno.errorcode.get(e.errno,'?')})")
    finally:
        os.close(fd)

v("ptmx_open_rdonly", lambda: os.open("/dev/ptmx", os.O_RDONLY | os.O_NOCTTY))
v("ptmx_open_rdwr", lambda: os.open("/dev/ptmx", os.O_RDWR | os.O_NOCTTY))
try:
    fd = gate_open("/dev/ptmx", os.O_RDONLY | os.O_NOCTTY)
except OSError as e:
    print(f"ptmx_ioctl_TIOCGPTN: NOT-REACHED (open errno={e.errno})")
else:
    try:
        n = fcntl.ioctl(fd, 0x80045430, b"\x00\x00\x00\x00")
        print(f"ptmx_ioctl_TIOCGPTN: OK pty#={struct.unpack('I', n)[0]} (alloc chain ALIVE)")
    except OSError as e:
        print(f"ptmx_ioctl_TIOCGPTN: errno={e.errno} ({errno.errorcode.get(e.errno,'?')})")
    finally:
        os.close(fd)

v("dri_open_rdonly", lambda: os.open("/dev/dri/card0", os.O_RDONLY))
v("dri_open_rdwr", lambda: os.open("/dev/dri/card0", os.O_RDWR))
try:
    fd = gate_open("/dev/dri/card0", os.O_RDONLY)
except OSError as e:
    print(f"dri_ioctl_version: NOT-REACHED (open errno={e.errno})")
else:
    try:
        fcntl.ioctl(fd, 0xc0586400, bytearray(80))
        print("dri_ioctl_version: OK (IOCTL NOT GATED)")
    except OSError as e:
        print(f"dri_ioctl_version: errno={e.errno} ({errno.errorcode.get(e.errno,'?')})")
    finally:
        os.close(fd)

v("pty_chain_openpty", lambda: (lambda m, s: (os.close(m), os.close(s), "alloc worked")[2])(*os.openpty()))

v("tty_tcgetattr_fd0", lambda: str(termios.tcgetattr(0))[:16])
try:
    fcntl.ioctl(0, 0x5412, b'x')
    print("sti_inherited_tty: OK (INJECTION OPEN)")
except OSError as e:
    print(f"sti_inherited_tty: errno={e.errno} ({errno.errorcode.get(e.errno,'?')})")
try:
    tv = open("/proc/sys/dev/tty/legacy_tiocsti").read().strip()
except OSError as e:
    tv = f"unreadable({e.errno})"
print(f"legacy_tiocsti: {tv}")

v("devnull_rw", lambda: (os.write(os.open("/dev/null", os.O_WRONLY), b"x"), "ok")[1])
v("devzero_read", lambda: os.read(os.open("/dev/zero", os.O_RDONLY), 8).hex())
v("devurandom_read", lambda: len(os.read(os.open("/dev/urandom", os.O_RDONLY), 8)))
v("input_mouse_open", lambda: os.open("/dev/input/mouse0", os.O_RDONLY))

v("raw_sock_ipproto_raw", lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, 255))
v("raw_sock_icmp", lambda: socket.socket(socket.AF_INET, socket.SOCK_RAW, 1))
v("af_packet", lambda: socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0))

try:
    s = socket.socket(getattr(socket, "AF_VSOCK", 40), socket.SOCK_STREAM)
    print("vsock_create: OK (creation ungated by design)")
    try:
        s.settimeout(2)
        s.connect((2, 1))
        print("vsock_connect: OK (BROKER WAVE-THROUGH — regression)")
    except OSError as e:
        print(f"vsock_connect: errno={e.errno} ({errno.errorcode.get(e.errno,'?')})")
    s.close()
except OSError as e:
    print(f"vsock_create: errno={e.errno} ({errno.errorcode.get(e.errno,'?')})")

def netlink_check():
    libc = ctypes.CDLL(None, use_errno=True)
    ifr = ctypes.c_void_p()
    if libc.getifaddrs(ctypes.byref(ifr)) != 0:
        raise OSError(ctypes.get_errno(), "getifaddrs")
    libc.freeifaddrs(ifr)
    return "getifaddrs ok"
v("netlink_getifaddrs", netlink_check)

v("bluetooth_l2cap", lambda: socket.socket(31, socket.SOCK_SEQPACKET, 0))

print("P17-PROBE-DONE")
PYEOF

echo "== P17 battery: one enforced session =="
OUT="$WORK/out.raw"
L=$(printf '%q launch --harness claude --project %q --enforce -- python3 %q' "$BIN/castellan" "$WORK/proj" "$PROBE")
script -qec "$L" /dev/null > "$OUT" 2>&1
tr -d '\r' < "$OUT" > "$WORK/out"
SID=$(grep -oE 's[0-9a-f]{10,}' "$WORK/out" | head -1)
[ -n "$SID" ] && SIDS+=("$SID")
grep -q 'P17-PROBE-DONE' "$WORK/out" || { bad "probe did not complete"; sed -n '1,20p' "$WORK/out"; echo "P17-DEVICE-FAIL"; exit 1; }
ok "probe completed in session ${SID:-unknown}"

has() { grep -qF "$1" "$WORK/out"; }

# --- harm gate: ioctls on in-domain device fds denied (G-1: three-way)
# denial = PASS; probe never reached the ioctl = NOTE (never PASS);
# ioctl worked = FAIL. A DAC-denied open prints NOT-REACHED, not EACCES,
# so it cannot satisfy the gate.
ioctl_gate() {
  if has "$1: errno=13 (EACCES)"; then ok "$2 denied (IOCTL_DEV gate)"
  elif has "$1: NOT-REACHED"; then note "$2 not exercised — read-open unavailable"
  elif has "$1: OK"; then bad "$2 NOT denied"
  else bad "$2 probe line missing"
  fi
}
if [ -e /dev/kvm ]; then
  ioctl_gate "kvm_ioctl_getapi" "kvm ioctl"
  has "kvm_open_rdonly: OK" && ok "kvm read-open survives (documented residual)" || note "kvm read-open: $(grep kvm_open_rdonly "$WORK/out")"
  has "kvm_open_rdwr: errno=13 (EACCES)" && ok "kvm write-open denied" || bad "kvm write-open NOT denied"
else
  note "/dev/kvm absent — kvm group skipped"
fi
if [ -e /dev/dri/card0 ]; then
  ioctl_gate "dri_ioctl_version" "drm ioctl"
  has "dri_open_rdwr: errno=13 (EACCES)" && ok "drm write-open denied" || bad "drm write-open NOT denied"
else
  note "/dev/dri/card0 absent — dri group skipped"
fi
# ptmx always present
has "ptmx_open_rdwr: errno=13 (EACCES)" && ok "ptmx write-open denied" || bad "ptmx write-open NOT denied"
ioctl_gate "ptmx_ioctl_TIOCGPTN" "pty alloc ioctl"
has "pty_chain_openpty: errno=13 (EACCES)" && ok "openpty denied" || bad "openpty succeeded"

# --- inherited-tty surface ---
has "tty_tcgetattr_fd0: OK" && ok "inherited tty ioctls alive (pre-restrict fd, by design)" || bad "inherited tcgetattr broken"
if has "sti_inherited_tty: OK"; then
  bad "TIOCSTI injection OPEN on inherited tty"
else
  ok "TIOCSTI denied ($(grep sti_inherited_tty "$WORK/out"))"
fi
has "legacy_tiocsti: 0" && ok "legacy_tiocsti=0 (kernel-side, TIOCSTI dead)" || note "legacy_tiocsti posture: $(grep legacy_tiocsti "$WORK/out")"

# --- controls: ordinary device nodes keep working ---
for c in "devnull_rw: OK" "devzero_read: OK" "devurandom_read: OK"; do
  has "$c" && ok "control $c" || bad "control broken: $c"
done

# --- F-G4: raw sockets (kernel caps path; P16 probe-bug correction) ---
has "raw_sock_ipproto_raw: errno=1 (EPERM)" && ok "raw socket creation EPERM (kernel caps)" || bad "raw socket creation allowed: $(grep raw_sock_ipproto_raw "$WORK/out")"

# --- F-G5: vsock — creation by design, CONNECT must deny ---
has "vsock_create: OK (creation ungated by design)" && ok "vsock create by design (accepted residual)" || note "vsock create: $(grep vsock_create "$WORK/out")"
has "vsock_connect: errno=1 (EPERM)" && ok "vsock CONNECT denied (deny_unknown_family arm)" || bad "vsock CONNECT allowed — F-E regression"

# --- regression: netlink exempt arm keeps resolution alive ---
has "netlink_getifaddrs: OK getifaddrs ok" && ok "netlink/getifaddrs alive" || bad "netlink broken: $(grep netlink_getifaddrs "$WORK/out")"

# --- notes: environment-dependent lines ---
grep 'input_mouse_open' "$WORK/out" | grep -q ': OK' && note "input device readable (group membership grants DAC read)" || note "input device denied: $(grep input_mouse_open "$WORK/out")"
grep 'bluetooth_l2cap' "$WORK/out" | grep -q ': OK' && note "bluetooth socket creation OK (connect hits broker deny, vsock class)" || note "bluetooth create: $(grep bluetooth_l2cap "$WORK/out")"

# --- seeded control (G-1 Koch criterion): with the probe's opens
# failing, the EACCES ioctl greps must go dark — proof the gate cannot
# PASS without a real ioctl. Second enforced session.
echo "== seeded control: open-failure must not read as ioctl denial =="
SOUT="$WORK/seeded.raw"
LS=$(printf '%q launch --harness claude --project %q --enforce -- env P17_SEED_OPEN_FAIL=1 python3 %q' "$BIN/castellan" "$WORK/proj" "$PROBE")
script -qec "$LS" /dev/null > "$SOUT" 2>&1
tr -d '\r' < "$SOUT" > "$WORK/seeded"
SID2=$(grep -oE 's[0-9a-f]{10,}' "$WORK/seeded" | head -1)
[ -n "$SID2" ] && SIDS+=("$SID2")
if ! grep -q 'P17-PROBE-DONE' "$WORK/seeded"; then
  bad "seeded probe did not complete"
elif grep -qF 'kvm_ioctl_getapi: NOT-REACHED' "$WORK/seeded" \
  && grep -qF 'ptmx_ioctl_TIOCGPTN: NOT-REACHED' "$WORK/seeded" \
  && ! grep -qF 'kvm_ioctl_getapi: errno=13 (EACCES)' "$WORK/seeded" \
  && ! grep -qF 'ptmx_ioctl_TIOCGPTN: errno=13 (EACCES)' "$WORK/seeded"; then
  ok "seeded control: open-failure degrades to NOT-REACHED; ioctl EACCES gate cannot fire"
else
  bad "seeded control: probe conflates open-failure with ioctl denial"
fi

echo "P17-DEVICE: $PASS pass, $FAIL fail, $NOTE note"
[ "$FAIL" -eq 0 ] && echo "P17-DEVICE-PASS" || echo "P17-DEVICE-FAIL"
[ "$FAIL" -eq 0 ]
