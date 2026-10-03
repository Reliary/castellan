#!/usr/bin/env bash
# P14 esoteric-sweep acceptance. Runs on a box with a real user cgroup
# slice (the R7 launcher-tty gate rejects a launch with no tty_nr, so it
# also needs a pty). Attempt-only probes; the negative control is the
# host run of the same syscalls, which must NOT be EPERM.
set -u
cd "$(dirname "$0")/../.."
BIN="$PWD/target/release"
PASS=0 FAIL=0 NOTE=0
ok()   { PASS=$((PASS+1)); echo "  PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
note() { NOTE=$((NOTE+1)); echo "  NOTE: $1"; }
cleanup() { [[ -n "${DAPID:-}" ]] && kill "$DAPID" 2>/dev/null; }
trap cleanup EXIT

WORK=$(mktemp -d /tmp/castellan-p14.XXXXXX)
mkdir -p "$WORK/proj" "$WORK/rt" "$WORK/tgt"
export XDG_STATE_HOME="$WORK/state" XDG_RUNTIME_DIR="$WORK/rt"

"$BIN/castellan-daemon" > "$WORK/daemon.log" 2>&1 &
DAPID=$!
for _ in $(seq 1 40); do grep -q listening "$WORK/daemon.log" 2>/dev/null && break; sleep 0.1; done

cat > "$WORK/mount.py" <<'PY'
import ctypes, os, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
def sy(nr, *a):
    ctypes.set_errno(0)
    args = [ctypes.c_char_p(x) if isinstance(x, bytes)
            else (ctypes.c_void_p(None) if x is None else ctypes.c_long(x)) for x in a]
    r = libc.syscall(ctypes.c_long(nr), *args)
    return ("OK" if r >= 0 else "ERRNO-%d" % ctypes.get_errno())
CLONE_NEWUSER=0x10000000; CLONE_NEWNS=0x00020000
tgt = sys.argv[1].encode()
sy(272, CLONE_NEWUSER | CLONE_NEWNS)  # unshare
print("legacy_mount=%s" % sy(165, b"tmpfs", tgt, b"tmpfs", 0, None))
print("fsopen=%s" % sy(430, b"tmpfs", 0))
print("open_tree=%s" % sy(428, -100, b"/", 0))
print("pidfd_getfd=%s" % sy(438, 0, 0, 0))
print("process_madvise=%s" % sy(440, -1, 0, 0, 0, 0))
print("name_to_handle_at=%s" % sy(303, -100, b"/etc/hostname", 0, 0, 0))
PY

LAUNCH=$(printf '%q launch --harness claude --project %q --enforce -- python3 %q %q' \
  "$BIN/castellan" "$WORK/proj" "$WORK/mount.py" "$WORK/tgt")
script -qec "$LAUNCH" /dev/null > "$WORK/out.raw" 2>"$WORK/err.raw"
# `script` runs the command under a pty, so every line ends CRLF — strip
# the CR or the anchored ERRNO match below never fires.
tr -d '\r' < "$WORK/out.raw" > "$WORK/out"
tr -d '\r' < "$WORK/err.raw" > "$WORK/err"
SID=$(grep -oh 's[0-9a-f]\{10,\}' "$WORK/out" "$WORK/err" 2>/dev/null | head -1)
[[ -n "$SID" ]] && ok "session launched ($SID)" || bad "no session id"

# Negative control FIRST: the host must NOT be EPERM on these (the host is
# CAP-less too, so legacy_mount may fail for capability reasons — that is
# why only fsopen/open_tree/pidfd are the discriminating probes).
HOST=$(python3 "$WORK/mount.py" "$WORK/tgt" 2>/dev/null | grep -E 'fsopen|open_tree|pidfd_getfd')
grep -q 'fsopen=OK' <<<"$HOST" && ok "control: host fsopen OK (probe is discriminating)" \
  || note "control: host fsopen not OK ($(grep fsopen <<<"$HOST")) — probe may be inconclusive"

for probe in legacy_mount fsopen open_tree pidfd_getfd process_madvise name_to_handle_at; do
  line=$(grep "^$probe=" "$WORK/out" || true)
  if grep -q "^$probe=ERRNO-1$" "$WORK/out"; then
    ok "$probe EPERM (denied)"
  elif grep -q "^$probe=OK" "$WORK/out"; then
    bad "$probe=OK — declared-Hard syscall is OPEN"
  else
    bad "$probe inconclusive: $line"
  fi
done

[[ -n "$SID" ]] && "$BIN/castellan" kill "$SID" >/dev/null 2>&1
echo "== SUMMARY: PASS=$PASS FAIL=$FAIL NOTE=$NOTE =="
[[ $FAIL -eq 0 ]] && echo "P14-ACCEPT-PASS" || echo "P14-ACCEPT-FAIL"
exit $FAIL
