#!/usr/bin/env bash
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

echo "== pre-clean stale state =="
for p in $(pgrep -f castellan-daemon); do
  exe=$(readlink "/proc/$p/exe" 2>/dev/null) || continue
  case "$exe" in *castellan-daemon*) kill -9 "$p";; esac
done
rm -f /run/user/$(id -u)/castellan.sock
SLICE="/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/castellan.slice"
if [[ -d "$SLICE" ]]; then
  for d in "$SLICE"/*.scope; do
    [[ -d "$d" ]] || continue
    for pid in $(cat "$d/cgroup.procs" 2>/dev/null); do kill -9 "$pid" 2>/dev/null; done
    rmdir "$d" 2>/dev/null
  done
fi
ok "stale state cleaned"

WORK=$(mktemp -d /tmp/castellan-p1.XXXXXX)
mkdir -p "$WORK/proj/src"
export XDG_STATE_HOME="$WORK/state"

echo "== start daemon =="
"$BIN/castellan-daemon" > "$WORK/daemon.log" 2>&1 &
DAPID=$!
sleep 0.5
grep -q listening "$WORK/daemon.log" && ok "daemon started" || { bad "daemon failed to start"; exit 1; }

echo "== ENFORCE: write inside envelope succeeds, outside fails =="
"$BIN/castellan" launch --harness claude --project "$WORK/proj" --enforce -- bash -c "
  echo inside > '$WORK/proj/src/inside.txt' && echo IN_OK || echo IN_FAIL
  echo outside > ~/castellan-escape.txt && echo OUT_OK || echo OUT_FAIL
  rm -f ~/castellan-escape.txt
" > "$WORK/enforce.out" 2>"$WORK/enforce.err"
SID=$(grep -o 's[0-9a-f]\{10,\}' "$WORK/enforce.err" | head -1)
[[ -n "$SID" ]] && ok "session $SID launched with --enforce" || bad "no session id in launch output"
grep -q IN_OK "$WORK/enforce.out" && ok "workspace write ALLOWED under enforce" || bad "workspace write blocked (false positive)"
grep -q OUT_FAIL "$WORK/enforce.out" && ok "home write DENIED under enforce (Landlock)" || bad "home write escaped the envelope!"
[[ ! -f ~/castellan-escape.txt ]] && ok "no escape file materialized" || { bad "escape file exists"; rm -f ~/castellan-escape.txt; }
"$BIN/castellan" kill "$SID" >/dev/null 2>&1

echo "== AUDIT: same behavior runs unrestricted but is classified =="
"$BIN/castellan" launch --harness claude --project "$WORK/proj" -- bash -c "
  echo inside > '$WORK/proj/src/inside2.txt'
  echo outside > ~/castellan-escape2.txt
  sleep 0.8
" > "$WORK/audit.out" 2>"$WORK/audit.err"
SID2=$(grep -o 's[0-9a-f]\{10,\}' "$WORK/audit.err" | head -1)
sleep 0.5
"$BIN/castellan" kill "$SID2" >/dev/null 2>&1
rm -f ~/castellan-escape2.txt
[[ -n "$SID2" ]] && ok "audit session $SID2 launched" || bad "no audit session id"
AUDIT_OUT=$("$BIN/castellan" audit "$SID2")
deny_count=$(echo "$AUDIT_OUT" | grep -c WOULD-DENY || true)
[[ "$deny_count" -ge 1 ]] && ok "audit recorded $deny_count would-deny write(s)" || bad "audit recorded nothing: $AUDIT_OUT"
echo "$AUDIT_OUT" | grep -q "castellan-escape2" && ok "would-deny names the home write" || bad "would-deny missing escape path"

echo "== ENFORCE: process tree still functional (git, compile-ish workload) =="
"$BIN/castellan" launch --harness codex --project "$WORK/proj" --enforce -- bash -c "
  cd '$WORK/proj'
  export GIT_CONFIG_GLOBAL='$WORK/proj/.gitconfig' GIT_CONFIG_SYSTEM=/dev/null
  git init -q .
  git config user.email t@t && git config user.name t
  echo hello > a.txt && git add a.txt && git commit -qm init && echo GIT_OK || echo GIT_FAIL
  awk 'BEGIN{print \"AWK_OK\"}'
" > "$WORK/workload.out" 2>&1
grep -q AWK_OK "$WORK/workload.out" && ok "child processes spawn and run under enforce" || bad "children broken under enforce"
grep -q GIT_OK "$WORK/workload.out" && ok "git workflow works under enforce" || bad "git blocked under enforce (false positive)"

echo "== seccomp: ptrace denied with EPERM under enforce =="
"$BIN/castellan" launch --harness pi --project "$WORK/proj" --enforce -- python3 -c "
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
r = libc.ptrace(16, os.getppid(), 0, 0)  # PTRACE_ATTACH would be hostile; PTRACE_TRACEME=0 used below instead
libc.ptrace(0, 0, 0, 0)
e = ctypes.get_errno()
print('PTRACE_ERRNO', e)
sys.exit(0 if e != 0 else 1)
" > "$WORK/seccomp.out" 2>&1
rc=$?
grep -q "PTRACE_ERRNO 1" "$WORK/seccomp.out" && ok "ptrace returns EPERM under seccomp" || bad "ptrace not blocked as expected: $(cat "$WORK/seccomp.out") (rc=$rc)"

echo "== daemon survives everything =="
if [[ -d "/proc/$DAPID" ]]; then ok "daemon still alive"; else bad "daemon died"; fi

rm -rf "$WORK"
echo
echo "RESULT: $PASS passed, $FAIL failed"
exit $([[ $FAIL -eq 0 ]] && echo 0 || echo 1)
