#!/usr/bin/env bash
# Phase 0 gate: the P8 drill fault-injection hook must be unreachable in
# a release build, and the release build must stay fully enforcing when
# the env vars are set.
#
# The hook used to be a runtime `CASTELLAN_TEST_DISABLE_*` read inside
# the enforcement path of Landlock, seccomp, the freezer, the canary and
# bless_approve. It is now the compile-time `drills` feature, in
# castellan-core::fault_injected.
#
# The gate asserts the CLOSED PROPERTY, not log text: with every
# `CASTELLAN_TEST_DISABLE_*` set, a release build must still deny a write
# outside the envelope and still deny ptrace. The old code returned Ok()
# from apply_envelope and let both through, so this is the direct
# regression test for the hole.
#
#   bash test/drill-gate-prod.sh [prod_cli] [drill_cli]
# Daemon paths: $CASTELLAN_PROD_DAEMON / $CASTELLAN_DRILL_DAEMON, else
# inferred as a sibling of the CLI binary.
#
# MUST run on a tty: the R7 launcher-tty gate rejects a session launch
# with no tty_nr, so `ssh -tt`.
set -u

REL=${CASTELLAN_RELEASE_DIR:-$HOME/src/castellan/target/release}
PROD=${1:-$REL/castellan}
DRILL=${2:-}
sibling() { d=$(dirname "$1"); b=$(basename "$1"); case "$b" in *-daemon) d=$(dirname "$d"); b=castellan-daemon;; esac; echo "$d/$b"; }
PROD_DAEMON=${CASTELLAN_PROD_DAEMON:-$(sibling "$PROD")}
DRILL_DAEMON=${CASTELLAN_DRILL_DAEMON:-}
[ -n "$DRILL" ] && DRILL_DAEMON=${DRILL_DAEMON:-$(sibling "$DRILL")}

WORK=$(mktemp -d /tmp/castellan-drillgate.XXXXXX)
PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

reap() {
  pkill -9 -x castellan-daemon 2>/dev/null
  pkill -9 -x castellan 2>/dev/null
  for p in $(pgrep -f "castellan-drillgate" 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
  rm -f /run/user/1000/castellan.sock
  sleep 0.4
}
trap 'reap; rm -rf "$WORK"' EXIT

mkdir -p "$WORK/proj/src"

# Probe scripts live in files: an inline python one-liner passed through
# bash -c -> ssh -> bash loses its quoting and dies before it runs, which
# looks exactly like a security failure.
cat > "$WORK/ptrace_probe.py" <<'PY'
import ctypes, sys
c = ctypes.CDLL("libc.so.6", use_errno=True)
c.ptrace.restype = ctypes.c_long
c.ptrace.argtypes = [ctypes.c_long] * 4
r = c.ptrace(0, 0, 0, 0)
sys.stdout.write("PTRACE_RC=%d ERRNO=%d\n" % (r, ctypes.get_errno()))
sys.exit(0 if r == 0 else 1)
PY

cat > "$WORK/session_probe.sh" <<SH
set -u
echo inside > '$WORK/proj/src/inside.txt' 2>/dev/null && echo IN_OK || echo IN_FAIL
echo outside > '$WORK/escape.txt' 2>/dev/null && echo OUT_OK || echo OUT_FAIL
python3 '$WORK/ptrace_probe.py' && echo PTRACE_OK || echo PTRACE_FAIL
SH

ALL_ENV=(
  CASTELLAN_TEST_DISABLE_LANDLOCK=1
  CASTELLAN_TEST_DISABLE_SECCOMP=1
  CASTELLAN_TEST_DISABLE_CENSUS=1
  CASTELLAN_TEST_DISABLE_HONEYPOT=1
  CASTELLAN_TEST_DISABLE_FREEZE=1
  CASTELLAN_TEST_DISABLE_BLESS=1
)

launch() {  # launch <cli> <state_home> <daemon_log> [env...]
  local cli=$1 state=$2 dlog=$3; shift 3
  env XDG_STATE_HOME="$state" "$@" "$cli" launch --harness claude \
    --project "$WORK/proj" --enforce -- bash "$WORK/session_probe.sh" \
    > "$WORK/session.out" 2> "$WORK/session.err"
}

check_confined() {  # check_confined <label>
  local label=$1
  grep -q IN_OK "$WORK/session.out" \
    && ok "$label: workspace write ALLOWED" \
    || bad "$label: workspace write blocked (false positive)"
  grep -q OUT_FAIL "$WORK/session.out" \
    && ok "$label: write outside envelope DENIED (Landlock live)" \
    || bad "$label: ENVELOPE ESCAPED — outside write succeeded"
  [ ! -f "$WORK/escape.txt" ] \
    && ok "$label: no escape file materialized" \
    || bad "$label: escape file exists outside the envelope"
  grep -q PTRACE_FAIL "$WORK/session.out" \
    && ok "$label: ptrace DENIED (seccomp live)" \
    || bad "$label: SECCOMP ESCAPED — ptrace succeeded"
  echo "         ptrace: $(grep -o 'PTRACE_RC=[-0-9]* ERRNO=[0-9]*' "$WORK/session.out" | head -1)"
}

echo "== release build ($PROD) =="
n=$(strings -a "$PROD" 2>/dev/null | grep -c 'FAULT INJECTION ACTIVE')
[ "$n" = "0" ] && ok "injection banner string absent from release binary" \
               || bad "injection string present in release binary ($n)"

reap
env "${ALL_ENV[@]}" "$PROD_DAEMON" > "$WORK/daemon.log" 2>&1 &
if grep -q listening "$WORK/daemon.log" || sleep 1; then :; fi
grep -q listening "$WORK/daemon.log" \
  && ok "daemon started with every injection var set ($PROD_DAEMON)" \
  || { bad "daemon failed to start ($PROD_DAEMON)"; tail -5 "$WORK/daemon.log"; exit 1; }

launch "$PROD" "$WORK/state" "$WORK/daemon.log" "${ALL_ENV[@]}"
check_confined "release"
if grep -q 'FAULT INJECTION ACTIVE' "$WORK/session.err" "$WORK/daemon.log" 2>/dev/null; then
  bad "release build announced fault injection — hook reachable in release"
else
  ok "release build announced no fault injection despite all six vars set"
fi

echo "== drills build (${DRILL:-skipped}) =="
if [ -z "$DRILL" ] || [ ! -x "$DRILL" ]; then
  echo "  SKIP: no drills build supplied (build with --features castellan-cli/drills,castellan-daemon/drills)"
else
  m=$(strings -a "$DRILL" 2>/dev/null | grep -c 'FAULT INJECTION ACTIVE')
  [ "$m" -ge 1 ] && ok "injection banner string present in drills build" \
                 || bad "drills build cannot announce injection (Koch criterion lost)"

  # One defense per launch. apply_envelope returns early on the Landlock
  # hook, so a combined LANDLOCK+SECCOMP request never reaches the seccomp
  # hook — correct fail-closed ordering, but it means the two have to be
  # probed separately to see both banners.
  for d in landlock seccomp; do
    W2=$(mktemp -d /tmp/castellan-drillgate2.XXXXXX)
    reap
    XDG_STATE_HOME="$W2/state" "$DRILL_DAEMON" > "$W2/daemon.log" 2>&1 &
    sleep 1
    env XDG_STATE_HOME="$W2/state" "CASTELLAN_TEST_DISABLE_$(echo "$d" | tr a-z A-Z)=1" \
      "$DRILL" launch --harness claude --project "$WORK/proj" --enforce -- \
      bash "$WORK/session_probe.sh" > "$W2/session.out" 2> "$W2/session.err"
    if grep -qh "FAULT INJECTION ACTIVE" "$W2/session.err" "$W2/daemon.log" 2>/dev/null; then
      ok "drills build: $d hook announced itself"
    else
      bad "drills build: $d hook did NOT announce itself"
    fi
    grep -qh "defense '$d'" "$W2/session.err" "$W2/daemon.log" 2>/dev/null \
      && ok "drills build: $d hook fired" \
      || bad "drills build: $d hook did not fire"
    if [ "$d" = landlock ]; then
      grep -q OUT_OK "$W2/session.out" \
        && ok "drills build: Landlock really is off (injection live)" \
        || bad "drills build: hook did NOT disable Landlock — P8 drill cannot fail"
    else
      grep -q PTRACE_OK "$W2/session.out" \
        && ok "drills build: seccomp really is off (injection live)" \
        || bad "drills build: hook did NOT disable seccomp"
      echo "         ptrace: $(grep -o 'PTRACE_RC=[-0-9]* ERRNO=[0-9]*' "$W2/session.out" | head -1)"
    fi
    rm -rf "$W2"
  done

  # census / honeypot / freeze / bless are reached only by session-exit,
  # canary-trip, bless-approve and orphan-escape paths — not by a launch
  # probe. Their Koch criterion lives in test/shell.d/p8-drills.sh, which
  # drives `castellan drill run` per defense. What this gate can assert
  # for all six is the release-build direction: the drills still pass with
  # every hook requested, i.e. nothing was injected.
  reap
  env "${ALL_ENV[@]}" "$PROD_DAEMON" > "$WORK/daemon2.log" 2>&1 &
  sleep 1
  env "${ALL_ENV[@]}" "$PROD" drill run > "$WORK/drills.out" 2>&1
  nfail=$(grep -c FAIL "$WORK/drills.out" 2>/dev/null || true)
  [ "${nfail:-0}" = "0" ] \
    && ok "release build: all 5 P8 drills pass with every hook requested (nothing injected)" \
    || bad "release build: $nfail drill(s) failed with hooks requested"
  grep -q 'FAULT INJECTION ACTIVE' "$WORK/daemon2.log" "$WORK/drills.out" 2>/dev/null \
    && bad "release build announced fault injection during drills" \
    || ok "release build announced no fault injection during drills"

  reap
  rm -rf "$W2"
fi

echo "GATE: $PASS passed, $FAIL failed"
[ "$FAIL" = "0" ] || exit 1
