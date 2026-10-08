#!/usr/bin/env bash
# castellan I0 — the README quickstart journey, end to end.
#
# WHAT THIS IS: extracts the Quickstart fenced block from README.md and
# executes its lines against scratch state, in one pty. The point is not
# only that each step works: it is that the DOCUMENTED journey works. If
# a quickstart line rots into an invalid command, this suite goes red
# (verified with a negative control: replace `preflight` with a bogus
# verb in a README copy and the driver reports FAIL — see --selfcheck).
#
# TWO DOCUMENTED SUBSTITUTIONS (everything else runs verbatim):
#   1. `cargo build --release --workspace` -> assert `castellan` and
#      `castellan-daemon` are on PATH. Building is CI's job; the journey
#      tests the user flow after binaries exist. Release mode wraps this
#      suite against an extracted release tarball (test/release-e2e.sh).
#   2. `castellan service install` -> start a daemon directly against the
#      scratch XDG dirs. `systemctl --user` is a singleton bound to the
#      REAL $XDG_CONFIG_HOME (a scratch-XDG unit is invisible to it,
#      measured on .227), so the unit path is covered by p18-lifecycle
#      instead of being made non-hermetic here. `uninstall --yes` still
#      runs for real against the scratch dirs.
#
# RUNS ON THE EXERCISE BOX: needs a real user cgroup slice and a pty
# (the tty witness gates freeze/keep). Run under
# `systemd-run --user --scope` like the other box suites.
#
# Legs:
#   J1-Jn  every quickstart line exits 0, in order
#   J-surv restart -> keep still works (P20 rehydration)
#   J-kill kill -> cert still issues
#   J-frict friction metric: per-line wall time + user-typed command count
#
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)

SELFCHECK=0
for a in "$@"; do [[ "$a" == "--selfcheck" ]] && SELFCHECK=1; done

PASS=0; FAIL=0; NOTE=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
note() { echo "  NOTE: $1"; NOTE=$((NOTE+1)); }

# Preconditions: user manager + cargo-free box OK. The journey needs
# systemctl user for the uninstall line's service cleanup calls, but not
# for install (substituted).
if ! systemctl --user show-environment >/dev/null 2>&1; then
  echo "no user systemd manager on this box — run under systemd-run --user --scope"
  exit 3
fi
if systemctl --user is-active castellan.service >/dev/null 2>&1; then
  echo "castellan.service is ACTIVE on this box — refusing: the journey's"
  echo "uninstall line would stop the real service. Stop it first."
  exit 3
fi

W=$(mktemp -d /tmp/castellan-i0.XXXXXX)
export XDG_STATE_HOME="$W/state"
export XDG_CONFIG_HOME="$W/config"
mkdir -p "$XDG_STATE_HOME" "$XDG_CONFIG_HOME/castellan"

# Binaries on PATH: prefer whatever the caller provided (release mode
# passes CASTELLAN_BIN_DIR pointing at an extracted tarball), else the
# repo's release build.
if [ -n "${CASTELLAN_BIN_DIR:-}" ]; then
  export PATH="$CASTELLAN_BIN_DIR:$PATH"
elif ! command -v castellan >/dev/null 2>&1; then
  export PATH="$REPO/target/release:$PATH"
fi
if ! command -v castellan >/dev/null 2>&1 || ! command -v castellan-daemon >/dev/null 2>&1; then
  echo "castellan / castellan-daemon not on PATH — build with"
  echo "`cargo build --release --workspace` or pass a release bin dir."
  exit 3
fi

# Harness shim: the quickstart says `-- claude`. The shim behaves like a
# tiny agent: makes a change in the cwd (the project) and exits.
SHIM="$W/shim"; mkdir -p "$SHIM"
cat > "$SHIM/claude" <<'SH'
#!/bin/sh
echo "hello from the journey" > journey-file.txt
sleep 2
exit 0
SH
chmod +x "$SHIM/claude"
export PATH="$SHIM:$PATH"

# Extract the Quickstart block from README.md. Trailing `# comment`
# text is stripped; blank lines and the fence are dropped.
CMDS="$W/quickstart.cmds"
python3 - "${CASTELLAN_JOURNEY_README:-$REPO/README.md}" > "$CMDS" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
m = re.search(r'## Quickstart\s*```sh\n(.*?)```', text, re.S)
if not m:
    print("EXTRACT-FAIL")
    sys.exit(0)
for line in m.group(1).splitlines():
    line = line.strip()
    if not line:
        continue
    # strip trailing comments (all quickstart comments start after two+ spaces)
    line = re.sub(r'\s+#.*$', '', line).strip()
    if line:
        print(line)
PY
if grep -q '^EXTRACT-FAIL$' "$CMDS" || [ ! -s "$CMDS" ]; then
  echo "FAIL: could not extract the Quickstart block from README.md"; exit 1
fi
N_LINES=$(wc -l < "$CMDS" | tr -d ' ')

cleanup() {
  [ -n "${DPID:-}" ] && kill -9 "$DPID" 2>/dev/null
  systemctl --user stop castellan.service 2>/dev/null
  rm -f "${XDG_CONFIG_HOME}/systemd/user/castellan.service" 2>/dev/null
}
trap cleanup EXIT

echo "== I0 journey: $N_LINES quickstart lines, scratch state at $W =="

# The driver runs INSIDE the pty: every human-only op (keep/undo,
# freeze-all/thaw-all) must share the launching terminal's kernel
# session id with the launches, so the whole journey runs in one pty.
cat > "$W/inner.sh" <<'INNER'
#!/bin/bash
set -u
W="$1"; W2="$1"; CMDS="$1/quickstart.cmds"
OUT="$1/journey.log"; TIMING="$1/timing.tsv"
: > "$TIMING"
PASS=0; FAIL=0; TYPED=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); echo "PASS $1" >> "$W/verdicts"; }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); echo "FAIL $1" >> "$W/verdicts"; }

LAST_SID=""
DAEMON_PID=""
SOCK="/run/user/$(id -u)/castellan.sock"

start_scratch_dauth() {
  # substitution 2: scratch daemon instead of the user unit
  for p in $(pgrep -f "castellan-daemon" 2>/dev/null); do
    [ "$(readlink /proc/$p/exe 2>/dev/null)" = "$(command -v castellan-daemon)" ] && kill -9 "$p" 2>/dev/null
  done
  sleep 0.3
  rm -f "$SOCK"
  XDG_STATE_HOME="$XDG_STATE_HOME" XDG_CONFIG_HOME="$XDG_CONFIG_HOME" \
    "$(command -v castellan-daemon)" > "$W/d.log" 2>&1 &
  DAEMON_PID=$!
  for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
  [ -S "$SOCK" ] || { echo "daemon did not start"; cat "$W/d.log"; exit 1; }
}

n=0
mkdir -p "$W/proj"
cd "$W/proj"   # quickstart runs from a project dir; cert.json lands here
while IFS= read -r line; do
  n=$((n+1))
  step=$(printf '%02d' "$n")

  # substitution 1: binary acquisition
  case "$line" in
    cargo\ build*)
      command -v castellan >/dev/null && command -v castellan-daemon >/dev/null \
        && ok "J$step (subst) binaries present: $(castellan --version)" \
        || bad "J$step binaries missing"
      continue ;;
    *service\ install*)
      start_scratch_dauth
      ok "J$step (subst) scratch daemon up (unit path covered by p18)"
      continue ;;
  esac

  # placeholder substitution: <session> -> the last launched session
  line="${line//<session>/$LAST_SID}"

  t0=$(date +%s.%N)
  bash -c "$line" > "$W/line.$step.out" 2>&1
  rc=$?
  t1=$(date +%s.%N)
  dt=$(python3 -c "print(f'{$t1-$t0:.2f}')")
  TYPED=$((TYPED+1))
  printf '%s\t%s\t%s\n' "$step" "$dt" "$line" >> "$TIMING"

  # the cert line's stdout is the certificate the next line verifies
  case "$line" in
    *castellan\ cert*) cp "$W/line.$step.out" "$W/cert.json" ;;
  esac

  if [ "$rc" -eq 0 ]; then
    ok "J$step ${dt}s: $line"
  else
    bad "J$step (rc=$rc) ${dt}s: $line"
    sed -n '1,5p' "$W/line.$step.out" | sed 's/^/        /'
  fi

  case "$line" in
    *castellan\ launch*) LAST_SID=$(grep -o 's[0-9a-f]\{10,\}' "$W/line.$step.out" | head -1) ;;
  esac
done < "$CMDS"

# --- survival legs -----------------------------------------------------
# The quickstart's last line is `uninstall`, which removes the daemon (in
# the scratch substitution it kills it). Restart before the survival legs.
echo "== J-surv: daemon restart -> keep still works =="
start_scratch_dauth
P="$W/proj-surv"; mkdir -p "$P"; echo "x = 1" > "$P/a.py"
bash -c "castellan launch --undo --project '$P' -- claude" > "$W/surv.launch" 2>&1
SIDS=$(grep -o 's[0-9a-f]\{10,\}' "$W/surv.launch" | head -1)
if [ -z "$SIDS" ]; then
  bad "J-surv: launch under restart leg failed: $(tail -2 "$W/surv.launch" | tr '\n' ' ')"
else
  kill -9 "$DAEMON_PID" 2>/dev/null
  sleep 0.5
  rm -f "$SOCK"
  XDG_STATE_HOME="$XDG_STATE_HOME" XDG_CONFIG_HOME="$XDG_CONFIG_HOME" \
    "$(command -v castellan-daemon)" > "$W/d2.log" 2>&1 &
  DAEMON_PID=$!
  for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
  castellan keep "$SIDS" > "$W/surv.keep" 2>&1
  if [ $? -eq 0 ]; then ok "J-surv: keep after daemon restart ($SIDS)"
  else bad "J-surv: keep after restart failed: $(tail -2 "$W/surv.keep" | tr '\n' ' ')"; fi
fi

echo "== J-kill: kill -> cert still issues =="
P="$W/proj-kill"; mkdir -p "$P"; echo "x = 1" > "$P/a.py"
bash -c "castellan launch --project '$P' -- claude" > "$W/kill.launch" 2>&1
SIDK=$(grep -o 's[0-9a-f]\{10,\}' "$W/kill.launch" | head -1)
castellan kill "$SIDK" >/dev/null 2>&1
cert_out=$(castellan cert "$SIDK" --json 2>&1)
if echo "$cert_out" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null; then
  ok "J-kill: cert parses after kill ($SIDK)"
else
  bad "J-kill: cert failed after kill: $(echo "$cert_out" | head -2 | tr '\n' ' ')"
fi

# --- friction metric ---------------------------------------------------
echo "== J-frict: friction metric =="
total=$(awk -F'\t' '{s+=$2} END{print s}' "$TIMING" 2>/dev/null)
echo "  user-typed commands: $TYPED of $n quickstart lines (substitutions excluded)"
echo "  wall time across typed lines: ${total}s"
awk -F'\t' '{printf "    %s  %6ss  %s\n", $1, $2, $3}' "$TIMING"

echo "I0-PASS=$PASS I0-FAIL=$FAIL" >> "$W/verdicts"
INNER

touch "$W/verdicts"
SHELL=/bin/sh script -qec "bash '$W/inner.sh' '$W'" /dev/null > "$W/pty.log" 2>&1
PTYRC=$?

sed 's/^/  /' "$W/pty.log" | grep -E 'PASS|FAIL|==|user-typed|wall time' | sed 's/^  //' | sed 's/^/  /'
echo
# tally from the pty log (the inner writes verdicts in a shared file)
while read -r kind msg; do
  case "$kind" in
    PASS) PASS=$((PASS+1)) ;;
    FAIL) FAIL=$((FAIL+1)) ;;
  esac
done < "$W/verdicts" 2>/dev/null || true

echo "== SUMMARY =="
echo "  PASS=$PASS FAIL=$FAIL"
if [ "$SELFCHECK" = "1" ]; then
  echo "== selfcheck (K7 negative control): a corrupted quickstart line must fail the journey =="
  CORRUPT="$W/corrupt-README.md"
  sed 's/^castellan status .*$/castellan definitely-not-a-verb/' "$REPO/README.md" > "$CORRUPT"
  if grep -q "definitely-not-a-verb" "$CORRUPT"; then
    CASTELLAN_JOURNEY_README="$CORRUPT" bash "$0" > "$W/selfcheck.log" 2>&1
    if [ $? -ne 0 ]; then
      ok "selfcheck: corrupted README makes the driver go red (rot is detected)"
    else
      bad "selfcheck: corrupted README still passed — the driver does not detect rot"
    fi
  else
    bad "selfcheck: could not corrupt the README (no 'castellan status' line?)"
  fi
fi
echo "  workdir: $W"
if [ "$FAIL" -eq 0 ]; then echo "I0-JOURNEY-PASS"; exit 0; else echo "I0-JOURNEY-FAIL"; exit 1; fi
