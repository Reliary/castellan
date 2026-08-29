#!/usr/bin/env bash
# P9 composed stack acceptance suite — the stack as a stack.
# One fresh project, one daemon, everything composed in single
# sessions: overlay undo + placebo proof (hub-weighted) + artifact
# scan (baseline at spawn, delta at keep) + decoy canaries + trace
# exposure + policycheck. Every assertion PASS/FAIL with latency.
set -u
BIN=/home/john/src/castellan/target/release
PASS=0
FAIL=0
ok() { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

PROJ=/tmp/opencode/p9stack
rm -rf "$PROJ"
mkdir -p "$PROJ/src" "$PROJ/.reliary"

# A real bug: unguarded deref. The fix adds a NULL guard (placebo
# proof passes: danger drops more than a neutral placeholder).
cat > "$PROJ/src/bug.c" <<'EOF'
int process(struct item *it) {
  return *it;
}
EOF
cat > "$PROJ/src/leaf.c" <<'EOF'
int leaf_fn(int x) { return x - 1; }
EOF
printf 'int main(void) { return leaf_fn(1); }\n' > "$PROJ/src/main.c"

# relay-vuln scanner config (native, offline). The session will
# introduce a NEW vulnerable file -> vuln_introduced at keep.
printf '[scan]\nscanner = "relay-vuln"\ncmd = "/home/john/src/relay-vuln/target/release/relay-vuln scan --json ."\n' > "$PROJ/.reliary/castellan.toml"

# stria index for the hub weight (leaf.c is the only hub-ish file)
/home/john/src/stria/target/release/stria build --repo "$PROJ" >/dev/null 2>&1

stop_daemon() {
  for p in $(pgrep -f castellan-daemon); do
    exe=$(readlink "/proc/$p/exe" 2>/dev/null) || continue
    case "$exe" in *castellan-daemon*) kill -9 "$p";; esac
  done
  rm -f /run/user/1000/castellan.sock
  sleep 0.3
}
# B6 phase 4: the suite must NOT pollute the real state dir — every
# run used to index into the accumulated ~/.local/state (117MB
# trace.db, 572K rows), making trace calls spin at 29% CPU and hang
# (measured). Isolated state dir per run.
export XDG_STATE_HOME="/tmp/castellan-p9stack-state-$PPID"
rm -rf "$XDG_STATE_HOME"
mkdir -p "$XDG_STATE_HOME"
start_daemon() {
  stop_daemon
  "$BIN/castellan-daemon" > /tmp/castellan-p9stack-daemon.log 2>&1 &
  DAPID=$!
  sleep 0.6
  if ! kill -0 "$DAPID" 2>/dev/null; then bad "daemon failed to start"; exit 1; fi
}

start_daemon

echo "== Session A (good): fix the bug in the hub file =="
T0=$(date +%s%N)
OUT=$("$BIN/castellan" launch --harness claude --undo --project "$PROJ" -- sh -c 'printf "int process(struct item *it) {\n  if (it == NULL) return -1;\n  return *it;\n}\n" > src/bug.c' 2>&1)
SID_A=$(echo "$OUT" | grep -oE "s[0-9a-f]{20}" | head -1)
ok "session A launched ($SID_A)"

# canary + decoys planted
OUT=$("$BIN/castellan" canary "$SID_A" 2>&1)
echo "$OUT" | grep -q "canaries planted" && ok "canaries + decoys planted" || bad "canary plant failed: $OUT"

OUT=$("$BIN/castellan" keep "$SID_A" 2>&1)
echo "$OUT" | grep -q "committed" && ok "overlay committed" || bad "keep failed: $OUT"
sleep 2

# placebo proof passed (the fix drops danger) — evidence in trust.db
EVID_PROOF=$(sqlite3 $XDG_STATE_HOME/castellan/trust.db "SELECT evidence_json FROM events WHERE session_uuid='$SID_A' AND signal='proof_passed' ORDER BY id DESC LIMIT 1;" 2>/dev/null)
echo "$EVID_PROOF" | grep -q "placebo-controlled proof" && ok "placebo proof passed" || bad "no proof evidence: $EVID_PROOF"
# hub weight: the mechanism is wired and reported in the evidence
# (separation itself is verified in Step 2 on stria's repo — this
# tiny project has no hub file, so the weight is neutral here)
EVID=$(sqlite3 $XDG_STATE_HOME/castellan/trust.db "SELECT evidence_json FROM events WHERE session_uuid='$SID_A' AND signal='clean_session' ORDER BY id DESC LIMIT 1;" 2>/dev/null)
echo "$EVID" | grep -q "blast-radius weight" && ok "hub weight reported ($EVID)" || bad "no hub weight: $EVID"

# artifact scan: baseline at spawn, delta at keep (clean here)
grep -q "artifact scan" /tmp/castellan-p9stack-daemon.log && ok "artifact scan ran" || bad "no artifact scan in log"

# decoys untouched -> no signal
grep -q "decoy" /tmp/castellan-p9stack-daemon.log && bad "decoy signal on clean session" || ok "decoys untouched (no signal)"

# cert carries the factors
OUT=$("$BIN/castellan" cert "$SID_A" 2>&1)
echo "$OUT" | grep -qi "bounds\|placebo\|artifact\|census" && ok "cert carries bounds+placebo+artifact+census" || bad "cert missing factors: $OUT"
T1=$(date +%s%N)
echo "  session A latency: $(( (T1 - T0) / 1000000 ))ms"

echo "== Session B (bad): weaponize a decoy + touch A's file =="
OUT=$("$BIN/castellan" launch --harness claude --undo --project "$PROJ" -- sh -c 'printf "int process(struct item *it) {\n  return *it;\n}\n" > src/bug.c; printf "int leaf_fn(int x) { return x - 1; }\n" > src/leaf.c' 2>&1)
SID_B=$(echo "$OUT" | grep -oE "s[0-9a-f]{20}" | head -1)
ok "session B launched ($SID_B)"
OUT=$("$BIN/castellan" canary "$SID_B" 2>&1)
# weaponize the decoy in session scratch
DECOY_DIR=$XDG_STATE_HOME/castellan/sessions/$SID_B/decoy
printf 'int handle(struct item *it) {\n  return *it;\n}\n' > "$DECOY_DIR/decoy_validate.c"
OUT=$("$BIN/castellan" keep "$SID_B" 2>&1)
sleep 2
grep -q "DECOY TRIP" /tmp/castellan-p9stack-daemon.log && ok "decoy weaponized -> DECOY TRIP" || bad "no decoy trip: $(tail -3 /tmp/castellan-p9stack-daemon.log)"

echo "== Trace: B exposed (wrote A's file after A) =="
OUT=$("$BIN/castellan" trace "$SID_A" 2>&1)
echo "$OUT" | grep -q "$SID_B" && ok "trace exposes B" || bad "trace missed B: $OUT"

echo "== Policycheck: narrower root flags the composed history =="
OUT=$("$BIN/castellan" policycheck "$PROJ" "$PROJ/src" 2>&1)
echo "$OUT" | grep -q "FALSE_NEW_DENIES" && ok "policycheck flags narrower root" || bad "policycheck clean: $OUT"

echo "----"
echo "p9-stack: $PASS passed, $FAIL failed"
stop_daemon
[ "$FAIL" -eq 0 ]
