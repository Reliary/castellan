#!/usr/bin/env bash
# P9.6 policy regression replay acceptance — self-contained.
#
# Builds its own kept-session fixture (no /tmp/opencode dependency):
#  1. launch an undoable session that writes one file inside src/ and one
#     beside it, then keep it (keep records CleanSession in the trust
#     ledger, which is what policycheck replays)
#  2. replay against the same root -> NO_FALSE_NEW_DENIES
#  3. replay against src/ as the candidate root -> the sibling write is a
#     false-NEW-deny, because the narrower root genuinely excludes it
#
# Needs a real user cgroup slice and a pty (launch + keep are tty-gated).
set -u
BIN="${CASTELLAN_BIN_DIR:-$(cd "$(dirname "$0")/../.." && pwd)/target/release}"
UID_=$(id -u)
SOCK="${XDG_RUNTIME_DIR:-/run/user/$UID_}/castellan.sock"
PASS=0; FAIL=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2' got '$3')"; fi }

pkill -9 -f 'castellan-daemon' 2>/dev/null
rm -f "$SOCK"
W=$(mktemp -d /tmp/castellan-p9pc.XXXXXX)
export XDG_STATE_HOME="$W/state"
mkdir -p "$XDG_STATE_HOME"
PROJ="$W/proj"; mkdir -p "$PROJ/src"
echo base > "$PROJ/src/old.txt"

echo "== start daemon =="
"$BIN/castellan-daemon" > "$W/daemon.log" 2>&1 &
DAPID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
"$BIN/castellan" status >/dev/null 2>&1 && ok "daemon started" || { bad "daemon not responding"; cat "$W/daemon.log"; exit 1; }

echo "== fixture: kept session with writes inside and outside src/ =="
OUT=$("$BIN/castellan" launch --project "$PROJ" --undo -- bash -c "
  echo inside > src/inside.txt
  echo sibling > sibling.txt
" 2>&1)
SID=$(grep -o 's[0-9a-f]\{16,\}' <<<"$OUT" | head -1)
[ -n "$SID" ] && ok "session $SID launched" || bad "no session id: $OUT"
KEEP=$("$BIN/castellan" keep "$SID" 2>&1)
grep -q "committed" <<<"$KEEP" && ok "kept session committed" || bad "keep failed: $KEEP"
[ -f "$PROJ/sibling.txt" ] && [ -f "$PROJ/src/inside.txt" ] \
  && ok "both writes materialized (fixture valid)" || bad "fixture writes missing"

echo "== replay against the same root =="
OUT_SAME=$("$BIN/castellan" policycheck "$PROJ" "$PROJ" 2>&1)
grep -q 'NO_FALSE_NEW_DENIES' <<<"$OUT_SAME" && ok "identical root is clean" || bad "identical root reported deltas: $OUT_SAME"
grep -q '0 with false-new-denies' <<<"$OUT_SAME" && ok "identical root has zero deltas" || bad "identical root delta count wrong: $OUT_SAME"
grep -q 'advisory' <<<"$OUT_SAME" && ok "advisory line present" || bad "advisory line missing"
grep -q '1 kept sessions' <<<"$OUT_SAME" || grep -qE '[1-9][0-9]* kept sessions' <<<"$OUT_SAME" \
  && ok "kept-session count reported" || bad "kept-session count missing: $OUT_SAME"

echo "== replay against a narrower root (src/) =="
OUT_NARROW=$("$BIN/castellan" policycheck "$PROJ" "$PROJ/src" 2>&1)
grep -q 'FALSE_NEW_DENIES' <<<"$OUT_NARROW" && ok "narrower root flags false-new-denies" || bad "narrower root not flagged: $OUT_NARROW"
grep -q 'FALSE-NEW-DENY' <<<"$OUT_NARROW" && ok "narrower root lists out-of-root paths" || bad "no false-new-deny rows"
grep -q 'sibling.txt' <<<"$OUT_NARROW" && ok "the excluded sibling write is the row named" || bad "wrong path named: $OUT_NARROW"

kill -9 "$DAPID" 2>/dev/null
rm -rf "$W"
echo "----"
echo "policycheck: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
