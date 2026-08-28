#!/usr/bin/env bash
# P9.6 policy regression replay acceptance suite.
# Requires: a running castellan daemon, a project with kept sessions
# in the trust ledger (from prior keep operations).
set -u
BIN=/home/john/src/castellan/target/release
PASS=0
FAIL=0
check() {
  local name="$1" cond="$2"
  if eval "$cond"; then
    echo "PASS  $name"
    PASS=$((PASS + 1))
  else
    echo "FAIL  $name"
    FAIL=$((FAIL + 1))
  fi
}

PROJ="${1:-/tmp/opencode/scan-proj}"
CAND="${2:-$PROJ/src}"

OUT_NARROW=$("$BIN/castellan" policycheck "$PROJ" "$CAND" 2>&1)
check "narrower root flags false-new-denies" \
  "echo \"\$OUT_NARROW\" | grep -q 'FALSE_NEW_DENIES'"
check "narrower root lists out-of-root paths" \
  "echo \"\$OUT_NARROW\" | grep -q 'FALSE-NEW-DENY'"
check "narrower root shows kept-session count" \
  "echo \"\$OUT_NARROW\" | grep -q 'kept sessions'"

OUT_SAME=$("$BIN/castellan" policycheck "$PROJ" "$PROJ" 2>&1)
check "identical root is clean" \
  "echo \"\$OUT_SAME\" | grep -q 'NO_FALSE_NEW_DENIES'"
check "identical root has zero deltas" \
  "echo \"\$OUT_SAME\" | grep -q '0 with false-new-denies'"
check "advisory line present" \
  "echo \"\$OUT_SAME\" | grep -q 'advisory'"

echo "----"
echo "policycheck: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
