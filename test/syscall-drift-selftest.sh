#!/usr/bin/env bash
# Prove the drift gate can fail.
#
# A gate that has never gone red is not evidence of anything. This runs
# test/syscall-drift.sh against deliberately broken copies of the class
# table and requires the gate to FAIL in each case. It is the gate's own
# Koch criterion, mirroring test/drill-gate-prod.sh.
#
# The four injections mirror the four real failure modes the gate exists
# for:
#   1. a Hard class whose syscall the filter does not block (the table
#      claims a closure that is not there)
#   2. a blocked syscall no class claims (a block with no rationale)
#   3. a class member that is not a real syscall (typo — the class is
#      silently vacuous, which is the worst case: it looks defended)
#   4. a kernel capability the table never classifies (new-syscall drift)
#
# Each mutation lives in its own file so no quoting layer can mangle it.
set -u

REPO=${CASTELLAN_REPO:-$HOME/src/castellan}
MUT=${DRIFT_MUT_DIR:-$(mktemp -d /tmp/driftmut.XXXXXX)}
PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

WORK=$(mktemp -d /tmp/driftgate.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# Copy just what the gate needs: the crate tree plus the gate script.
# A full `cp -r` of the repo is slow and drags target/ with it.
seed() {  # seed <dir>
  mkdir -p "$1/crates/castellan-envelope/examples" "$1/test"
  cp -r "$REPO/crates/castellan-envelope/src" "$1/crates/castellan-envelope/"
  cp "$REPO/crates/castellan-envelope/Cargo.toml" "$1/crates/castellan-envelope/"
  cp "$REPO/crates/castellan-envelope/examples/syscall-classes.rs" \
     "$1/crates/castellan-envelope/examples/"
  cp "$REPO/Cargo.toml" "$1/"
  # workspace member list, trimmed to the crates we need plus their deps
  python3 - "$1/Cargo.toml" <<'PY'
import sys, pathlib, re
p = pathlib.Path(sys.argv[1])
s = p.read_text()
keep = {
  "castellan-core", "castellan-policy",
}
members = re.search(r"members = \[(.*?)\]", s, re.S).group(1)
lines = [l for l in members.splitlines() if any('"%s"' % k in l for k in keep)]
new = 'members = [\n  "crates/castellan-envelope",\n  "crates/castellan-core",\n  "crates/castellan-policy",\n]'
s = re.sub(r"members = \[.*?\]", new, s, count=1, flags=re.S)
p.write_text(s)
PY
  # copy the deps the kept crates need
  for c in castellan-core castellan-policy; do
    mkdir -p "$1/crates/$c"
    cp -r "$REPO/crates/$c/src" "$1/crates/$c/"
    cp "$REPO/crates/$c/Cargo.toml" "$1/crates/$c/"
  done
  cp "$REPO/test/syscall-drift.sh" "$1/test/"
}

apply() {  # apply <dir> <mutation.py>
  python3 "$2" "$1/crates/castellan-envelope/examples/syscall-classes.rs" \
          "$1/crates/castellan-envelope/src/syscall_classes.rs" \
    || { echo "  FAIL: mutation $(basename "$2") did not apply"; FAIL=$((FAIL+1)); return 1; }
}

run_gate() {  # run_gate <dir> <expect> <label>
  local dir=$1 expect=$2 label=$3 out got
  out=$(cd "$dir" && bash test/syscall-drift.sh 2>&1)
  if grep -q '^GATE: FAIL' <<<"$out"; then got=fail; else got=pass; fi
  if [ "$got" = "$expect" ]; then
    ok "$label (gate went $got as expected)"
  else
    bad "$label — expected gate=$expect, got $got"
    grep -E '^  FAIL:' <<<"$out" | head -3 | sed 's/^/       /'
  fi
}

echo "== control: unpatched table must PASS =="
seed "$WORK/control"
run_gate "$WORK/control" pass "baseline"

echo "== injection 1: Hard class claims a closure the filter lacks =="
seed "$WORK/i1"
apply "$WORK/i1" "$MUT/m1.py" && run_gate "$WORK/i1" fail "Hard class with an unblocked const"

echo "== injection 2: a blocked syscall no class claims =="
seed "$WORK/i2"
apply "$WORK/i2" "$MUT/m2.py" && run_gate "$WORK/i2" fail "blocked syscall no class claims"

echo "== injection 3: class member that is not a syscall (typo) =="
seed "$WORK/i3"
apply "$WORK/i3" "$MUT/m3.py" && run_gate "$WORK/i3" fail "class member that is not real"

echo "== injection 4: kernel capability the table never classifies =="
seed "$WORK/i4"
apply "$WORK/i4" "$MUT/m4.py" && run_gate "$WORK/i4" fail "kernel capability unclassified"

echo "GATE: $PASS passed, $FAIL failed"
[ "$FAIL" = "0" ] || exit 1
