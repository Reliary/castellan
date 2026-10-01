#!/usr/bin/env bash
# Prove the drift gate can fail.
#
# A gate that has never gone red is not evidence of anything. This runs
# test/syscall-drift.sh against deliberately broken copies of the class
# table / filter and requires the gate to FAIL in each case. It is the
# gate's own Koch criterion, mirroring test/drill-gate-prod.sh.
#
# P14 (2026-10-01) correction: this script used to shell out to four
# mutation .py files under $DRIFT_MUT_DIR that are not in the repo, so it
# always reported "mutation did not apply" and the four injections never
# ran — while THREAT_MODEL cited it as "5/5". The mutations are now
# generated inline from this file, so the criterion is self-contained.
#
# The four injections mirror the four failure modes the gate exists for:
#   1. a Hard class whose member the filter does not block (the gate's
#      new P14 member-closure check; also catches a class claiming a
#      closure via a libc const the filter omits)
#   2. a blocked syscall no class claims (a block with no rationale)
#   3. a class member that is not a real syscall (typo — the class is
#      silently vacuous, which is the worst case: it looks defended)
#   4. a kernel capability the table never classifies (new-syscall drift)
set -u

REPO=${CASTELLAN_REPO:-$HOME/src/castellan}
PASS=0
FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

WORK=$(mktemp -d /tmp/driftgate.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# Copy just what the gate needs: the crate tree plus the gate script.
seed() {  # seed <dir>
  mkdir -p "$1/crates/castellan-envelope/examples" "$1/test"
  cp -r "$REPO/crates/castellan-envelope/src" "$1/crates/castellan-envelope/"
  cp "$REPO/crates/castellan-envelope/Cargo.toml" "$1/crates/castellan-envelope/"
  cp "$REPO/crates/castellan-envelope/examples/syscall-classes.rs" \
     "$1/crates/castellan-envelope/examples/"
  cp "$REPO/Cargo.toml" "$1/"
  python3 - "$1/Cargo.toml" <<'PY'
import sys, pathlib, re
p = pathlib.Path(sys.argv[1]); s = p.read_text()
keep = {"castellan-core", "castellan-policy"}
new = 'members = [\n  "crates/castellan-envelope",\n  "crates/castellan-core",\n  "crates/castellan-policy",\n]'
s = re.sub(r"members = \[.*?\]", new, s, count=1, flags=re.S)
p.write_text(s)
PY
  for c in castellan-core castellan-policy; do
    mkdir -p "$1/crates/$c"; cp -r "$REPO/crates/$c/src" "$1/crates/$c/"; cp "$REPO/crates/$c/Cargo.toml" "$1/crates/$c/"
  done
  cp "$REPO/test/syscall-drift.sh" "$1/test/"
}

# mutate <dir> <python-expr-file>  — apply a python program to the two
# source files. Each mutation is written inline below.
mutate() {  # mutate <dir> <script>
  python3 "$2" "$1/crates/castellan-envelope/src/seccomp.rs" \
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

echo "== injection 1: a Hard member the filter does not block =="
seed "$WORK/i1"
cat > "$WORK/m1.py" <<'PY'
import sys, pathlib
seccomp = pathlib.Path(sys.argv[1]); s = seccomp.read_text()
# remove fsopen from the filter; the class table still declares it Hard.
s = s.replace("    libc::SYS_fsopen,\n", "")
seccomp.write_text(s)
PY
mutate "$WORK/i1" "$WORK/m1.py" && run_gate "$WORK/i1" fail "Hard member unblocked"

echo "== injection 2: a blocked syscall no class claims =="
seed "$WORK/i2"
cat > "$WORK/m2.py" <<'PY'
import sys, pathlib
classes = pathlib.Path(sys.argv[2]); s = classes.read_text()
# drop SYS_ptrace from the process-memory Hard class's libc_consts; the
# filter still blocks ptrace, so it becomes an orphan block.
s = s.replace('      "SYS_ptrace",\n', '', 1)
classes.write_text(s)
PY
mutate "$WORK/i2" "$WORK/m2.py" && run_gate "$WORK/i2" fail "blocked syscall no class"

echo "== injection 3: a class member that is not a real syscall (typo) =="
seed "$WORK/i3"
cat > "$WORK/m3.py" <<'PY'
import sys, pathlib
classes = pathlib.Path(sys.argv[2]); s = classes.read_text()
s = s.replace('"mount",\n      "umount2",', '"mount",\n      "not_a_real_syscall_xyz",\n      "umount2",', 1)
classes.write_text(s)
PY
mutate "$WORK/i3" "$WORK/m3.py" && run_gate "$WORK/i3" fail "class member not real"

echo "== injection 4: a kernel capability the table never classifies =="
seed "$WORK/i4"
cat > "$WORK/m4.py" <<'PY'
import sys, pathlib
# remove io_uring_setup from the class members, its libc const, AND the
# filter, so the running kernel exposes it matching ^io_uring but the
# table never classifies it (the new-syscall-drift channel).
seccomp = pathlib.Path(sys.argv[1]); s = seccomp.read_text()
s = s.replace("    libc::SYS_io_uring_setup,\n", "")
s = s.replace('  ("io_uring_setup", libc::SYS_io_uring_setup),\n', "")
seccomp.write_text(s)
classes = pathlib.Path(sys.argv[2]); c = classes.read_text()
c = c.replace('      "io_uring_setup",\n', "", 1)
c = c.replace('"SYS_io_uring_setup", ', "", 1)
classes.write_text(c)
PY
mutate "$WORK/i4" "$WORK/m4.py" && run_gate "$WORK/i4" fail "kernel capability unclassified"

echo "GATE: $PASS passed, $FAIL failed"
[ "$FAIL" = "0" ] || exit 1
