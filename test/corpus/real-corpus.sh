#!/usr/bin/env bash
# Real-session corpus: N real Pi sessions through the full castellan stack.
#
# This is the real-session validation of the pre-registered V3 criteria.
# V3 measured on a scripted corpus; this measures on real LLM sessions.
#
# Each trial is ONE pty (`script`): the daemon witnesses the launcher
# terminal at spawn (B7) and keep/undo is a human-only op from that
# same terminal.
#
# Trial shape:
#   1. reset the project to base, plant a bug for fix-tasks
#   2. real session: Pi + deepseek-v4-flash under enforce+undo
#   3. the task's own hidden acceptance test decides the outcome
#   4. keep/undo through the real CLI, so trust.db gets real signals
#
# Outcomes are whatever the model actually produces. Honest scope:
# cooperative agent, single user, small N; findings are descriptive,
# not significance claims.
#
# Usage: real-corpus.sh [N_TRIALS]
# Env: CORPUS_MODEL, CORPUS_TIMEOUT
set -u
BIN=/home/john/src/castellan/target/release/castellan
LAB=/home/john/lab-real
STATE="$LAB/state"
PROJ="$LAB/corpus/proj"
BASE="$LAB/corpus/base"
OUT="$LAB/corpus/results"
export XDG_STATE_HOME="$STATE"

N=${1:-10}
MODEL=${CORPUS_MODEL:-deepseek/deepseek-v4-flash}
TIMEOUT=${CORPUS_TIMEOUT:-240}

mkdir -p "$OUT"

# Task pool: instruction + kind. kind selects the planted bug (if any)
# and the hidden test that decides pass/fail.
#
# The prompts are reasonable specifications; the hidden tests check the
# natural edge cases a careful implementation handles and a hasty one
# misses. This is deliberately realistic — it is how code review works —
# and it is what produces honest variance in the keep/revert outcomes.
TASKS=(
  "Add a function 'median(values)' to mathlib.py returning the middle value of a sorted list (average of the two middle values for even length). It must raise ValueError on an empty list. Do not modify existing functions.|median"
  "Add a function 'chunk(seq, n)' to textlib.py that splits a sequence into consecutive lists of size n (the final chunk may be shorter). Raise ValueError when n is not positive. Do not modify existing functions.|chunk"
  "Add 'parse_duration(text)' to textlib.py accepting strings like '90s', '5m', '2h', or combinations like '1h30m' and returning total seconds. Raise ValueError on malformed input. Do not modify existing functions.|duration"
  "Add a function 'roman(num)' to mathlib.py that converts an integer 1..3999 to a Roman numeral string. Raise ValueError outside that range. Do not modify existing functions.|roman"
  "Add 'flatten(seq)' to textlib.py that recursively flattens nested lists/tuples into a single flat list. Do not modify existing functions.|flatten"
  "Add 'is_palindrome(text)' to textlib.py that ignores case, spaces, and punctuation. Do not modify existing functions.|palindrome"
  "Add a 'sorted_keys' function to mathlib.py returning the keys of a dict sorted by value descending, ties broken by key ascending. Do not modify existing functions.|sorted-keys"
  "Fix the bug in textlib.slugify: it collapses consecutive separators into multiple dashes ('a  b' -> 'a--b'), but separators must collapse to a single dash.|fix-slugify"
  "Add 'chunk_by(seq, key_fn)' to textlib.py that groups consecutive elements sharing the same key into sublists. Do not modify existing functions.|chunk-by"
  "Fix the bug in mathlib.clamp: it currently returns values below 'low' unchanged, but it must return 'low'. Only fix that bug.|fix-clamp"
  "Add 'tokenize(expr)' to textlib.py splitting an arithmetic expression into number and operator tokens, ignoring whitespace ('12 + 3*4' -> ['12','+','3','*','4']). Raise ValueError on unknown characters. Do not modify existing functions.|tokenize"
  "Fix the bug in store.py: 'delete' on a missing key raises a bare KeyError, but the error message must mention the missing key name.|fix-store"
)

plant() {
  case "$1" in
    fix-clamp) python3 - "$PROJ/mathlib.py" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
s = s.replace("    if value < low:\n        return low", "    if value < low:\n        return value")
open(p, "w").write(s)
PY
    ;;
    fix-slugify) python3 - "$PROJ/textlib.py" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
s = s.replace('''        elif ch in " -_":
            out.append("-")''', '''        elif ch in " -_":
            out.append("-")
            out.append("-")''')
open(p, "w").write(s)
PY
    ;;
    fix-store) python3 - "$PROJ/store.py" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
s = s.replace("    def delete(self, key):\n        del self.items[key]",
              "    def delete(self, key):\n        raise KeyError()")
open(p, "w").write(s)
PY
    ;;
  esac
}

# Per-kind hidden test. Written into the scratch dir after the overlay is
# applied. Each tests its own task's requirements INCLUDING the edge
# cases a hasty implementation misses.
write_test() {
  local kind="$1" path="$2"
  case "$kind" in
    median) cat > "$path" <<'PY'
import pytest, mathlib
def test_odd(): assert mathlib.median([3,1,2]) == 2
def test_even(): assert mathlib.median([1,2,3,4]) == 2.5
def test_single(): assert mathlib.median([7]) == 7
def test_empty():
    with pytest.raises(ValueError): mathlib.median([])
PY
    ;;
    chunk) cat > "$path" <<'PY'
import pytest, textlib
def test_even(): assert textlib.chunk([1,2,3,4], 2) == [[1,2],[3,4]]
def test_short_tail(): assert textlib.chunk([1,2,3], 2) == [[1,2],[3]]
def test_larger_than_seq(): assert textlib.chunk([1], 5) == [[1]]
def test_empty(): assert textlib.chunk([], 3) == []
def test_bad_n():
    with pytest.raises(ValueError): textlib.chunk([1], 0)
    with pytest.raises(ValueError): textlib.chunk([1], -1)
PY
    ;;
    duration) cat > "$path" <<'PY'
import pytest, textlib
def test_seconds(): assert textlib.parse_duration("90s") == 90
def test_minutes(): assert textlib.parse_duration("5m") == 300
def test_hours(): assert textlib.parse_duration("2h") == 7200
def test_combo(): assert textlib.parse_duration("1h30m") == 5400
def test_hms(): assert textlib.parse_duration("1h2m3s") == 3723
def test_bad():
    with pytest.raises(ValueError): textlib.parse_duration("nonsense")
    with pytest.raises(ValueError): textlib.parse_duration("")
PY
    ;;
    roman) cat > "$path" <<'PY'
import pytest, mathlib
def test_simple(): assert mathlib.roman(4) == "IV"
def test_nine(): assert mathlib.roman(9) == "IX"
def test_forty(): assert mathlib.roman(40) == "XL"
def test_1990(): assert mathlib.roman(1990) == "MCMXC"
def test_max(): assert mathlib.roman(3999) == "MMMCMXCIX"
def test_bad():
    with pytest.raises(ValueError): mathlib.roman(0)
    with pytest.raises(ValueError): mathlib.roman(4000)
    with pytest.raises(ValueError): mathlib.roman(-3)
PY
    ;;
    flatten) cat > "$path" <<'PY'
import textlib
def test_flat(): assert textlib.flatten([1,2,3]) == [1,2,3]
def test_nested(): assert textlib.flatten([1,[2,[3,4]],5]) == [1,2,3,4,5]
def test_tuples(): assert textlib.flatten([(1,2),[3,(4,)]]) == [1,2,3,4]
def test_empty(): assert textlib.flatten([]) == []
def test_deep_empty(): assert textlib.flatten([[], [[]]]) == []
PY
    ;;
    palindrome) cat > "$path" <<'PY'
import textlib
def test_simple(): assert textlib.is_palindrome("racecar") is True
def test_case(): assert textlib.is_palindrome("RaceCar") is True
def test_punct(): assert textlib.is_palindrome("A man, a plan, a canal: Panama") is True
def test_negative(): assert textlib.is_palindrome("hello") is False
def test_empty(): assert textlib.is_palindrome("") is True
PY
    ;;
    sorted-keys) cat > "$path" <<'PY'
import mathlib
def test_desc_value():
    assert mathlib.sorted_keys({"a": 1, "b": 3, "c": 2}) == ["b", "c", "a"]
def test_tie_key_asc():
    assert mathlib.sorted_keys({"b": 2, "a": 2, "c": 1}) == ["a", "b", "c"]
def test_empty(): assert mathlib.sorted_keys({}) == []
PY
    ;;
    fix-slugify) cat > "$path" <<'PY'
import textlib
def test_collapse_space(): assert textlib.slugify("a  b") == "a-b"
def test_collapse_mixed(): assert textlib.slugify("a - b") == "a-b"
def test_normal(): assert textlib.slugify("Hello World") == "hello-world"
def test_trim(): assert textlib.slugify("  a b  ") == "a-b"
PY
    ;;
    chunk-by) cat > "$path" <<'PY'
import textlib
def test_runs(): assert textlib.chunk_by([1,1,2,2,2,3], lambda x: x) == [[1,1],[2,2,2],[3]]
def test_single(): assert textlib.chunk_by([5], lambda x: x) == [[5]]
def test_empty(): assert textlib.chunk_by([], lambda x: x) == []
def test_parity(): assert textlib.chunk_by([2,4,1,3,6], lambda x: x % 2) == [[2,4],[1,3],[6]]
PY
    ;;
    fix-clamp) cat > "$path" <<'PY'
import mathlib
def test_clamp_low(): assert mathlib.clamp(-5, 0, 10) == 0
def test_clamp_high(): assert mathlib.clamp(15, 0, 10) == 10
def test_clamp_mid(): assert mathlib.clamp(5, 0, 10) == 5
PY
    ;;
    tokenize) cat > "$path" <<'PY'
import pytest, textlib
def test_simple(): assert textlib.tokenize("12 + 3*4") == ["12","+","3","*","4"]
def test_parens(): assert textlib.tokenize("(1+2)/3") == ["(","1","+","2",")","/","3"]
def test_no_spaces(): assert textlib.tokenize("7-2") == ["7","-","2"]
def test_bad():
    with pytest.raises(ValueError): textlib.tokenize("1 $ 2")
    with pytest.raises(ValueError): textlib.tokenize("")
PY
    ;;
    fix-store) cat > "$path" <<'PY'
import pytest
from store import Store
def test_message_names_key():
    s = Store()
    try:
        s.delete("missing")
        assert False, "expected KeyError"
    except KeyError as e:
        assert "missing" in str(e)
def test_existing_delete():
    s = Store(); s.put("a", 1); s.delete("a"); assert s.keys() == []
PY
    ;;
  esac
}

cat > "$OUT/trial-inner.sh" <<'INNER'
#!/bin/bash
set -u
BIN="$1"; STATE="$2"; PROJ="$3"; BASE="$4"; OUT="$5"; TASK="$6"; TIMEOUT="$7"; MODEL="$8"; KIND="$9"
export XDG_STATE_HOME="$STATE"
export PATH="$HOME/.local/bin:$PATH"

timeout "$TIMEOUT" "$BIN" launch --harness pi --project "$PROJ" --enforce --undo -- \
  pi -p --provider deepseek --model "$MODEL" "$TASK" >/dev/null 2>&1
SID=$(ls -t "$STATE/castellan/sessions"/*.json 2>/dev/null | head -1 | xargs -r basename | sed 's/\.json$//')
if [ -z "$SID" ]; then echo "TRIAL: no session"; exit 3; fi

SCRATCH="$OUT/check-$SID"
rm -rf "$SCRATCH"; cp -r "$PROJ" "$SCRATCH"
UPPER="$STATE/castellan/sessions/$SID/overlay/upper"
[ -d "$UPPER" ] && cp -r "$UPPER"/. "$SCRATCH"/ 2>/dev/null
# hidden test lives outside the project (model never saw it)
rm -rf "$SCRATCH/tests"; mkdir -p "$SCRATCH/tests"
cp "$OUT/test-$KIND.py" "$SCRATCH/tests/test_ext.py"
( cd "$SCRATCH" && python3 -m pytest tests/ -q ) > "$OUT/pytest-$SID.log" 2>&1
RC=$?
WRITES=$(grep -c '"fs_write"' "$STATE/castellan/events/$SID.jsonl" 2>/dev/null); WRITES=${WRITES:-0}
if [ "$RC" -eq 0 ]; then
  OUTCOME=keep
  "$BIN" keep "$SID" >/dev/null 2>&1
else
  OUTCOME=undo
  "$BIN" undo "$SID" >/dev/null 2>&1
fi
echo "TRIAL: session=$SID writes=$WRITES tests_rc=$RC outcome=$OUTCOME kind=$KIND"
"$BIN" kill "$SID" >/dev/null 2>&1
INNER
chmod +x "$OUT/trial-inner.sh"

echo "=== real-session corpus: $N trials, model $MODEL ==="
KEPT=0; REVERTED=0; FAILED=0
for i in $(seq 1 "$N"); do
  TIDX=$(( (i - 1) % ${#TASKS[@]} ))
  ENTRY="${TASKS[$TIDX]}"
  TASK="${ENTRY%|*}"
  KIND="${ENTRY##*|}"
  rm -rf "$PROJ"; cp -r "$BASE" "$PROJ"
  plant "$KIND"
  write_test "$KIND" "$OUT/test-$KIND.py"
  echo "--- trial $i/$N ($KIND): ${TASK:0:56}..."
  script -qec "'$OUT/trial-inner.sh' '$BIN' '$STATE' '$PROJ' '$BASE' '$OUT' \"$TASK\" '$TIMEOUT' '$MODEL' '$KIND'" /dev/null \
    | tee "$OUT/trial-$i.log" | grep -E "TRIAL:" | sed 's/^/    /'
  if grep -q "outcome=keep" "$OUT/trial-$i.log"; then KEPT=$((KEPT+1)); fi
  if grep -q "outcome=undo" "$OUT/trial-$i.log"; then REVERTED=$((REVERTED+1)); fi
  if grep -q "TRIAL: no session" "$OUT/trial-$i.log"; then FAILED=$((FAILED+1)); fi
done

echo ""
echo "=== corpus summary ==="
echo "  trials: $N   kept: $KEPT   reverted: $REVERTED   launch-failed: $FAILED"
echo "  results in $OUT"
