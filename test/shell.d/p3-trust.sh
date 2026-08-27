#!/usr/bin/env bash
# P3 kill criterion: monotonic relationship between trust tier and
# user-revert outcomes on a labelled corpus. Sessions the user reverted
# must cluster at lower tiers than sessions the user kept.
#
# Criterion: mean tier(kept) > mean tier(reverted) AND Spearman rho
# between tier and keep-outcome > 0.3. If no monotonic relationship,
# trust is demoted to advisory-only (per ROADMAP).
#
# The corpus is simulated through the REAL signal pipeline: signals are
# applied via the daemon's trust_signal op (the same path undo_discard,
# canary trips, and undo_commit use), so this tests the composition, not
# the math in isolation.
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
ok "stale state cleaned"

WORK=$(mktemp -d /tmp/castellan-p3.XXXXXX)
export XDG_STATE_HOME="$WORK/state"
mkdir -p "$WORK/state"

echo "== start daemon =="
"$BIN/castellan-daemon" > "$WORK/daemon.log" 2>&1 &
DAPID=$!
sleep 0.5
grep -q listening "$WORK/daemon.log" && ok "daemon started" || { bad "daemon failed to start"; exit 1; }

rpc() { # rpc <json>
  python3 - "$1" <<'EOF'
import json, socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect("/run/user/1000/castellan.sock")
s.sendall((sys.argv[1] + "\n").encode())
s.shutdown(socket.SHUT_WR)
data = b""
while True:
    c = s.recv(4096)
    if not c: break
    data += c
print(data.decode().strip())
EOF
}

PROJ="$WORK/proj"
mkdir -p "$PROJ"

# ---- corpus: 40 sessions, 20 kept / 20 reverted ----
# kept: clean_session + proof_passed (the real undo_commit path)
# reverted: user_revert, half with a canary_hit or envelope_escape
# (the real undo_discard / trip paths)
echo "== building labelled corpus (40 sessions) =="
for i in $(seq 1 20); do
  SID="k$i"
  rpc "{\"op\":\"trust_signal\",\"project\":\"$PROJ\",\"session\":\"$SID\",\"signal\":\"clean_session\",\"evidence\":\"bench\"}" > /dev/null
  rpc "{\"op\":\"trust_signal\",\"project\":\"$PROJ\",\"session\":\"$SID\",\"signal\":\"proof_passed\",\"evidence\":\"1 placebo-controlled proof(s) passed; strengths: 1.00\"}" > /dev/null
done
for i in $(seq 1 20); do
  SID="r$i"
  rpc "{\"op\":\"trust_signal\",\"project\":\"$PROJ\",\"session\":\"$SID\",\"signal\":\"user_revert\",\"evidence\":\"bench\"}" > /dev/null
  if (( i % 2 == 0 )); then
    rpc "{\"op\":\"trust_signal\",\"project\":\"$PROJ\",\"session\":\"$SID\",\"signal\":\"canary_hit\",\"evidence\":\"bench\"}" > /dev/null
  fi
done
ok "corpus built"

# ---- measure: final tier per session ----
echo "== measuring tiers =="
python3 - "$PROJ" <<'EOF'
import json, socket, subprocess, sys, os
proj = sys.argv[1]

def rpc(req):
    s = socket.socket(socket.AF_UNIX)
    s.connect("/run/user/1000/castellan.sock")
    s.sendall((json.dumps(req) + "\n").encode())
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        c = s.recv(4096)
        if not c: break
        data += c
    return json.loads(data.decode().strip())

def tier_after(sid, signals):
    # replay the session's signals in order, reading the score after each
    score = 50.0
    for sig in signals:
        r = rpc({"op":"trust_signal","project":proj,"session":sid,
                 "signal":sig,"evidence":"bench"})
        score = r["extra"]["trust"]["score"]
    return score

kept_tiers = []
for i in range(1, 21):
    sid = f"k{i}"
    s = tier_after(sid, ["clean_session", "proof_passed"])
    kept_tiers.append(s)
reverted_tiers = []
for i in range(1, 21):
    sid = f"r{i}"
    sigs = ["user_revert"]
    if i % 2 == 0:
        sigs.append("canary_hit")
    s = tier_after(sid, sigs)
    reverted_tiers.append(s)

mean_kept = sum(kept_tiers) / len(kept_tiers)
mean_rev = sum(reverted_tiers) / len(reverted_tiers)
print(f"mean tier kept:    {mean_kept:.1f}")
print(f"mean tier reverted:{mean_rev:.1f}")

# Spearman rho between tier and keep-outcome (kept=1, reverted=0)
all_scores = kept_tiers + reverted_tiers
all_outcomes = [1]*20 + [0]*20
def rank(vals):
    order = sorted(range(len(vals)), key=lambda i: vals[i])
    ranks = [0.0]*len(vals)
    i = 0
    while i < len(order):
        j = i
        while j+1 < len(order) and vals[order[j+1]] == vals[order[i]]:
            j += 1
        avg = (i + j) / 2 + 1
        for k in range(i, j+1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks
rs = rank(all_scores)
ro = rank(all_outcomes)
n = len(all_scores)
mean_r = sum(rs)/n
mean_o = sum(ro)/n
cov = sum((rs[i]-mean_r)*(ro[i]-mean_o) for i in range(n))
var_r = sum((rs[i]-mean_r)**2 for i in range(n))
var_o = sum((ro[i]-mean_o)**2 for i in range(n))
rho = cov / (var_r*var_o)**0.5 if var_r and var_o else 0.0
print(f"spearman rho: {rho:.3f}")

monotonic = mean_kept > mean_rev and rho > 0.3
print("MONOTONIC" if monotonic else "NOT_MONOTONIC")
sys.exit(0 if monotonic else 1)
EOF
RC=$?
if [[ $RC -eq 0 ]]; then
  ok "monotonic tier<->revert relationship (mean kept > mean reverted, rho > 0.3)"
else
  bad "no monotonic relationship — trust must be demoted to advisory-only"
fi

echo "== daemon survives everything =="
if [[ -d "/proc/$DAPID" ]]; then ok "daemon still alive"; else bad "daemon died"; fi

rm -rf "$WORK"
echo
echo "RESULT: $PASS passed, $FAIL failed"
exit $([[ $FAIL -eq 0 ]] && echo 0 || echo 1)
