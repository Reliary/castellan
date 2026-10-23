#!/usr/bin/env bash
# castellan acceptance battery — run every wired-system suite in the
# execution context it requires, and print one table.
#
# Contexts (why the distinction matters):
#   self-pty  the suite creates its own pty internally (script -qec) and
#             must NOT be nested inside another pty: a nested pty gets a
#             fresh tty_nr and the R7 launcher-tty witness stops matching.
#   wrap-pty  the suite launches sessions but never creates a pty itself,
#             so it must run under `script` or every launch is refused.
#   bare      no sessions are launched; run directly.
#   local     needs machine-local data (model corpus, relay-vuln/stria
#             binaries, a drills build, or a pre-built fixture). Skipped
#             unless `--local` is passed; not part of the green bar.
#
# Usage:
#   test/run-all.sh                 # green bar: self-pty + wrap-pty + bare
#   test/run-all.sh --local         # also run machine-local suites
#   test/run-all.sh --only p1,p2    # subset by name prefix
#   test/run-all.sh --list          # show the manifest and exit
#
# Binaries: set CASTELLAN_BIN_DIR to run against a release tarball's
# extracted binaries (no cargo needed). Default: <repo>/target/release.
set -u
cd "$(dirname "$0")/.."
REPO=$PWD

# The suites move agent pids into castellan.slice/<session>.scope, which
# needs the caller to live in the user manager's cgroup tree. An ssh
# session sits in session-N.scope, where those writes are EPERM ("failed
# to move pid into scope"). Re-exec inside a transient user scope so the
# battery behaves the same over ssh as on a desktop terminal.
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
if [ "${CASTELLAN_RUN_ALL_IN_SCOPE:-0}" != "1" ] \
   && ! grep -q "user@$(id -u).service" /proc/self/cgroup 2>/dev/null \
   && command -v systemd-run >/dev/null 2>&1 \
   && [ -S "$XDG_RUNTIME_DIR/systemd/private" ]; then
  export CASTELLAN_RUN_ALL_IN_SCOPE=1
  exec systemd-run --user --scope --collect --quiet -- "$0" "$@"
fi
BIN_DIR="${CASTELLAN_BIN_DIR:-$REPO/target/release}"
export CASTELLAN_BIN_DIR="$BIN_DIR"
export SHELL=/bin/sh

LOCAL=0
ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --local) LOCAL=1; shift;;
    --only) ONLY="${2:-}"; shift 2;;
    --list) LIST=1; shift;;
    -h|--help) sed -n '3,24p' "$0"; exit 0;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done

# name:context
MANIFEST="
b8-broker:wrap-pty
b8-sweep:wrap-pty
ch5-proof:self-pty
i0-journey:self-pty
p0-freeze:self-pty
p1-envelope:wrap-pty
p11-tier-egress:self-pty
p12-proxy:self-pty
p13-escape-probe:self-pty
p14-esoteric:self-pty
p15-fingerprint-framing:self-pty
p17-device-sweep:self-pty
p18-lifecycle:wrap-pty
p19-watchdog-survival:bare
p2-undo:wrap-pty
p20-restart:wrap-pty
p21-desktop:wrap-pty
p21-freeze-ux:wrap-pty
p21-visibility:wrap-pty
p3-trust:bare
p4-certificates:bare
p6-floor:self-pty
p9-stack:local
p8-drills:local
p9-policycheck:wrap-pty
v3-corpus:local
"

if [ -n "${LIST:-}" ]; then
  printf '%s\n' "$MANIFEST" | grep -v '^$' | awk -F: '{printf "%-26s %s\n", $1, $2}'
  exit 0
fi

if [ ! -x "$BIN_DIR/castellan" ] || [ ! -x "$BIN_DIR/castellan-daemon" ]; then
  echo "castellan binaries not found in $BIN_DIR"
  echo "build with 'cargo build --release --workspace' or set CASTELLAN_BIN_DIR"
  exit 2
fi

# Several suites kill every castellan-daemon of this uid, freeze every session
# scope in the user slice, install real systemd units and run
# `castellan uninstall --yes` against the real state. That is correct on a
# dedicated CI account and destructive on a desktop with live agents.
# Require an explicit opt-in: losing a running agent session to a test run is
# not a mistake worth making silently.
if [ "${CASTELLAN_ALLOW_DESTRUCTIVE:-0}" != "1" ]; then
  echo "refusing: the battery kills this uid's daemons, freezes every session"
  echo "scope, and runs uninstall against real state."
  echo "run it on a dedicated CI account, or set CASTELLAN_ALLOW_DESTRUCTIVE=1"
  echo "if this account has no live sessions to lose."
  exit 3
fi

matches() {
  [ -z "$ONLY" ] && return 0
  local name=$1 want
  IFS=',' read -ra wants <<< "$ONLY"
  for want in "${wants[@]}"; do case "$name" in "$want"*) return 0;; esac; done
  return 1
}

# Log directory. CI passes the path it will upload; local runs get a temp
# dir under the caller's TMPDIR. Removed on success, kept on failure (and
# the path is always printed), so a red run is diagnosable and a green run
# leaves nothing behind.
LOG_BASE="${CASTELLAN_LOG_DIR:-${TMPDIR:-/tmp}}"
mkdir -p "$LOG_BASE"
W=$(mktemp -d "$LOG_BASE/castellan-run-all.XXXXXX")
ROWS="$W/rows"
: > "$ROWS"
PASS=0; FAIL=0; SKIP=0

for entry in $MANIFEST; do
  name=${entry%%:*}
  ctx=${entry##*:}
  suite="test/shell.d/$name.sh"
  if ! matches "$name"; then continue; fi
  if [ "$ctx" = "local" ] && [ "$LOCAL" -eq 0 ]; then
    printf '%-26s %-9s SKIP  (local-only; --local to run)\n' "$name" "$ctx"
    SKIP=$((SKIP+1)); continue
  fi
  if [ ! -f "$suite" ]; then
    printf '%-26s %-9s SKIP  (missing %s)\n' "$name" "$ctx" "$suite"
    SKIP=$((SKIP+1)); continue
  fi
  log="$W/$name.log"
  start=$(date +%s)
  case "$ctx" in
    self-pty) timeout 900 bash "$suite" > "$log" 2>&1 < /dev/null;;
    wrap-pty) timeout 900 script -qec "bash '$suite'" /dev/null > "$log" 2>&1 < /dev/null;;
    bare)     timeout 900 bash "$suite" > "$log" 2>&1 < /dev/null;;
    local)    timeout 1800 bash "$suite" > "$log" 2>&1 < /dev/null;;
  esac
  rc=$?
  dur=$(( $(date +%s) - start ))
  if [ "$rc" -eq 0 ]; then
    printf '%-26s %-9s PASS  %3ds\n' "$name" "$ctx" "$dur"
    PASS=$((PASS+1)); echo "$name:pass" >> "$ROWS"
  else
    printf '%-26s %-9s FAIL  %3ds  (%s)\n' "$name" "$ctx" "$dur" "$log"
    FAIL=$((FAIL+1)); echo "$name:fail" >> "$ROWS"
  fi
done

echo
echo "battery: $PASS passed, $FAIL failed, $SKIP skipped  (bin: $BIN_DIR)"
echo "logs: $W"
if [ "$FAIL" -gt 0 ]; then
  echo "first failing assertions:"
  for name in $(awk -F: '$2=="fail"{print $1}' "$ROWS"); do
    echo "--- $name"
    grep -E '^\s*(FAIL|bad)|RESULT' "$W/$name.log" | head -5
  done
  exit 1
fi

# Green: the logs are noise. Red: they stay, and the path above says where.
rm -rf "$W"
