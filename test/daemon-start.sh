#!/usr/bin/env bash
# Start a fresh castellan daemon for the primary uid, detached, and wait
# until its socket is up. Prints the pid. Safe to re-run.
set -u
BIN=/home/john/src/castellan/target/release/castellan-daemon
LOG=${CASTELLAN_LOG:-/home/john/lab-real/daemon.log}

# stop existing same-uid daemons only (a different uid's is not ours)
for p in $(pgrep -f "target/release/castellan-daemon" 2>/dev/null); do
  u=$(stat -c %u "/proc/$p" 2>/dev/null) || continue
  [ "$u" = "$(id -u)" ] && kill -9 "$p" 2>/dev/null
done
sleep 0.5
rm -f "/run/user/$(id -u)/castellan.sock"

setsid env XDG_STATE_HOME="${XDG_STATE_HOME:-/home/john/lab-real/state}" \
  "$BIN" >>"$LOG" 2>&1 </dev/null &
disown 2>/dev/null || true

for _ in $(seq 1 60); do
  pgrep -f "target/release/castellan-daemon" >/dev/null 2>&1 && \
    [ -S "/run/user/$(id -u)/castellan.sock" ] && break
  sleep 0.2
done
pgrep -f "target/release/castellan-daemon" | while read -r p; do
  [ "$(stat -c %u /proc/$p 2>/dev/null)" = "$(id -u)" ] && echo "$p"
done | head -1
