#!/usr/bin/env bash
# castellan release e2e — run the documented journey from a release tarball.
#
# Usage: test/release-e2e.sh <castellan-vX.Y.Z-linux-<arch>.tar.gz> [SHA256SUMS]
#
# What it guarantees (the v0.1.0 defect this closes): the release shipped
# CLI-only and the documented first command (`castellan daemon`) failed.
# A tarball is not "released" until the user journey runs from its
# contents. This test never builds anything: it untars, checks the
# binaries/permissions/sha, and drives i0-journey.sh with
# CASTELLAN_BIN_DIR pointing at the extracted files.
#
# Runs on the exercise box (needs a user cgroup slice + pty); the journey
# does the rest.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)

TARBALL="${1:-}"
SUMS="${2:-}"
if [ -z "$TARBALL" ] || [ ! -f "$TARBALL" ]; then
  echo "usage: test/release-e2e.sh <castellan-v*-linux-*.tar.gz> [SHA256SUMS]"
  exit 2
fi

PASS=0; FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

W=$(mktemp -d /tmp/castellan-rel.XXXXXX)
echo "== release e2e: $TARBALL -> $W =="

# R1: sha256 verification when a checksums file is supplied.
if [ -n "$SUMS" ] && [ -f "$SUMS" ]; then
  want=$(awk -v f="$(basename "$TARBALL")" '$2==f {print $1}' "$SUMS")
  got=$(sha256sum "$TARBALL" | awk '{print $1}')
  if [ -n "$want" ] && [ "$want" = "$got" ]; then
    ok "sha256 matches SHA256SUMS ($got)"
  else
    bad "sha256 mismatch: sums=$want actual=$got"
  fi
else
  echo "  NOTE: no SHA256SUMS given; skipping checksum verification"
fi

tar -xzf "$TARBALL" -C "$W" || { bad "tar extraction failed"; echo "REL-FAIL"; exit 1; }
ok "tarball extracts"

# R2: both binaries present, executable, matching the documented pattern.
shopt -s nullglob
clis=("$W"/castellan-v*-linux-*)
daemons=("$W"/castellan-daemon-v*-linux-*)
shopt -u nullglob
if [ "${#clis[@]}" = "1" ]; then ok "CLI binary present ($(basename "${clis[0]}"))"
else bad "expected exactly one castellan-v*-linux-* binary, found ${#clis[@]}"; fi
if [ "${#daemons[@]}" = "1" ]; then ok "daemon binary present ($(basename "${daemons[0]}"))"
else bad "expected exactly one castellan-daemon-v*-linux-* binary, found ${#daemons[@]}"; fi
[ "${#clis[@]}" = "1" ] && [ -x "${clis[0]}" ] && ok "CLI executable bit set" || bad "CLI not executable"
[ "${#daemons[@]}" = "1" ] && [ -x "${daemons[0]}" ] && ok "daemon executable bit set" || bad "daemon not executable"

# The journey expects the short names on PATH: symlink, never rename
# (keeping the versioned artifacts intact).
if [ "${#clis[@]}" = "1" ] && [ "${#daemons[@]}" = "1" ]; then
  ln -sf "${clis[0]}" "$W/castellan"
  ln -sf "${daemons[0]}" "$W/castellan-daemon"
fi

V=$("$W/castellan" --version 2>&1)
case "$V" in
  castellan\ *) ok "extracted CLI runs: $V" ;;
  *) bad "extracted CLI --version failed: $V" ;;
esac

# R3: the full documented journey from the tarball.
echo "== journey from tarball =="
CASTELLAN_BIN_DIR="$W" bash "$REPO/test/shell.d/i0-journey.sh" > "$W/journey.log" 2>&1
jrc=$?
tail -20 "$W/journey.log" | sed 's/^/  /'
if [ "$jrc" -eq 0 ]; then ok "i0-journey PASS from the release tarball"
else bad "i0-journey FAILED from the release tarball (rc=$jrc; log: $W/journey.log)"; fi

echo "== SUMMARY =="
echo "  PASS=$PASS FAIL=$FAIL  workdir: $W"
if [ "$FAIL" -eq 0 ]; then echo "REL-E2E-PASS"; exit 0; else echo "REL-E2E-FAIL"; exit 1; fi
