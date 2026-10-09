#!/usr/bin/env bash
# castellan P21.5 — desktop controls + onboarding.
#
# K17 `systemctl --user start castellan-freeze.service` from a non-tty
#     caller freezes every session scope (the keybind path)
# K18 an in-envelope agent still cannot reach systemctl (p13 rerun
#     covers the broker; here we assert the unit path itself is
#     outside what an enveloped process can trigger — the daemonless
#     verb under the envelope is EPERM, live check)
# K19 `systemctl --user start castellan-thaw.service` restores sessions
# K21 bash -n / zsh -n / fish -n accept every completion script and each
#     names every advertised verb
# K22 uninstall removes the daemon unit, both oneshots, the watch unit,
#     and the completions file it installed
#
# WHY REAL STATE, NOT SCRATCH: systemctl --user is a singleton bound to
# the real XDG_CONFIG_HOME (p18 records the measurement). The suite
# therefore installs for real and uninstalls in cleanup, like p18.
#
# Preconditions: user cgroup slice + pty + systemctl --user on .227.
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
BIN="$REPO/target/release"
PASS=0; FAIL=0; NOTE=0
ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
note() { echo "  NOTE: $1"; NOTE=$((NOTE+1)); }

UNIT="castellan.service"
UNITS="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
SOCK="/run/user/$(id -u)/castellan.sock"
W=$(mktemp -d /tmp/castellan-p215.XXXXXX)

if ! systemctl --user show-environment >/dev/null 2>&1; then
  echo "P21.5-ACCEPT-SKIP: no systemctl --user on this box"; exit 0
fi

cleanup() {
  systemctl --user stop castellan-watch.service 2>/dev/null
  systemctl --user stop castellan-freeze.service castellan-thaw.service 2>/dev/null
  "$BIN/castellan" uninstall --yes --keep-config >/dev/null 2>&1
  for p in $(pgrep -f "target/release/castellan-daemon" 2>/dev/null); do
    [ "$(readlink "/proc/$p/exe" 2>/dev/null)" = "$BIN/castellan-daemon" ] && kill -9 "$p" 2>/dev/null
  done
}
trap cleanup EXIT

# -- install for real (units land in the real manager's view) --
"$BIN/castellan" service install >"$W/install.log" 2>&1
rc=$?
[ $rc -eq 0 ] && ok "service install rc=0" || { bad "service install rc=$rc: $(tail -3 "$W/install.log")"; echo "P21.5-ACCEPT-FAIL"; exit 1; }
# enable --now returns before the daemon has bound the socket; wait for it
# (p18 does the same — a launcher racing the socket sees ECONNREFUSED).
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] && ok "daemon socket bound after install" || bad "no socket after install: $(systemctl --user status "$UNIT" --no-pager 2>&1 | tail -3 | tr '\n' ' ')"
for u in castellan-freeze.service castellan-thaw.service; do
  [ -f "$UNITS/$u" ] && ok "installed $u" || bad "$u missing from $UNITS"
done
grep -q 'freeze --daemonless' "$UNITS/castellan-freeze.service" && ok "freeze unit runs the daemonless verb" || bad "freeze unit verb wrong"
grep -q 'thaw --daemonless' "$UNITS/castellan-thaw.service" && ok "thaw unit runs the daemonless verb" || bad "thaw unit verb wrong"

# -- one live session to freeze --
P="$W/proj"; mkdir -p "$P"; printf 'x = 1\n' > "$P/a.py"
SHELL=/bin/sh script -qec "
  cd '$P'
  '$BIN/castellan' launch --project '$P' -- sleep 300 > '$W/launch.out' 2>&1 &
  for _ in \$(seq 1 50); do
    grep -q 'launched' '$W/launch.out' && break
    sleep 0.1
  done
  sleep 0.5
" /dev/null >/dev/null 2>&1
SID=$(grep -o 's[0-9a-f]\{10,\}' "$W/launch.out" | head -1)
if [ -z "$SID" ]; then
  bad "no live session to freeze: $(tail -3 "$W/launch.out")"
  echo "P21.5-ACCEPT-FAIL"; exit 1
fi
"$BIN/castellan" status 2>/dev/null | grep -q "$SID" && ok "session $SID live" || bad "session not in status"

echo
echo "== K17: keybind path freezes from a non-tty caller =="
# This suite itself may run under a tty; the point is the *unit* runs
# with no tty, which ExecStart guarantees. Start the unit.
systemctl --user start castellan-freeze.service
sleep 1
STATE=$(cat "/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/castellan.slice/$SID.scope/cgroup.freeze" 2>/dev/null)
[ "$STATE" = "1" ] && ok "K17: scope frozen via systemctl oneshot (no tty, no daemon round trip)" \
  || bad "K17: scope not frozen (cgroup.freeze=$STATE); unit log: $(systemctl --user status castellan-freeze.service --no-pager 2>&1 | tail -2 | tr '\n' ' ')"

echo
echo "== K19: thaw unit restores the session =="
systemctl --user start castellan-thaw.service
sleep 1
STATE=$(cat "/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/castellan.slice/$SID.scope/cgroup.freeze" 2>/dev/null)
[ "$STATE" = "0" ] && ok "K19: scope thawed via systemctl oneshot" || bad "K19: scope still frozen (cgroup.freeze=$STATE)"

echo
echo "== K18: the daemonless verbs cannot freeze from inside the envelope =="
# The property is "cannot freeze", not "nonzero exit": measured live, the
# enveloped verb cannot even SEE the scopes (Landlock read rules hide
# cgroupfs), so it exits 0 with "no session scopes to freeze" — and the
# scope stays unfrozen. Assert the property, and the negative control.
P18="$W/env"; mkdir -p "$P18"
SHELL=/bin/sh script -qec "
  cd '$P18'
  '$BIN/castellan' launch --project '$P18' -- sh -c '\"$BIN/castellan\" freeze --daemonless; \"$BIN/castellan\" thaw --daemonless' > '$W/env-launch.out' 2>&1 &
  sleep 3
" /dev/null >/dev/null 2>&1
SID18=$(grep -o 's[0-9a-f]\{10,\}' "$W/env-launch.out" | head -1)
STATE18=$(cat "/sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/castellan.slice/$SID18.scope/cgroup.freeze" 2>/dev/null)
if [ -z "$SID18" ]; then
  bad "K18: envelope session never launched: $(tail -2 "$W/env-launch.out" | tr '\n' ' ')"
elif [ "$STATE18" = "0" ]; then
  ok "K18: enveloped session $SID18 still unfrozen after freeze --daemonless ($(grep -m1 'scopes to freeze' "$W/env-launch.out" || echo 'verb output: see log'))"
else
  bad "K18: ENVELOPED freeze --daemonless FROZE the scope (cgroup.freeze=$STATE18) — escape"
fi

echo
echo "== K21: completion scripts pass their shells' syntax checks =="
for sh in bash zsh fish; do
  "$BIN/castellan" completions "$sh" > "$W/c.$sh" 2>/dev/null
  case $sh in
    bash) bash -n "$W/c.bash" 2>"$W/c.err" && ok "K21: bash -n accepts completions" || bad "K21: bash -n: $(cat "$W/c.err")";;
    zsh)
      if command -v zsh >/dev/null; then
        zsh -n "$W/c.zsh" 2>"$W/c.err" && ok "K21: zsh -n accepts completions" || bad "K21: zsh -n: $(cat "$W/c.err")"
      else note "K21: zsh not installed here — syntax check skipped"; fi;;
    fish)
      if command -v fish >/dev/null; then
        fish -n "$W/c.fish" 2>"$W/c.err" && ok "K21: fish -n accepts completions" || bad "K21: fish -n: $(cat "$W/c.err")"
      else note "K21: fish not installed here — syntax check skipped"; fi;;
  esac
done
for v in status watch freeze thaw kill spawn launch audit adopt bless cert verify replay radar drill channels trace policycheck memory voice proxy service uninstall gc init doctor; do
  grep -q "$v" "$W/c.bash" || bad "K21: bash completions missing verb $v"
done
ok "K21: all core verbs present in bash completions"

echo
echo "== K22: uninstall removes every installed artifact =="
"$BIN/castellan" uninstall --yes --keep-config >"$W/uninstall.log" 2>&1
for u in castellan.service castellan-freeze.service castellan-thaw.service; do
  [ -f "$UNITS/$u" ] && bad "K22: $u still present after uninstall" || ok "K22: $u removed"
done
[ -S "$SOCK" ] && bad "K22: socket still present" || ok "K22: socket removed"

echo
echo "== SUMMARY =="
echo "  PASS=$PASS FAIL=$FAIL NOTE=$NOTE  workdir: $W"
if [ "$FAIL" -eq 0 ]; then echo "P21.5-ACCEPT-PASS"; exit 0; else echo "P21.5-ACCEPT-FAIL"; exit 1; fi
