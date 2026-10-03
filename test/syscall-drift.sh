#!/usr/bin/env bash
# Kernel-drift gate for the seccomp denylist.
#
# The seccomp filter is a denylist (commitment #8 — deliberately not an
# allowlist, see THREAT_MODEL A4). A denylist can only block what
# somebody wrote down, so the risk is not a mistake in today's list: it
# is a KERNEL UPGRADE that adds a syscall nobody enumerated. The new
# call arrives with no block entry, the agent can use it, and nothing
# reports anything.
#
# The gate makes that class of drift a red build instead of silence:
#
#   1. Dump the capability-class table (crates/castellan-envelope/src/
#      syscall_classes.rs) and check the filter and the table agree —
#      proven in Rust too, but re-proved here so the gate is meaningful
#      on a kernel whose numbers differ.
#   2. Read the RUNNING KERNEL's syscall table and find members of every
#      watched class that this kernel has but the table does not.
#      Hard/Probed -> FAIL (needs a decision). Novel -> WARN.
#   3. Report the block state of every class so a change to a Probed
#      line is visible in the log.
#
# The kernel table comes from three sources, in order of preference,
# because a CI container may not have strace or the headers:
#   a) /usr/include/asm/unistd_64.h  (glibc dev headers)
#   b) /usr/include/x86_64-linux-gnu/asm/unistd_64.h (Debian/Ubuntu)
#   c) `ausyscall --dump` if present
# If none is available the gate reports UNVERIFIABLE and exits non-zero:
# a gate that cannot see the kernel is not a gate.
set -u

# Default to the tree this script lives in, NOT a hardcoded path. The
# self-test copies the gate into a mutated tree and runs it there; a
# hardcoded REPO would make the gate read the pristine table and every
# injection would silently test nothing.
REPO=${CASTELLAN_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
FAIL=0
WARN=0
ok()  { echo "  PASS: $1"; }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
warn() { echo "  WARN: $1"; WARN=$((WARN+1)); }

# kernel_at_least X.Y.Z — is the RUNNING kernel at least X.Y.Z? Used for
# members whose class rationale documents a post-runner introduction
# version ("<name> (X.Y.Z)" in the rationale). Absent from an older
# kernel is expected; absent from a kernel that should have it stays a
# FAIL (the typo detector is unchanged — only documented-new syscalls on
# older kernels take the note path).
kernel_at_least() {
  # Two separate locals: in `local a=.. b=${a}..` the ${a} expands
  # before ANY assignment in the command runs, so b would capture the
  # empty outer value (caught in testing: `[ 0 -ge '' ]`).
  local want_major=${1%%.*} rest=${1#*.}
  local want_minor=${rest%%.*}
  local rel kmaj krest kmin
  rel=$(uname -r)
  kmaj=${rel%%.*}; krest=${rel#*.}; kmin=${krest%%[.-]*}
  case "$kmaj$want_minor$want_major${kmin:-0}" in
    *[!0-9]*) return 0 ;;  # unparseable kernel string: do not false-red
  esac
  [ "$kmaj" -gt "$want_major" ] && return 0
  [ "$kmaj" -eq "$want_major" ] && [ "${kmin:-0}" -ge "$want_minor" ] && return 0
  return 1
}

TABLE=$(mktemp)
trap 'rm -f "$TABLE"' EXIT

echo "== syscall capability-class table =="
(cd "$REPO" && cargo run --quiet -p castellan-envelope --example syscall-classes) \
  > "$TABLE" 2>/dev/null

if [ ! -s "$TABLE" ]; then
  bad "could not dump the class table (cargo run failed)"
  echo "GATE: FAIL — table unavailable"
  exit 1
fi

NC=$(grep -c '^class' "$TABLE")
NM=$(grep -c '^member' "$TABLE")
NB=$(grep -c '^blocked' "$TABLE")
echo "  $NC classes, $NM members, $NB blocked constants"
[ "$NC" -ge 10 ] && ok "class table has substance ($NC classes)" \
                 || bad "class table is suspiciously small ($NC classes)"

# 1. filter/table agreement -------------------------------------------
# Both directions, because either one alone is gameable:
#   blocked -> has a Hard class   (a block with no rationale)
#   Hard class -> is blocked      (a closure the filter does not have)
# The second is the one that matters. It is only checkable if the gate
# reads the filter's REAL contents (`filtered` lines, resolved by the
# crate itself) rather than a second declaration of the same list.
filtered=$(awk -F'\t' '$1=="filtered"{print $2}' "$TABLE" | sort -u)
nfiltered=$(wc -l <<<"$filtered" | tr -d ' ')
[ "$nfiltered" -ge 30 ] && ok "filter reports $nfiltered blocked syscalls" \
                       || bad "filter reports only $nfiltered blocked syscalls — implausible"
unresolved=$(grep -c '^nr:' <<<"$filtered" || true)
[ "${unresolved:-0}" = "0" ] \
  && ok "every blocked syscall resolved to a name" \
  || bad "$unresolved blocked syscall(s) have no name mapping (unrecognised const)"

hard_consts=$(awk -F'\t' '$1=="hardconsts"{n=split($3,a,","); for(i=1;i<=n;i++) if(a[i]!="") print a[i]}' "$TABLE" | sort -u)
# Normalise SYS_pkey_alloc -> pkey_alloc so both sides are bare names.
hard_bare=$(printf '%s\n' "$hard_consts" | sed 's/^SYS_//' | grep -v '^$' | sort -u)
printf '%s\n' "$filtered" | grep -v '^$' | sort -u > /tmp/.drift_filtered.$$
printf '%s\n' "$hard_bare" | grep -v '^$' | sort -u > /tmp/.drift_hard.$$

orphan=$(comm -23 /tmp/.drift_filtered.$$ /tmp/.drift_hard.$$)
if [ -z "$orphan" ]; then
  ok "every blocked syscall belongs to a Hard class"
else
  bad "blocked syscalls with no Hard class: $(tr '\n' ' ' <<<"$orphan")"
fi

unblocked=$(comm -23 /tmp/.drift_hard.$$ /tmp/.drift_filtered.$$)
if [ -z "$unblocked" ]; then
  ok "every Hard-class syscall is actually in the filter"
else
  bad "Hard class claims these are blocked but the filter does not: $(tr '\n' ' ' <<<"$unblocked")"
fi
rm -f /tmp/.drift_filtered.$$ /tmp/.drift_hard.$$

# 2. kernel cross-check -----------------------------------------------
KERNEL_LIST=$(mktemp)
trap 'rm -f "$TABLE" "$KERNEL_LIST"' EXIT
KERNEL_SRC=""
for h in /usr/include/asm/unistd_64.h \
         /usr/include/x86_64-linux-gnu/asm/unistd_64.h; do
  if [ -r "$h" ]; then
    sed -n 's/^#define __NR_\([a-z0-9_]*\) .*/\1/p' "$h" | sort -u > "$KERNEL_LIST"
    if [ -s "$KERNEL_LIST" ]; then KERNEL_SRC="$h"; break; fi
  fi
done
if [ -z "$KERNEL_SRC" ] && command -v ausyscall >/dev/null 2>&1; then
  ausyscall --dump 2>/dev/null | awk 'NR>1{print $2}' | sort -u > "$KERNEL_LIST"
  KERNEL_SRC="ausyscall"
fi

if [ ! -s "$KERNEL_LIST" ]; then
  bad "cannot read the kernel's syscall table — gate is UNVERIFIABLE, not passing"
  echo "GATE: FAIL"
  exit 1
fi
NKS=$(wc -l < "$KERNEL_LIST")
echo "  kernel table: $NKS syscalls (from $KERNEL_SRC)"
echo "  kernel: $(uname -r)"

# The class line is exactly 6 tab-separated fields:
#   class <name> <Decision> <capability> <rationale> <members>
# `read` is bash-only here (arrays via -a), and every field must be
# named or members lands empty and the typo check silently passes.
DRIFT=0
while IFS=$'\t' read -r kind name decision capability rationale members; do
  [ "$kind" = "class" ] || continue
  [ -n "$name" ] || continue
  nconst=$(awk -F'\t' -v c="$name" '$1=="blocked" && $2==c{n++} END{print n+0}' "$TABLE")
  case "$decision" in
    Hard)   echo "  state: $name = Hard (blocked: $nconst consts)" ;;
    Probed) echo "  state: $name = Probed (DELIBERATELY ALLOWED — residual on record; blocked: $nconst)" ;;
    Novel)  echo "  state: $name = Novel (not blocked, not needed; blocked: $nconst)" ;;
    *)      bad "class $name has an unrecognised decision '$decision'"; DRIFT=1 ;;
  esac
  if [ -z "$members" ]; then
    bad "class $name has no member list — the table format changed or the line is truncated"
    DRIFT=1
    continue
  fi
  IFS=',' read -ra mem <<< "$members"
  for m in "${mem[@]}"; do
    [ -n "$m" ] || continue
    if ! grep -qx "$m" "$KERNEL_LIST"; then
      # Documented-new syscall: the class rationale may carry the
      # introducing version as "<name> (X.Y.Z)" (e.g. rseq_slice_yield
      # (7.0.3) — CI runner kernels predate it). Knowledge lives in the
      # table, not a second copy here; an undocumented absence is still
      # the typo/vacuous-class FAIL, and a documented absence on a
      # kernel that should have it is also FAIL.
      since=$(grep -oE "$m \([0-9]+(\.[0-9]+)+\)" <<< "$rationale" \
        | grep -oE '[0-9]+(\.[0-9]+)+' | head -1 || true)
      if [ -n "$since" ] && ! kernel_at_least "$since"; then
        echo "  note: '$m' introduced in $since; running kernel $(uname -r) is older — expected absence"
      else
        bad "class $name lists '$m' but this kernel has no such syscall (typo or arch gap — the class is silently vacuous)"
        DRIFT=1
      fi
    fi
  done
done < <(grep '^class' "$TABLE")
[ "$DRIFT" = "0" ] && ok "every class member is a real syscall on this kernel"

# 2a. P14 F-D: every MEMBER of a Hard class must be in the filter.
# This is the check whose absence let 21 declared-Hard members
# (fsopen/pidfd_getfd/…) run unblocked while the gate stayed green. The
# old "Hard class -> is blocked" branch (below, via check_kw) computed
# hits = comm -23 <kernel-matching> <known>, which excludes every name
# the table already lists — so a listed-but-unblocked member was
# invisible. This branch works on the member set directly, and the
# selftest seeds a removal to prove it can go red.
hard_mem=$(awk -F'\t' '$1=="class" && $3=="Hard"{n=split($6,a,","); for(i=1;i<=n;i++) if(a[i]!="") print a[i]}' "$TABLE" | sort -u)
printf '%s\n' "$hard_mem" | grep -v '^$' | sort -u > /tmp/.drift_hardmem.$$
printf '%s\n' "$filtered" | grep -v '^$' | sort -u > /tmp/.drift_filt2.$$
gap=$(comm -23 /tmp/.drift_hardmem.$$ /tmp/.drift_filt2.$$)
if [ -z "$gap" ]; then
  ok "every Hard-class member is in the filter"
else
  bad "Hard-class members NOT blocked (declared closed, actually open): $(tr '\n' ' ' <<<"$gap")"
fi
rm -f /tmp/.drift_hardmem.$$ /tmp/.drift_filt2.$$

# 2b. the direction that actually matters: this kernel has syscalls in a
# watched CAPABILITY that the table never names. The table cannot know
# them in advance — that is the point — so the gate flags every
# capability-bearing name the kernel offers and cross-references the
# table. A name appearing under two classes, or under a class but not
# blocked when the class is Hard, is a real gap.
#
# The capability-bearing list is a superset guard: these are the names
# the kernel exposes that belong to a watched class by their documented
# capability. Any kernel-only name here is a candidate the table must
# classify.
echo
echo "== kernel capability census (Hard/Probed classes must be closed) =="
# Names the table already accounts for.
known=$(awk -F'\t' '$1=="member"{print $3}' "$TABLE" | sort -u)
blocked_names=$(awk -F'\t' '$1=="blocked"{print $3}' "$TABLE" | sed 's/^SYS_//' | sort -u)

# Capability keywords: any kernel syscall whose name contains one of
# these is in a watched class whether or not the table lists it. This is
# the early-warning channel for new-syscall drift.
check_kw() {
  local kw=$1 cls=$2 decision=$3
  local hits
  hits=$(comm -23 <(grep -E "$kw" "$KERNEL_LIST" | sort -u) <(grep -E "^$kw" <<<"$known" | sort -u))
  [ -z "$hits" ] && return 0
  local h
  while read -r h; do
    [ -n "$h" ] || continue
    case "$decision" in
      Hard|Real)
        if ! grep -qx "$h" <<<"$known"; then
          bad "kernel exposes '$h' (matches $kw, class $cls) but the table never classifies it"
        elif ! grep -qx "$h" <<<"$blocked_names"; then
          bad "class $cls is Hard and the table lists '$h', but the filter does NOT block it"
        fi
        ;;
      Probed)
        # A NEW name in a Probed class is a FAIL, not a warning. Probed
        # means "we measured this exact family and accepted the residual
        # on the record". A member the record does not mention has not
        # been measured, so the residual does not extend to it — the
        # decision has to be made explicitly or the class is silently
        # broader than its justification.
        if ! grep -qx "$h" <<<"$known"; then
          bad "kernel exposes '$h' (matches $kw, class $cls) — a Probed class's written residual does not cover it; decide and record it"
        fi
        ;;
      Novel)
        warn "kernel exposes '$h' (matches $kw) — candidate for a watched class"
        ;;
    esac
  done <<<"$hits"
}

check_kw '^(mount|umount2|pivot_root|chroot|fsopen|fsconfig|fsmount|move_mount|open_tree|mount_setattr)$' mount-namespace Hard
check_kw '^(ptrace|process_vm_|process_mrelease|kcmp)$' process-memory Hard
check_kw '^(add_key|request_key|keyctl)$' keyring Hard
check_kw '^(init_module|finit_module|delete_module|kexec_)' kernel-module Hard
check_kw '^(bpf|perf_event_open|userfaultfd|syslog)$' kernel-observer Hard
check_kw '^(io_uring|io_ring)' io-uring Hard
check_kw '^(open_by_handle_at|name_to_handle_at)$' file-handle-bypass Hard
check_kw '^(setxattr|lsetxattr|fsetxattr|removexattr|lremovexattr|fremovexattr)$' extended-attribute Hard
check_kw '^(reboot|swapon|swapoff|settimeofday|clock_settime|clock_adjtime|adjtimex|quotactl)' machine-admin Hard
check_kw '^(unshare|setns)$' namespace-membership Probed
check_kw '^(chown|fchown|lchown|fchownat|chmod|fchmod|utime|utimensat|utimes|futimesat)$' ownership-transfer Probed
check_kw '^(setrlimit|prlimit64|sched_setattr|membarrier|rseq)' resource-tuning Novel
check_kw '^(landlock_|lsm_)' landlock-self-service Probed
ok "census complete"

# 3. residual visibility ----------------------------------------------
NR=$(grep -c '^residual' "$TABLE")
echo
echo "== Probed classes (the honest residuals) =="
grep '^residual' "$TABLE" | while IFS=$'\t' read -r _ name why; do
  echo "  $name: ${why:0:150}"
done
[ "$NR" -ge 1 ] && ok "$NR Probed class(es) carry a written residual" \
                || bad "no Probed class records why it is allowed"

echo
if [ "$FAIL" = "0" ]; then
  echo "GATE: PASS ($WARN warn)"
  exit 0
fi
echo "GATE: FAIL ($FAIL fail, $WARN warn)"
exit 1
