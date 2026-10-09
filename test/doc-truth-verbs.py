#!/usr/bin/env python3
"""Doc-truth: every command the CLI help advertises must actually exist,
and every command with a match arm must be advertised.

Motivation (2026-10-08): `print_usage_and_exit` listed `castellan daemon`, and
the README told users to run it three times, but the CLI has no `daemon` match
arm — the documented first step failed with "unknown command: daemon" on a
fresh install. The release also shipped only the `castellan` binary, so even
`castellan-daemon` was not in the download. A help line that names a
non-existent command is the same class of dishonesty as a stale status line:
it is a claim about the code, checked against the code.

J2 adds the reverse direction: `diff`, `undo`, `keep`, `siblings` and
`campaign` had match arms but no usage line, so the commands existed and were
invisible. Both directions are checked now.

Rules:
- advertised -> arm: each `eprintln!("  castellan <verb> ...")` usage line,
  the verb must appear as a match arm in the same file. Verbs written with a
  leading `[` or `--` are flags, not commands, and are skipped.
  `castellan-daemon` is a distinct binary, not a CLI verb.
- arm -> advertised: each top-level match-arm string literal in the command
  dispatch (`"<verb>" =>` or `"<verb>" | ... =>`) must appear in a usage line.
  Aliases (`help`/`--help`/`-h`, `version`/`--version`/`-V`) and the catch-all
  are exempt.

Exit non-zero on any mismatch.
"""
import re
import sys

SRC = "crates/castellan-cli/src/main.rs"

# Match arms whose verb is a flag alias or handled outside the usage table.
EXEMPT = {"help", "--help", "-h", "version", "--version", "-V"}


def advertised_verbs(src: str) -> list[str]:
    usage = re.findall(r'eprintln!\("  (castellan[^"]*)"', src)
    if not usage:
        print("FAIL: no usage lines found — parser or format changed.")
        return []
    advertised = []
    for line in usage:
        toks = line.split()
        if not toks or toks[0] != "castellan" or len(toks) < 2:
            continue
        verb = toks[1]
        if verb.startswith("[") or verb.startswith("--"):
            continue
        advertised.append(verb)
    return advertised


def match_arm_verbs(src: str) -> list[str]:
    """Top-level dispatch arms of `match args[0].as_str()`. That block's
    arms sit at exactly four spaces of indentation (`    "verb" =>` or
    `    "a" | "b" =>`); string-literal matches inside functions are
    indented deeper, so the indent filter separates dispatch from data."""
    arms = []
    for m in re.finditer(r'^    "([a-z][a-z0-9-]*)"(\s*\|[^=]*)?\s*=>', src, re.M):
        first = m.group(1)
        if first in EXEMPT:
            continue
        arms.append(first)
        if m.group(2):
            for alt in re.findall(r'"([a-z][a-z0-9-]*)"', m.group(2)):
                if alt not in EXEMPT:
                    arms.append(alt)
    return arms


def main() -> int:
    try:
        src = open(SRC).read()
    except OSError as e:
        print(f"FAIL: cannot read {SRC}: {e}")
        return 1

    advertised = advertised_verbs(src)
    if not advertised:
        print("FAIL: no verbs parsed from usage — format changed.")
        return 1

    missing_arms = [
        v for v in advertised
        if not re.search(r'"' + re.escape(v) + r'"\s*(\||=>)', src)
    ]
    print(f"advertised verbs: {sorted(set(advertised))}")
    if missing_arms:
        print(f"FAIL: help advertises {sorted(set(missing_arms))} with no match arm in {SRC}")
        return 1
    print(f"all {len(set(advertised))} advertised verbs have match arms")

    arms = set(match_arm_verbs(src))
    adv = set(advertised)
    invisible = sorted(v for v in arms if v not in adv)
    if invisible:
        print(f"FAIL: match arms exist but are not in help: {invisible}")
        print("      every command a user can run must be discoverable in usage.")
        return 1
    print(f"all {len(arms)} match-arm verbs are advertised")

    # The completions table is hand-written; it must name every verb help
    # advertises (a missing verb means Tab silently offers nothing).
    comp_src = open("crates/castellan-cli/src/completions.rs").read()
    m = re.search(r"VERBS: &\[&str\] = &\[(.*?)\];", comp_src, re.S)
    if not m:
        print("FAIL: cannot parse the VERBS table in completions.rs")
        return 1
    comp = set(re.findall(r'"([a-z][a-z0-9-]*)"', m.group(1)))
    missing_comp = sorted(adv - comp)
    if missing_comp:
        print(f"FAIL: help advertises {missing_comp} but completions.rs omits them")
        return 1
    print(f"completions table covers all {len(adv)} advertised verbs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
