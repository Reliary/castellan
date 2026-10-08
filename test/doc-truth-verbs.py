#!/usr/bin/env python3
"""Doc-truth: every command the CLI help advertises must actually exist.

Motivation (2026-10-08): `print_usage_and_exit` listed `castellan daemon`, and
the README told users to run it three times, but the CLI has no `daemon` match
arm — the documented first step failed with "unknown command: daemon" on a
fresh install. The release also shipped only the `castellan` binary, so even
`castellan-daemon` was not in the download. A help line that names a
non-existent command is the same class of dishonesty as a stale status line:
it is a claim about the code, checked against the code.

Rule: for each `eprintln!("  castellan <verb> ...")` usage line, the verb must
appear as a match arm (`"<verb>" =>` or `"<verb>" | ... =>`) in the same file.
Verbs written with a leading `[` or `--` are flags, not commands, and are
skipped. `castellan-daemon` is a distinct binary, not a CLI verb.

Exit non-zero on any advertised command with no arm.
"""
import re
import sys

SRC = "crates/castellan-cli/src/main.rs"


def main() -> int:
    try:
        src = open(SRC).read()
    except OSError as e:
        print(f"FAIL: cannot read {SRC}: {e}")
        return 1

    usage = re.findall(r'eprintln!\("  (castellan[^"]*)"', src)
    if not usage:
        print("FAIL: no usage lines found — parser or format changed.")
        return 1

    advertised = []
    for line in usage:
        toks = line.split()
        if not toks or toks[0] != "castellan" or len(toks) < 2:
            continue
        verb = toks[1]
        if verb.startswith("[") or verb.startswith("--"):
            continue
        advertised.append(verb)

    if not advertised:
        print("FAIL: no verbs parsed from usage — format changed.")
        return 1

    missing = [
        v for v in advertised
        if not re.search(r'"' + re.escape(v) + r'"\s*(\||=>)', src)
    ]
    print(f"advertised verbs: {sorted(set(advertised))}")
    if missing:
        print(f"FAIL: help advertises {sorted(set(missing))} with no match arm in {SRC}")
        return 1
    print(f"all {len(set(advertised))} advertised verbs have match arms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
