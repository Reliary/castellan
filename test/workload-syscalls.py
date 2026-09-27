#!/usr/bin/env python3
"""Map probe syscall numbers to names and check them against the class table."""
import re
import shutil
import subprocess
import sys
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
PROBE = REPO / "target/debug/examples/syscall-probe"

def kernel_table():
    names = {}
    for h in ("/usr/include/asm/unistd_64.h",
              "/usr/include/x86_64-linux-gnu/asm/unistd_64.h"):
        p = pathlib.Path(h)
        if p.is_file():
            for line in p.read_text().splitlines():
                m = re.match(r"#define __NR_([a-z0-9_]+) (\d+)", line)
                if m:
                    names[int(m.group(2))] = m.group(1)
            if names:
                return names, h
    raise SystemExit("no kernel syscall table available")

def class_table():
    out = subprocess.run(
        ["cargo", "run", "--quiet", "-p", "castellan-envelope",
         "--example", "syscall-classes"],
        cwd=REPO, capture_output=True, text=True, check=True).stdout
    classes, members, decision_of = {}, {}, {}
    for line in out.splitlines():
        f = line.split("\t")
        if f[0] == "class":
            classes[f[1]] = f[2]
        elif f[0] == "member":
            members.setdefault(f[1], []).append(f[2])
            decision_of[f[2]] = f[3]
    return classes, members, decision_of

def probe(outdir, argv):
    outdir = pathlib.Path(outdir)
    if outdir.exists():
        for f in outdir.iterdir():
            f.unlink()
    r = subprocess.run([str(PROBE), str(outdir)] + argv,
                       cwd=REPO, capture_output=True, text=True)
    if r.returncode != 0:
        print("  probe failed: %s" % (r.stderr.strip()[:200] or r.returncode))
        return None
    seen = {}
    for line in (outdir / "syscalls.txt").read_text().splitlines():
        nr, cnt = line.split("\t")
        seen[int(nr)] = int(cnt)
    return seen

def main():
    kt, ksrc = kernel_table()
    classes, members, decision_of = class_table()
    print("kernel table: %s" % ksrc)

    workloads = [
        ("echo",      ["/bin/echo", "hi"]),
        ("git-init",  ["/usr/bin/git", "-C", "/tmp/opencode/wl-git", "init"]),
        ("git-commit",["/usr/bin/git", "-C", "/tmp/opencode/wl-git",
                       "-c", "user.email=t@t", "-c", "user.name=t",
                       "commit", "--allow-empty", "-m", "x"]),
        ("sh",        ["/bin/sh", "-c", "echo hi > /tmp/opencode/wl-sh.out"]),
        ("python3",   ["/usr/bin/python3", "-c", "print(sum(range(10)))"]),
        ("touch",     ["/usr/bin/touch", "/tmp/opencode/wl-touch"]),
        ("cargo-ver", ["cargo", "--version"]),
        # A real compile is the workload the V3 unblock decision was
        # actually about ("cargo/cc/touch set mtimes for fingerprints").
        # Probing only `cargo --version` would re-derive the decision
        # from a command that touches no timestamps.
        ("rustc-compile", ["rustc", "-O", "--out-dir",
                            "/tmp/opencode/wl-rustc", "/tmp/opencode/wl-hello.rs"]),
    ]
    subprocess.run(["rm", "-rf", "/tmp/opencode/wl-git", "/tmp/opencode/wl-rustc"])
    pathlib.Path("/tmp/opencode/wl-git").mkdir(parents=True, exist_ok=True)
    (pathlib.Path("/tmp/opencode/wl-git") / "f").write_text("x\n")
    pathlib.Path("/tmp/opencode/wl-rustc").mkdir(parents=True, exist_ok=True)
    pathlib.Path("/tmp/opencode/wl-hello.rs").write_text(
        'fn main() { let v: Vec<u32> = (0..10).collect(); '
        'println!("{}", v.iter().sum::<u32>()); }\n')

    all_names, hard_needed, probed_needed = set(), {}, {}
    ran = 0
    def available(prog):
        # Bare names (cargo, rustc) must be looked up on PATH; a
        # Path("cargo").exists() check silently skips the compile
        # workload, which is the one the V3 decision is actually about.
        if "/" in prog:
            return pathlib.Path(prog).exists()
        return shutil.which(prog) is not None

    for label, argv in workloads:
        if not available(argv[0]):
            print("  SKIP %-13s (%s not on PATH)" % (label, argv[0]))
            continue
        seen = probe("/tmp/opencode/sp-%s" % label, argv)
        if seen is None:
            continue
        ran += 1
        names = {kt.get(n, "nr:%d" % n) for n in seen}
        all_names |= names
        for n in names:
            d = decision_of.get(n)
            if d == "Hard":
                hard_needed.setdefault(n, []).append(label)
            elif d in ("Probed", "Novel"):
                probed_needed.setdefault(n, []).append(label)
        print("  %-11s %3d unique" % (label, len(names)))

    if not ran:
        raise SystemExit("no workload ran — gate is UNVERIFIABLE, not passing")

    print()
    print("workloads run: %d, distinct syscalls: %d" % (ran, len(all_names)))

    fails, notes = [], []
    if hard_needed:
        print()
        print("workload needs a Hard-class syscall (blocking it would break real work):")
        for n, ls in sorted(hard_needed.items()):
            fails.append("Hard '%s' needed by %s" % (n, ",".join(ls)))
            print("  %s <- %s" % (n, ", ".join(ls)))
    else:
        print("  PASS: no workload needs a Hard-class syscall")

    if probed_needed:
        print()
        print("workload needs a Probed/Novel syscall (allowed today; residual depends on it):")
        for n, ls in sorted(probed_needed.items()):
            notes.append(n)
            print("  %s <- %s" % (n, ", ".join(ls)))
    if notes:
        print()
        print("  NOTE: these are the syscalls the unblocked decisions were justified by.")
        print("        If a Probed class ever gains a member, re-run this before")
        print("        accepting the new residual.")

    unclassified = sorted(n for n in all_names
                          if n not in decision_of and not n.startswith("nr:"))
    if unclassified:
        print()
        print("  NOTE: %d workload syscall(s) are in no class: %s"
              % (len(unclassified), ", ".join(unclassified)))
        print("        That is expected for ordinary work (read, write, mmap, ...);")
        print("        the gate cares about capability-bearing classes, not all of them.")

    print()
    if fails:
        print("GATE: FAIL")
        for f in fails:
            print("  - %s" % f)
        raise SystemExit(1)
    print("GATE: PASS")

if __name__ == "__main__":
    main()
