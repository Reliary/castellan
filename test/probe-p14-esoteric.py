#!/usr/bin/env python3
"""P14 esoteric battery — run INSIDE an enforced session.
Targets: new mount API attach paths, pidfd_getfd, process_madvise,
name_to_handle_at, and non-INET/UNIX socket families the broker's
`Other(_) => Allow` arm waves through.
"""
import ctypes, os, socket, struct, sys

libc = ctypes.CDLL("libc.so.6", use_errno=True)
def sy(nr, *a):
    ctypes.set_errno(0)
    args=[]
    for x in a:
        if isinstance(x, bytes): args.append(ctypes.c_char_p(x))
        elif isinstance(x, ctypes.c_char_p): args.append(x)
        elif x is None: args.append(ctypes.c_void_p(None))
        else: args.append(ctypes.c_long(x))
    r = libc.syscall(ctypes.c_long(nr), *args)
    if r < 0:
        e=ctypes.get_errno(); return None, "ERRNO-%d" % e
    return r, "OK"

SYS_mount=165; SYS_umount2=166; SYS_open_tree=428; SYS_move_mount=429
SYS_fsopen=430; SYS_fsconfig=431; SYS_fsmount=432; SYS_mount_setattr=442
SYS_pidfd_open=434; SYS_pidfd_getfd=438
SYS_process_madvise=440; SYS_process_mrelease=448
SYS_name_to_handle_at=303; SYS_open_by_handle_at=304
SYS_unshare=272
CLONE_NEWUSER=0x10000000; CLONE_NEWNS=0x00020000
AT_FDCWD=-100; FSCONFIG_CMD_CREATE=6; MOVE_MOUNT_F_EMPTY_PATH=0x4

print("== new mount API ==")
r,st=sy(SYS_unshare, CLONE_NEWUSER|CLONE_NEWNS); print("unshare=%s"%st)
print("legacy_mount=%s"%sy(SYS_mount, b"tmpfs", sys.argv[1].encode(), b"tmpfs", 0, None)[1])
fsfd,st=sy(SYS_fsopen, b"tmpfs", 0); print("fsopen=%s"%st)
if fsfd is not None:
    print("fsconfig_create=%s"%sy(SYS_fsconfig, fsfd, FSCONFIG_CMD_CREATE, None, None, 0)[1])
    mfd,st=sy(SYS_fsmount, fsfd, 0, 0); print("fsmount=%s"%st)
    if mfd is not None:
        # attach INSIDE the write root (project) vs OUTSIDE (target)
        print("move_mount_to_WRITEROOT=%s"%sy(SYS_move_mount, mfd, b"", AT_FDCWD,
              sys.argv[2].encode(), MOVE_MOUNT_F_EMPTY_PATH)[1])
ot,st=sy(SYS_open_tree, AT_FDCWD, b"/", 0); print("open_tree(/)=%s"%st)
if ot is not None:
    # can a detached mount fd be traversed directly?
    try:
        fd=os.open("/proc/self/fd/%d/etc/hostname"%ot, os.O_RDONLY)
        print("openat_through_mountfd=OK fd=%d"%fd)
    except OSError as e:
        print("openat_through_mountfd=ERRNO-%d"%e.errno)

print("== pidfd / process families ==")
pfd,st=sy(SYS_pidfd_open, os.getpid(), 0); print("pidfd_open(self)=%s"%st)
if pfd is not None:
    print("pidfd_getfd(self,0)=%s"%sy(SYS_pidfd_getfd, pfd, 0, 0)[1])
print("process_madvise(self)=%s"%sy(SYS_process_madvise, -1, 0, 0, 0, 0)[1])
print("process_mrelease(self)=%s"%sy(SYS_process_mrelease, -1, 0)[1])
print("name_to_handle_at=%s"%sy(SYS_name_to_handle_at, AT_FDCWD, b"/etc/hostname", 0, 0, 0)[1])

print("== socket families (broker Other->Allow) ==")
for name, fam in [("AF_VSOCK",40),("AF_ALG",38),("AF_NETLINK",16),
                  ("AF_PACKET",17),("AF_XDP",44),("AF_TIPC",30),
                  ("AF_SMC",43),("AF_KCM",41),("AF_QIPCRTR",42)]:
    try:
        s=socket.socket(fam, socket.SOCK_RAW if fam in (17,) else socket.SOCK_STREAM)
        print("%s=SOCKET-OK"%name); s.close()
    except OSError as e:
        print("%s=ERRNO-%d"%(name,e.errno))
