#!/usr/bin/env python3
"""P14 probe: can the agent mount with the NEW mount API?

The envelope denylist blocks the legacy mount/umount2/pivot_root/chroot.
The class table declares fsopen/fsconfig/fsmount/move_mount/open_tree/
mount_setattr as HARD members, but blocked_syscalls() never includes them
(only the class's libc_consts are enforced, and the drift gate's
"table-lists-but-filter-does-not" branch is dead). Probe: unshare a
user+mount namespace, then try the legacy path (must EPERM) and the new
path (suspected to succeed).
"""
import ctypes, os, sys

libc = ctypes.CDLL("libc.so.6", use_errno=True)

SYS_fsopen = 430
SYS_fsconfig = 431
SYS_fsmount = 432
SYS_move_mount = 429
SYS_open_tree = 428
SYS_mount = 165
SYS_unshare = 272

CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000

FSCONFIG_CMD_CREATE = 6
MOVE_MOUNT_F_EMPTY_PATH = 0x00000004
AT_FDCWD = -100


def rawerr(name):
    e = ctypes.get_errno()
    return "ERRNO-%d(%s)" % (e, os.strerror(e))


def syscall(nr, *args):
    ctypes.set_errno(0)
    ctypes_args = []
    for a in args:
        if isinstance(a, ctypes.c_char_p):
            ctypes_args.append(a)
        elif isinstance(a, bytes):
            ctypes_args.append(ctypes.c_char_p(a))
        elif a is None:
            ctypes_args.append(ctypes.c_void_p(None))
        else:
            ctypes_args.append(ctypes.c_long(a))
    r = libc.syscall(ctypes.c_long(nr), *ctypes_args)
    if r < 0:
        return None, rawerr("x")
    return r, "OK"


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "/tmp/p14mnt"
    # 1. user+mount namespace (needed for CAP_SYS_ADMIN for mounting).
    r, st = syscall(SYS_unshare, CLONE_NEWUSER | CLONE_NEWNS)
    print("unshare(user|mnt)=%s" % st)
    # 2. legacy mount to the target (kernel tmpfs) — denylist should EPERM.
    r, st = syscall(SYS_mount, ctypes.c_char_p(b"tmpfs"), ctypes.c_char_p(target.encode()),
                    ctypes.c_char_p(b"tmpfs"), 0, None)
    print("legacy_mount=%s" % st)
    # 3. new mount API: fsopen(tmpfs) -> fsconfig(CREATE) -> fsmount -> move_mount
    fsfd, st = syscall(SYS_fsopen, ctypes.c_char_p(b"tmpfs"), 0)
    print("fsopen=%s%s" % (st, (" fd=%d" % fsfd) if fsfd is not None else ""))
    if fsfd is None:
        return
    r, st = syscall(SYS_fsconfig, fsfd, FSCONFIG_CMD_CREATE, None, None, 0)
    print("fsconfig(CREATE)=%s" % st)
    mfd, st = syscall(SYS_fsmount, fsfd, 0, 0)
    print("fsmount=%s%s" % (st, (" mfd=%d" % mfd) if mfd is not None else ""))
    if mfd is None:
        return
    r, st = syscall(SYS_move_mount, mfd, ctypes.c_char_p(b""),
                    AT_FDCWD, ctypes.c_char_p(target.encode()), MOVE_MOUNT_F_EMPTY_PATH)
    print("move_mount=%s" % st)
    if r is not None:
        # Did it actually take? write a file through the new mount.
        try:
            with open(os.path.join(target, "p14-proof"), "w") as f:
                f.write("mounted by the agent\n")
            print("write_through_new_mount=OK")
            print("MOUNT-ESCAPE-CONFIRMED")
        except OSError as e:
            print("write_through_new_mount=ERRNO-%d(%s)" % (e.errno, e.strerror))
            print("MOUNT-REACHABLE-BUT-WRITE-DENIED")
    # 4. open_tree as a second shape: clone an existing mount.
    tfd, st = syscall(SYS_open_tree, AT_FDCWD, ctypes.c_char_p(b"/"), 0)
    print("open_tree(/)=%s%s" % (st, (" fd=%d" % tfd) if tfd is not None else ""))


main()
