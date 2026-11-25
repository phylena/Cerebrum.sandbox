"""Launcher for the process runtime: applies the sandbox restrictions to itself, then execs the
sandboxed program. Run as `python3 -I -S csb_launch.py '<json config>' -- argv...`.

It is a separate program (not a preexec_fn) because the controller is multi-threaded, and code
between fork and exec in a threaded process can deadlock. It uses only the standard library and
ctypes, and fails closed: if a required restriction cannot be applied, the program is not run.

Order: resource limits -> no_new_privs -> Landlock (files + TCP) -> seccomp -> exec.
"""
import ctypes
import ctypes.util
import json
import os
import resource
import sys

EXIT_SETUP = 125  # like env(1)/timeout(1): the sandbox could not be set up; the program never ran

# ---- syscalls (x86_64 and aarch64 share the Landlock numbers) ---------------------------------
SYS_LANDLOCK_CREATE_RULESET, SYS_LANDLOCK_ADD_RULE, SYS_LANDLOCK_RESTRICT_SELF = 444, 445, 446
PR_SET_NO_NEW_PRIVS = 38
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1

# Landlock filesystem rights, with the ABI version that introduced them
FS = {"execute": (1 << 0, 1), "write_file": (1 << 1, 1), "read_file": (1 << 2, 1), "read_dir": (1 << 3, 1),
      "remove_dir": (1 << 4, 1), "remove_file": (1 << 5, 1), "make_char": (1 << 6, 1), "make_dir": (1 << 7, 1),
      "make_reg": (1 << 8, 1), "make_sock": (1 << 9, 1), "make_fifo": (1 << 10, 1), "make_block": (1 << 11, 1),
      "make_sym": (1 << 12, 1), "refer": (1 << 13, 2), "truncate": (1 << 14, 3), "ioctl_dev": (1 << 15, 5)}
NET_BIND_TCP, NET_CONNECT_TCP = 1 << 0, 1 << 1  # ABI >= 4

READ = ("execute", "read_file", "read_dir")
DEV = ("read_file", "write_file", "read_dir", "ioctl_dev", "truncate")
RW = ("execute", "write_file", "read_file", "read_dir", "remove_dir", "remove_file", "make_dir", "make_reg",
      "make_sym", "make_fifo", "make_sock", "refer", "truncate")

_libc = ctypes.CDLL(None, use_errno=True)


def fail(msg: str) -> "None":
    sys.stderr.write(f"cerebrum-sandbox: {msg}\n")
    sys.stderr.flush()
    os._exit(EXIT_SETUP)


def landlock_abi() -> int:
    v = _libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, ctypes.c_size_t(0), LANDLOCK_CREATE_RULESET_VERSION)
    return v if v > 0 else 0


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64)]


class _PathBeneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def _mask(names, abi: int) -> int:
    return sum(FS[n][0] for n in names if FS[n][1] <= abi)


def apply_landlock(read_paths, rw_paths, dev_paths, block_tcp: bool) -> int:
    abi = landlock_abi()
    if abi < 1:
        fail("Landlock is not available on this kernel")
    handled_fs = _mask(FS, abi)
    attr = _RulesetAttr(handled_fs, (NET_BIND_TCP | NET_CONNECT_TCP) if (block_tcp and abi >= 4) else 0)
    size = ctypes.sizeof(attr) if abi >= 4 else 8
    fd = _libc.syscall(SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(attr), ctypes.c_size_t(size), 0)
    if fd < 0:
        fail(f"landlock_create_ruleset failed (errno {ctypes.get_errno()})")
    for paths, rights in ((read_paths, READ), (rw_paths, RW), (dev_paths, DEV)):
        for p in paths:
            if not os.path.exists(p):
                continue
            pfd = os.open(p, os.O_PATH | os.O_CLOEXEC)
            # a rule on a regular file may only carry file rights
            allowed = _mask(rights, abi) & (handled_fs if os.path.isdir(p) else _mask(
                ("execute", "write_file", "read_file", "truncate", "ioctl_dev"), abi))
            rule = _PathBeneath(allowed, pfd)
            if _libc.syscall(SYS_LANDLOCK_ADD_RULE, fd, LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(rule), 0) != 0:
                fail(f"landlock_add_rule({p}) failed (errno {ctypes.get_errno()})")
            os.close(pfd)
    if _libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0) != 0:
        fail(f"landlock_restrict_self failed (errno {ctypes.get_errno()})")
    os.close(fd)
    return abi


# ---- seccomp through libseccomp ---------------------------------------------------------------
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_CMP_NE, SCMP_CMP_EQ, SCMP_CMP_MASKED_EQ = 1, 4, 7
EPERM, ENOSYS = 1, 38
AF_UNIX = 1
# CLONE_NEWUSER, NEWPID, NEWNET, NEWIPC, NEWUTS, NEWNS, NEWCGROUP, NEWTIME
CLONE_NEW_FLAGS = (0x10000000, 0x20000000, 0x40000000, 0x08000000, 0x04000000, 0x00020000, 0x02000000, 0x00000080)

DENY = ["ptrace", "process_vm_readv", "process_vm_writev", "mount", "umount2", "pivot_root", "chroot",
        "swapon", "swapoff", "reboot", "kexec_load", "kexec_file_load", "init_module", "finit_module",
        "delete_module", "bpf", "perf_event_open", "keyctl", "add_key", "request_key", "setns", "unshare",
        "userfaultfd", "io_uring_setup", "io_uring_enter", "io_uring_register", "acct", "quotactl",
        "open_by_handle_at", "name_to_handle_at", "fanotify_init", "lookup_dcookie", "setsid", "tkill",
        "move_mount", "open_tree", "fsopen", "fsmount", "fsconfig", "fspick", "mount_setattr",
        "landlock_create_ruleset", "kcmp", "pidfd_getfd", "syslog", "vhangup", "iopl", "ioperm"]


class _ArgCmp(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int), ("datum_a", ctypes.c_uint64),
                ("datum_b", ctypes.c_uint64)]


def apply_seccomp(protect_pids: list[int]) -> None:
    name = ctypes.util.find_library("seccomp") or "libseccomp.so.2"
    try:
        lib = ctypes.CDLL(name, use_errno=True)
    except OSError:
        fail("libseccomp is not installed")
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint,
                                           ctypes.POINTER(_ArgCmp)]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    ctx = lib.seccomp_init(SCMP_ACT_ALLOW)
    if not ctx:
        fail("seccomp_init failed")

    def errno_action(e: int) -> int:
        return 0x00050000 | (e & 0xFFFF)

    def rule(syscall: str, action: int, *cmps: tuple[int, int, int, int]) -> None:
        nr = lib.seccomp_syscall_resolve_name(syscall.encode())
        if nr < 0:  # not on this architecture
            return
        arr = (_ArgCmp * max(1, len(cmps)))(*[_ArgCmp(*c) for c in cmps])
        rc = lib.seccomp_rule_add_array(ctx, action, nr, len(cmps), arr if cmps else None)
        if rc != 0:
            fail(f"seccomp rule for {syscall} failed ({rc})")

    for sc in DENY:
        rule(sc, errno_action(EPERM))
    # clone3 cannot be filtered by flags: make glibc fall back to clone, which can
    rule("clone3", errno_action(ENOSYS))
    # no new namespaces (the rules for one syscall are OR-ed: any CLONE_NEW* flag is refused)
    for flag in CLONE_NEW_FLAGS:
        rule("clone", errno_action(EPERM), (0, SCMP_CMP_MASKED_EQ, flag, flag))
    # network: only Unix sockets (no IPv4/IPv6/raw/packet/netlink)
    rule("socket", errno_action(EPERM), (0, SCMP_CMP_NE, AF_UNIX, 0))
    # signals: never the controller (same Unix user when there is no PID namespace), never "every process"
    mask32 = 0xFFFFFFFF
    for pid in protect_pids:
        for target in (pid, (-pid) & mask32):
            rule("kill", errno_action(EPERM), (0, SCMP_CMP_MASKED_EQ, mask32, target))
        rule("tgkill", errno_action(EPERM), (0, SCMP_CMP_MASKED_EQ, mask32, pid))
        rule("pidfd_open", errno_action(EPERM), (0, SCMP_CMP_MASKED_EQ, mask32, pid))
    rule("kill", errno_action(EPERM), (0, SCMP_CMP_MASKED_EQ, mask32, mask32))  # kill(-1, ...)
    if lib.seccomp_load(ctx) != 0:
        fail("seccomp_load failed")


def apply_limits(cfg: dict) -> None:
    mb = 1024 * 1024
    limits = [
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_NOFILE, cfg.get("nofile", 1024)),
        (resource.RLIMIT_FSIZE, cfg["fsize_mb"] * mb),
        (resource.RLIMIT_DATA, cfg["memory_mb"] * mb),
        (resource.RLIMIT_CPU, cfg["cpu_seconds"]),
    ]
    if cfg.get("nproc"):
        limits.append((resource.RLIMIT_NPROC, cfg["nproc"]))
    for which, value in limits:
        try:
            resource.setrlimit(which, (value, value))
        except (ValueError, OSError) as e:
            fail(f"setrlimit({which}) failed: {e}")


def main() -> None:
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        fail("usage: csb_launch.py CONFIG -- argv...")
    cfg = json.loads(sys.argv[1])
    argv = sys.argv[3:]
    apply_limits(cfg)
    if _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        fail("could not set no_new_privs")
    if cfg.get("landlock"):
        ll = cfg["landlock"]
        apply_landlock(ll["read"], ll["rw"], ll["dev"], ll.get("block_tcp", True))
    apply_seccomp(cfg.get("protect_pids", []))
    try:
        os.chdir(cfg["cwd"])
    except OSError as e:
        fail(f"cannot enter the working directory: {e}")
    try:
        os.execvp(argv[0], argv)
    except OSError as e:
        sys.stderr.write(f"{argv[0]}: {e.strerror}\n")
        os._exit(127 if isinstance(e, FileNotFoundError) else 126)


if __name__ == "__main__":
    main()
