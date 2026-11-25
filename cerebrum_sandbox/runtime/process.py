"""Process adapter: sandboxes as restricted, unprivileged process trees.

For hosts that cannot run containers for sandboxes: a Hugging Face Space (itself an unprivileged
container), a PaaS, a CI runner. It is WEAKER than the container runtime and is therefore its own
isolation level ("process", ranked below "container"); a node only uses it when the operator turns
it on (SANDBOX_RUNTIMES=process, plus SANDBOX_PROCESS_FALLBACK=1 to serve container profiles with it).

Every command runs through csb_launch.py, which applies, in this order and failing closed:
  * resource limits: memory (RLIMIT_DATA), CPU seconds, file size, open files, processes, no core files;
  * no_new_privs;
  * Landlock (kernel >= 5.13): read-only system paths, read-write only the sandbox's own workspace,
    home and tmp; TCP bind/connect refused (Landlock ABI >= 4);
  * seccomp: only Unix sockets (no IPv4/IPv6/raw/packet/netlink), no ptrace / process_vm_* / mount /
    namespaces / io_uring / bpf / keyctl / setsid, no signals to the controller or to every process.
When bubblewrap and unprivileged user namespaces work, each command additionally runs in its own
mount, PID, network, IPC and UTS namespaces (mode "bwrap"); the sandbox then sees /workspace, /tmp
and /home/sandbox at their usual paths. Without namespaces (mode "landlock") the sandbox's directories
are at host paths: arguments and environment values starting with /workspace are rewritten to them.

Always: a clean environment (none of the controller's variables or secrets), a new session per
command (the whole tree is killed after the command, on timeout and on stop), the controller marked
non-dumpable (other processes of the same Unix user cannot read its memory or environment).

Limits that a container has and this runtime does not: no hard cap on the total size of the workspace
(single files are capped; the controller's quota check runs after commands), no per-sandbox CPU share,
and in "landlock" mode sandboxes share the PID namespace with each other (they cannot signal the
controller, but one sandbox can signal another's processes of the same Unix user). The runtime refuses
to run without Landlock or namespaces unless SANDBOX_PROCESS_ALLOW_WEAK=1.
"""
from __future__ import annotations

import ctypes
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from ..profiles import Isolation
from ..settings import Settings
from .base import ExecResult, Runtime, RuntimeError_, SandboxSpec, WORKSPACE, safe_workdir

LAUNCHER = Path(__file__).with_name("csb_launch.py")
HOME_IN, TMP_IN = "/home/sandbox", "/tmp"
SYSTEM_READ = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt", "/proc", "/sys/devices/system/cpu"]
DEVICES = ["/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", "/dev/full", "/dev/tty"]
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PR_SET_DUMPABLE = 4
# the launcher needs only the standard library: use the base interpreter (a virtualenv's python is not
# mounted inside the bubblewrap namespaces)
PYTHON = os.path.realpath(getattr(sys, "_base_executable", None) or sys.executable)


def _protect_controller() -> None:
    """Other processes of this Unix user (the sandboxes) cannot read our memory or /proc/<pid>/environ."""
    try:
        ctypes.CDLL(None, use_errno=True).prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
    except (OSError, AttributeError):
        pass


def _landlock_abi() -> int:
    try:
        v = ctypes.CDLL(None, use_errno=True).syscall(444, None, ctypes.c_size_t(0), 1)
        return v if v > 0 else 0
    except (OSError, AttributeError):
        return 0


def _seccomp_available() -> bool:
    import ctypes.util
    return bool(ctypes.util.find_library("seccomp"))


def _bwrap_works(binary: str) -> bool:
    path = shutil.which(binary)
    if not path:
        return False
    try:
        r = subprocess.run([path, "--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "true"],
                           capture_output=True, timeout=10)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _session_pids(session: int) -> list[int]:
    """Processes whose session id is `session` (field 6 of /proc/<pid>/stat)."""
    out = []
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            stat = Path(f"/proc/{d}/stat").read_text()
            fields = stat[stat.rindex(")") + 2:].split()
            if int(fields[3]) == session:
                out.append(int(d))
        except (OSError, ValueError, IndexError):
            continue
    return out


def _kill_session(session: int, sig: int = signal.SIGKILL) -> None:
    for pid in _session_pids(session):
        try:
            os.kill(pid, sig)
        except OSError:
            pass


def _user_tasks() -> int:
    """Threads + processes of this Unix user (RLIMIT_NPROC counts them all)."""
    uid, n = os.getuid(), 0
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                if os.stat(f"/proc/{d}").st_uid == uid:
                    n += len(os.listdir(f"/proc/{d}/task"))
            except OSError:
                continue
    return n


class ProcessRuntime(Runtime):
    name = "process"
    isolation = Isolation.PROCESS

    def __init__(self, st: Settings):
        self.st = st
        self.root = Path(st.process_root or (Path(st.data_dir) / "process")).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.bwrap_bin = st.process_bwrap_bin
        self.landlock_abi = _landlock_abi()
        self.seccomp = _seccomp_available()
        wanted = st.process_mode
        self.mode = "none"
        if wanted in ("auto", "bwrap") and _bwrap_works(self.bwrap_bin):
            self.mode = "bwrap"
        elif wanted in ("auto", "landlock") and self.landlock_abi >= 1:
            self.mode = "landlock"
        _protect_controller()
        self._running: dict[str, set[int]] = {}
        self._lock = threading.Lock()

    # ---- paths and state ----------------------------------------------------------------------
    def _dir(self, sid: str) -> Path:
        if not sid.isalnum() or len(sid) > 32:
            raise RuntimeError_("invalid sandbox id")
        return self.root / sid

    def _meta(self, sid: str) -> dict:
        try:
            return json.loads((self._dir(sid) / "meta.json").read_text())
        except (OSError, ValueError):
            raise RuntimeError_("sandbox does not exist on this node") from None

    def _save(self, sid: str, meta: dict) -> None:
        tmp = self._dir(sid) / "meta.json.tmp"
        tmp.write_text(json.dumps(meta))
        tmp.replace(self._dir(sid) / "meta.json")

    def _host(self, sid: str, path: str) -> str:
        """Host path of a sandbox path (landlock mode)."""
        d = self._dir(sid)
        for inner, sub in ((WORKSPACE, "workspace"), (HOME_IN, "home")):
            if path == inner or path.startswith(inner + "/"):
                return str(d / sub) + path[len(inner):]
        return path

    def _rewrite(self, sid: str, value: str) -> str:
        if self.mode == "bwrap":
            return value
        return self._host(sid, value) if value.startswith((WORKSPACE, HOME_IN)) else value

    # ---- lifecycle ----------------------------------------------------------------------------
    def ready(self) -> tuple[bool, str]:
        if not self.seccomp:
            return False, "libseccomp is not installed (needed for the network and syscall filter)"
        if self.mode == "none" and not self.st.process_allow_weak:
            return False, ("neither bubblewrap with user namespaces nor Landlock is available; refusing "
                           "(set SANDBOX_PROCESS_ALLOW_WEAK=1 to run with limits and seccomp only)")
        return True, f"mode={self.mode}"

    def create(self, spec: SandboxSpec) -> None:
        if spec.profile.isolation != self.isolation:
            raise RuntimeError_(f"runtime 'process' only runs 'process' sandboxes, not '{spec.profile.isolation}'")
        ok, detail = self.ready()
        if not ok:
            raise RuntimeError_(f"process isolation unavailable: {detail}")
        if spec.profile.network.mode.value != "none":
            raise RuntimeError_("the process runtime has no network for sandboxes: profiles with network "
                                "access need the container runtime")
        if spec.profile.gpus:
            raise RuntimeError_("the process runtime has no GPU support")
        d = self._dir(spec.sandbox_id)
        for sub in ("workspace", "home", "tmp"):
            (d / sub).mkdir(parents=True, exist_ok=True, mode=0o700)
        p = spec.profile
        self._save(spec.sandbox_id, {"state": "stopped", "profile": p.name, "memory_mb": p.memory_mb,
                                     "pids": p.pids, "workspace_mb": p.workspace_mb, "cpu": p.cpu,
                                     "env": {**p.env, **spec.env}, "created": time.time()})

    def _set_state(self, sid: str, state: str) -> None:
        meta = self._meta(sid)
        meta["state"] = state
        self._save(sid, meta)

    def start(self, sandbox_id: str) -> None:
        self._set_state(sandbox_id, "running")

    def stop(self, sandbox_id: str) -> None:
        self.kill_processes(sandbox_id)
        self._set_state(sandbox_id, "stopped")

    def pause(self, sandbox_id: str) -> None:
        for s in list(self._running.get(sandbox_id, ())):
            _kill_session(s, signal.SIGSTOP)
        self._set_state(sandbox_id, "paused")

    def resume(self, sandbox_id: str) -> None:
        for s in list(self._running.get(sandbox_id, ())):
            _kill_session(s, signal.SIGCONT)
        self._set_state(sandbox_id, "running")

    def destroy(self, sandbox_id: str, *, delete_workspace: bool) -> None:
        self.kill_processes(sandbox_id)
        d = self._dir(sandbox_id)
        if delete_workspace:
            shutil.rmtree(d, ignore_errors=True)
        elif d.exists():
            for sub in ("home", "tmp"):
                shutil.rmtree(d / sub, ignore_errors=True)
            self._set_state(sandbox_id, "stopped")

    def status(self, sandbox_id: str) -> str:
        try:
            return self._meta(sandbox_id)["state"]
        except RuntimeError_:
            return "missing"

    def logs(self, sandbox_id: str, tail: int = 200) -> str:
        try:
            lines = (self._dir(sandbox_id) / "exec.log").read_text().splitlines()
        except OSError:
            return ""
        return "\n".join(lines[-max(1, min(tail, 5000)):])

    def health(self) -> dict:
        ok, detail = self.ready()
        layers = {"bubblewrap_namespaces": self.mode == "bwrap", "landlock_abi": self.landlock_abi,
                  "landlock_tcp": self.landlock_abi >= 4, "seccomp": self.seccomp, "rlimits": True,
                  "clean_env": True, "controller_non_dumpable": True}
        return {"runtime": "process", "ok": ok, "detail": detail, "mode": self.mode, "layers": layers}

    def kill_processes(self, sandbox_id: str) -> None:
        with self._lock:
            sessions = list(self._running.get(sandbox_id, ()))
        for s in sessions:
            _kill_session(s)

    # ---- execution ----------------------------------------------------------------------------
    def _command(self, sid: str, argv: list[str], workdir: str, meta: dict, timeout_s: int) -> tuple[list[str], dict]:
        d = self._dir(sid)
        cfg = {"fsize_mb": max(1, meta["workspace_mb"]), "memory_mb": meta["memory_mb"],
               "cpu_seconds": max(2, int(timeout_s * max(1.0, meta.get("cpu", 1.0))) + 5),
               "protect_pids": sorted({os.getpid(), 1}), "nofile": 1024}
        env = {"PATH": SAFE_PATH, "LANG": "C.UTF-8", "PYTHONUNBUFFERED": "1", "CSB_SANDBOX_ID": sid}
        for k, v in meta.get("env", {}).items():
            env[k] = self._rewrite(sid, v)
        if self.mode == "bwrap":
            env.update({"HOME": HOME_IN, "TMPDIR": TMP_IN})
            cfg["cwd"] = workdir
            cmd = [shutil.which(self.bwrap_bin) or self.bwrap_bin, "--unshare-all", "--die-with-parent",
                   "--new-session", "--hostname", "sandbox",
                   "--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc"]
            for link in ("bin", "sbin", "lib", "lib64"):
                target = os.path.realpath(f"/{link}")
                if os.path.islink(f"/{link}"):
                    cmd += ["--symlink", target.lstrip("/") if target.startswith("/usr") else target, f"/{link}"]
                elif os.path.isdir(f"/{link}"):
                    cmd += ["--ro-bind", f"/{link}", f"/{link}"]
            if os.path.isdir("/opt"):
                cmd += ["--ro-bind", "/opt", "/opt"]
            cmd += ["--proc", "/proc", "--dev", "/dev",
                    "--bind", str(d / "workspace"), WORKSPACE, "--bind", str(d / "home"), HOME_IN,
                    "--bind", str(d / "tmp"), TMP_IN,
                    "--ro-bind", str(LAUNCHER), "/.csb/launch.py", "--chdir", workdir, "--"]
            # inside its own PID namespace the sandbox cannot see the controller: no pids to protect
            cfg["protect_pids"] = []
            cmd += [PYTHON, "-I", "-S", "/.csb/launch.py", json.dumps(cfg), "--", *argv]
            return cmd, env
        # landlock mode (or weak mode): host paths
        host_wd = self._host(sid, workdir)
        env.update({"HOME": str(d / "home"), "TMPDIR": str(d / "tmp"), "CSB_WORKSPACE": str(d / "workspace")})
        cfg["cwd"] = host_wd
        cfg["nproc"] = _user_tasks() + max(8, meta["pids"])
        if self.mode == "landlock":
            cfg["landlock"] = {"read": SYSTEM_READ + [str(LAUNCHER), sys.base_prefix, os.path.dirname(PYTHON)],
                               "rw": [str(d / "workspace"), str(d / "home"), str(d / "tmp")],
                               "dev": DEVICES, "block_tcp": True}
        cmd = [PYTHON, "-I", "-S", str(LAUNCHER), json.dumps(cfg), "--",
               *[self._rewrite(sid, a) for a in argv]]
        return cmd, env

    def execute(self, sandbox_id, argv, *, workdir, env, timeout_s, max_output_bytes, stdin=None) -> ExecResult:
        meta = self._meta(sandbox_id)
        if meta["state"] != "running":
            raise RuntimeError_(f"sandbox is {meta['state']}, not running")
        if not argv:
            raise RuntimeError_("argv must not be empty")
        meta = {**meta, "env": {**meta.get("env", {}), **env}}
        cmd, run_env = self._command(sandbox_id, list(argv), safe_workdir(workdir), meta, timeout_s)
        t0 = time.monotonic()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=run_env,
                                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                start_new_session=True, cwd=str(self._dir(sandbox_id)), close_fds=True)
        session = proc.pid
        with self._lock:
            self._running.setdefault(sandbox_id, set()).add(session)
        if stdin is not None:
            def feed():
                try:
                    proc.stdin.write(stdin)
                except (BrokenPipeError, OSError):
                    pass
                finally:
                    try:
                        proc.stdin.close()
                    except OSError:
                        pass
            threading.Thread(target=feed, daemon=True).start()
        bufs = {"out": bytearray(), "err": bytearray()}
        over = {"out": False, "err": False}

        def drain(stream, key):
            for chunk in iter(lambda: stream.read(8192), b""):
                room = max_output_bytes - len(bufs[key])
                if room > 0:
                    bufs[key] += chunk[:room]
                if len(chunk) > room:
                    over[key] = True

        threads = [threading.Thread(target=drain, args=(proc.stdout, "out"), daemon=True),
                   threading.Thread(target=drain, args=(proc.stderr, "err"), daemon=True)]
        for t in threads:
            t.start()
        timed_out = False
        try:
            proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
        # the command is over: nothing of it may keep running (background processes included)
        _kill_session(session)
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        for t in threads:
            t.join(timeout=5)
        with self._lock:
            self._running.get(sandbox_id, set()).discard(session)
        rc = proc.returncode
        if timed_out:
            rc = 124
        elif rc is not None and rc < 0:
            rc = 128 - rc  # killed by a signal, shell style (e.g. 137 for SIGKILL)
        result = ExecResult(exit_code=rc, stdout=bufs["out"].decode("utf-8", "replace"),
                            stderr=bufs["err"].decode("utf-8", "replace"), timed_out=timed_out,
                            truncated=over["out"] or over["err"], duration_s=round(time.monotonic() - t0, 3))
        try:
            with open(self._dir(sandbox_id) / "exec.log", "a") as f:
                f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} exit={rc} "
                        f"timed_out={timed_out} {result.duration_s}s argv0={argv[0]!r}\n")
        except OSError:
            pass
        return result

    # ---- operations that the base class does with fixed /workspace paths ----------------------
    def workspace_usage_bytes(self, sid: str) -> int:
        total = 0
        for p in (self._dir(sid) / "workspace").rglob("*"):
            try:
                if p.is_file() and not p.is_symlink():
                    total += p.stat().st_size
            except OSError:
                continue
        return total

    def export_workspace(self, sid: str, *, max_bytes: int) -> bytes:
        if self.mode == "bwrap":
            return super().export_workspace(sid, max_bytes=max_bytes)
        r = self._sh(sid, '{ tar -c -C "$1" . || echo "CSB_TAR_FAILED" >&2; } | base64 -w0',
                     str(self._dir(sid) / "workspace"), timeout_s=600, max_output_bytes=max_bytes * 4 // 3 + 1024)
        if r.exit_code != 0 or r.truncated or "CSB_TAR_FAILED" in r.stderr:
            raise RuntimeError_("snapshot failed: " + ("workspace larger than the snapshot limit" if r.truncated
                                                        else r.stderr.strip()[:200]))
        import base64
        return base64.b64decode(r.stdout)

    def import_workspace(self, sid: str, tar: bytes, *, clear: bool) -> None:
        if self.mode == "bwrap":
            return super().import_workspace(sid, tar, clear=clear)
        ws = str(self._dir(sid) / "workspace")
        script = ('find "$1" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + ; ' if clear else '') + \
            'tar -x --no-same-owner --no-same-permissions -C "$1"'
        r = self._sh(sid, script, ws, stdin=tar, timeout_s=600)
        if r.exit_code != 0:
            raise RuntimeError_(f"restore failed: {r.stderr.strip()[:200]}")

    def stats(self, sid: str) -> dict | None:
        pids = [p for s in self._running.get(sid, ()) for p in _session_pids(s)]
        rss = 0
        for p in pids:
            try:
                rss += int(Path(f"/proc/{p}/statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE")
            except (OSError, ValueError, IndexError):
                continue
        return {"pids": len(pids), "memory": f"{rss / 2**20:.1f}MiB", "workspace_bytes": self.workspace_usage_bytes(sid)}
