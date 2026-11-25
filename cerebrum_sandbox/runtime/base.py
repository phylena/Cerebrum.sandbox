"""The runtime interface every adapter implements. Controller code only sees this."""
from abc import ABC, abstractmethod
import re
from dataclasses import dataclass, field

from ..profiles import Profile


class RuntimeError_(Exception):
    """A runtime could not do what was asked (message is safe to show to API callers)."""


@dataclass
class SandboxSpec:
    sandbox_id: str
    profile: Profile
    env: dict[str, str] = field(default_factory=dict)
    gpu_indices: list[int] = field(default_factory=list)  # assigned by the scheduler


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False
    duration_s: float = 0.0


class Runtime(ABC):
    name: str

    @abstractmethod
    def create(self, spec: SandboxSpec) -> None: ...
    @abstractmethod
    def start(self, sandbox_id: str) -> None: ...
    @abstractmethod
    def stop(self, sandbox_id: str) -> None: ...
    @abstractmethod
    def pause(self, sandbox_id: str) -> None: ...
    @abstractmethod
    def resume(self, sandbox_id: str) -> None: ...
    @abstractmethod
    def destroy(self, sandbox_id: str, *, delete_workspace: bool) -> None: ...
    @abstractmethod
    def execute(self, sandbox_id: str, argv: list[str], *, workdir: str, env: dict[str, str],
                timeout_s: int, max_output_bytes: int, stdin: bytes | None = None) -> ExecResult: ...
    @abstractmethod
    def status(self, sandbox_id: str) -> str:
        """One of: running, paused, stopped, missing."""
    @abstractmethod
    def logs(self, sandbox_id: str, tail: int = 200) -> str: ...
    @abstractmethod
    def health(self) -> dict: ...

    # ---- generic operations built on execute(): every runtime gets them for free -------------
    # They only use POSIX sh + coreutils (base64, stat, find, du, kill) inside the sandbox.
    def _sh(self, sid: str, script: str, *args: str, stdin: bytes | None = None, timeout_s: int = 60,
            max_output_bytes: int = 1 << 20) -> ExecResult:
        return self.execute(sid, ["sh", "-c", script, "sh", *args], workdir=WORKSPACE, env={},
                            timeout_s=timeout_s, max_output_bytes=max_output_bytes, stdin=stdin)

    def write_file(self, sid: str, path: str, data: bytes, *, mode: str = "644") -> None:
        import base64
        path = safe_path(path)
        if not re.fullmatch(r"[0-7]{3}", mode):
            raise RuntimeError_("mode must be three octal digits")
        r = self._sh(sid, 'mkdir -p -- "$(dirname -- "$1")" && base64 -d > "$1" && chmod "$2" -- "$1"',
                     path, mode, stdin=base64.b64encode(data), timeout_s=120)
        if r.exit_code != 0:
            raise RuntimeError_(f"write failed: {r.stderr.strip()[:200]}")

    def read_file(self, sid: str, path: str, *, max_bytes: int) -> bytes:
        import base64
        path = safe_path(path)
        r = self._sh(sid, 'test -f "$1" || { echo "not a regular file" >&2; exit 2; }; '
                          's=$(stat -c %s -- "$1"); if [ "$s" -gt "$2" ]; then echo "too large: $s bytes" >&2; exit 3; fi; '
                          'base64 -w0 -- "$1"', path, str(max_bytes), timeout_s=120,
                     max_output_bytes=max_bytes * 4 // 3 + 1024)
        if r.exit_code != 0:
            raise RuntimeError_(f"read failed: {r.stderr.strip()[:200]}")
        return base64.b64decode(r.stdout)

    def list_dir(self, sid: str, path: str, *, limit: int = 1000) -> list[dict]:
        path = safe_path(path)
        r = self._sh(sid, 'test -d "$1" || { echo "not a directory" >&2; exit 2; }; '
                          'find "$1" -mindepth 1 -maxdepth 1 -printf "%y\t%s\t%T@\t%f\n" | head -n "$2"',
                     path, str(limit))
        if r.exit_code != 0:
            raise RuntimeError_(f"list failed: {r.stderr.strip()[:200]}")
        kinds = {"f": "file", "d": "dir", "l": "symlink"}
        out = []
        for line in r.stdout.splitlines():
            t, size, mtime, name = line.split("\t", 3)
            out.append({"name": name, "type": kinds.get(t, "other"), "size": int(size), "mtime": float(mtime)})
        return sorted(out, key=lambda e: (e["type"] != "dir", e["name"]))

    def delete_path(self, sid: str, path: str) -> None:
        path = safe_path(path)
        if path == WORKSPACE:
            raise RuntimeError_("refusing to delete the workspace root")
        r = self._sh(sid, 'rm -rf -- "$1"', path)
        if r.exit_code != 0:
            raise RuntimeError_(f"delete failed: {r.stderr.strip()[:200]}")

    def workspace_usage_bytes(self, sid: str) -> int:
        r = self._sh(sid, 'du -sk /workspace | cut -f1')
        if r.exit_code != 0:
            raise RuntimeError_(f"usage failed: {r.stderr.strip()[:200]}")
        return int(r.stdout.strip() or 0) * 1024

    def stats(self, sid: str) -> dict | None:
        """Live resource usage (None if the runtime cannot report it)."""
        return None

    def address(self, sid: str, network: str) -> str | None:
        """IP of the sandbox on a named network (None if not applicable)."""
        return None

    def export_workspace(self, sid: str, *, max_bytes: int) -> bytes:
        """tar of /workspace (taken inside the sandbox; the host never extracts it)."""
        import base64
        r = self._sh(sid, '{ tar -c -C /workspace . || echo "CSB_TAR_FAILED" >&2; } | base64 -w0', timeout_s=600,
                     max_output_bytes=max_bytes * 4 // 3 + 1024)
        if r.exit_code != 0 or r.truncated or "CSB_TAR_FAILED" in r.stderr:
            raise RuntimeError_("snapshot failed: " + ("workspace larger than the snapshot limit" if r.truncated
                                                        else r.stderr.strip()[:200]))
        return base64.b64decode(r.stdout)

    def import_workspace(self, sid: str, tar: bytes, *, clear: bool) -> None:
        script = ('find /workspace -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + ; ' if clear else '') + \
            'tar -x --no-same-owner --no-same-permissions -C /workspace'
        r = self._sh(sid, script, stdin=tar, timeout_s=600)
        if r.exit_code != 0:
            raise RuntimeError_(f"restore failed: {r.stderr.strip()[:200]}")

    def kill_processes(self, sid: str) -> None:
        """Kill every process of the sandbox user (left-over/background/setsid'd processes).
        The sandbox keeps running: its keeper process runs as a different user."""
        self._sh(sid, "kill -9 -1 2>/dev/null; exit 0", timeout_s=15)


WORKSPACE = "/workspace"


def safe_workdir(path: str | None) -> str:
    """Resolve a working directory; it must stay inside /workspace (no '..' escapes)."""
    import posixpath
    if not path:
        return WORKSPACE
    joined = path if path.startswith("/") else posixpath.join(WORKSPACE, path)
    norm = posixpath.normpath(joined)
    if norm != WORKSPACE and not norm.startswith(WORKSPACE + "/"):
        raise RuntimeError_(f"working directory must be inside {WORKSPACE}")
    return norm


def safe_path(path: str) -> str:
    """A file path that must be inside /workspace (relative paths are relative to it)."""
    if not path or "\x00" in path:
        raise RuntimeError_("path required")
    return safe_workdir(path)
