"""The runtime interface every adapter implements. Controller code only sees this."""
from abc import ABC, abstractmethod
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
                timeout_s: int, max_output_bytes: int) -> ExecResult: ...
    @abstractmethod
    def status(self, sandbox_id: str) -> str:
        """One of: running, paused, stopped, missing."""
    @abstractmethod
    def logs(self, sandbox_id: str, tail: int = 200) -> str: ...
    @abstractmethod
    def health(self) -> dict: ...
    # File and metrics operations arrive with the workspace (phase 6) and monitoring (phase 10) work.


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
