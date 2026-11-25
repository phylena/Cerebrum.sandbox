"""Sandbox profiles. A profile can only *restrict*: there is no field for privileged mode,
host mounts, extra capabilities, or the Docker socket, so no profile can ask for them."""
import re
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .policy import NetworkMode, NetworkPolicy


class Isolation(StrEnum):
    PROCESS = "process"      # restricted process tree (Landlock/seccomp/namespaces): hosts without containers
    CONTAINER = "container"  # hardened runc container (default)
    GVISOR = "gvisor"        # runsc user-space kernel
    MICROVM = "microvm"      # Firecracker microVM (own kernel, KVM)


RANK = {Isolation.PROCESS: -1, Isolation.CONTAINER: 0, Isolation.GVISOR: 1, Isolation.MICROVM: 2}
RUNTIME_FOR = {Isolation.PROCESS: "process", Isolation.CONTAINER: "docker", Isolation.GVISOR: "gvisor",
               Isolation.MICROVM: "firecracker"}


_NAME = re.compile(r"^[a-z][a-z0-9-]{1,39}$")
_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid")  # unknown fields (e.g. privileged) are errors, not ignored

    name: str
    description: str = ""
    builtin: bool = False
    image: str = "cerebrum-sandbox/base:latest"
    isolation: Isolation = Isolation.CONTAINER
    cpu: float = Field(1.0, gt=0, le=64)
    memory_mb: int = Field(512, ge=64, le=1_048_576)
    pids: int = Field(128, ge=8, le=65536)
    workspace_mb: int = Field(512, ge=16, le=1_048_576)  # quota for /workspace
    tmp_mb: int = Field(64, ge=8, le=65536)
    persistent_workspace: bool = False
    default_timeout_s: int = Field(60, ge=1)
    max_timeout_s: int = Field(300, ge=1)
    network: NetworkPolicy = Field(default_factory=NetworkPolicy)
    gpus: int = Field(0, ge=0, le=16)
    # If set, only these executables may be run through the execute API (by basename).
    allowed_executables: list[str] | None = None
    env: dict[str, str] = Field(default_factory=dict)  # non-secret defaults only

    @field_validator("name")
    @classmethod
    def _name_ok(cls, v: str) -> str:
        if not _NAME.match(v):
            raise ValueError("profile name: lowercase letters, digits, dashes (2-40)")
        return v

    @field_validator("env")
    @classmethod
    def _env_ok(cls, v: dict[str, str]) -> dict[str, str]:
        for k in v:
            if not _ENV_KEY.match(k):
                raise ValueError(f"bad environment variable name '{k}'")
        return v

    def model_post_init(self, _ctx) -> None:
        if self.default_timeout_s > self.max_timeout_s:
            raise ValueError("default_timeout_s exceeds max_timeout_s")


def _p(**kw) -> Profile:
    return Profile(builtin=True, **kw)


_ALLOW_PKG = NetworkPolicy(mode=NetworkMode.ALLOWLIST,
                           allowed_domains=["pypi.org", "files.pythonhosted.org", "registry.npmjs.org"])

BUILTIN: dict[str, Profile] = {p.name: p for p in [
    _p(name="basic", description="Simple code execution: no network, small limits.",
       cpu=0.5, memory_mb=256, pids=64, workspace_mb=64, default_timeout_s=30, max_timeout_s=60),
    _p(name="development", description="Coding agents: git, shell, languages, package registries only.",
       cpu=1.0, memory_mb=1024, pids=256, workspace_mb=2048, persistent_workspace=True,
       default_timeout_s=120, max_timeout_s=600, network=_ALLOW_PKG),
    _p(name="research", description="Experiments and data analysis; no network by default.",
       image="cerebrum-sandbox/research:latest", cpu=2.0, memory_mb=4096, pids=512,
       workspace_mb=8192, persistent_workspace=True, default_timeout_s=300, max_timeout_s=3600),
    _p(name="training", description="Training jobs. GPU needs a GPU worker (not implemented yet).",
       image="cerebrum-sandbox/training:latest", cpu=2.0, memory_mb=8192, pids=1024,
       workspace_mb=51200, persistent_workspace=True, gpus=1, default_timeout_s=3600, max_timeout_s=43200),
    _p(name="browser", description="Isolated browser automation (Playwright image).",
       image="cerebrum-sandbox/browser:latest", cpu=1.0, memory_mb=2048, pids=512, workspace_mb=512,
       default_timeout_s=120, max_timeout_s=600),
    _p(name="mcp", description="Isolated MCP servers; no network unless a custom profile grants it.",
       image="cerebrum-sandbox/mcp:latest", cpu=0.5, memory_mb=512, pids=128, workspace_mb=256,
       default_timeout_s=60, max_timeout_s=300),
]}


def clamp_check(profile: Profile, *, max_cpu: float, max_memory_mb: int, max_timeout: int) -> None:
    """Refuse profiles that exceed the platform's hard ceilings."""
    if profile.cpu > max_cpu:
        raise ValueError(f"cpu {profile.cpu} exceeds the platform maximum {max_cpu}")
    if profile.memory_mb > max_memory_mb:
        raise ValueError(f"memory_mb {profile.memory_mb} exceeds the platform maximum {max_memory_mb}")
    if profile.max_timeout_s > max_timeout:
        raise ValueError(f"max_timeout_s {profile.max_timeout_s} exceeds the platform maximum {max_timeout}")
