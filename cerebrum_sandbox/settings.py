"""All settings, read from environment variables (SANDBOX_*). Call `load()` to rebuild."""
import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _int(name: str, default: int) -> int:
    return int(_env(name, str(default)) or default)


def _float(name: str, default: float) -> float:
    return float(_env(name, str(default)) or default)


def _list(name: str, default: str = "") -> list[str]:
    return [x.strip() for x in _env(name, default).split(",") if x.strip()]


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(_env("SANDBOX_DATA_DIR", "./data")))
    # One key per role. No key at all = the API refuses every request (fail closed).
    admin_key: str = field(default_factory=lambda: _env("SANDBOX_ADMIN_KEY"))
    operator_key: str = field(default_factory=lambda: _env("SANDBOX_OPERATOR_KEY"))  # Cerebrum uses this
    viewer_key: str = field(default_factory=lambda: _env("SANDBOX_VIEWER_KEY"))

    runtime: str = field(default_factory=lambda: _env("SANDBOX_RUNTIME", "docker"))
    docker_bin: str = field(default_factory=lambda: _env("SANDBOX_DOCKER_BIN", "docker"))
    gvisor_runtime: str = field(default_factory=lambda: _env("SANDBOX_GVISOR_RUNTIME", "runsc"))
    # Docker network that only reaches the egress proxy (needed for allowlist profiles; empty = refuse them)
    egress_network: str = field(default_factory=lambda: _env("SANDBOX_EGRESS_NETWORK"))
    egress_proxy_url: str = field(default_factory=lambda: _env("SANDBOX_EGRESS_PROXY_URL"))
    allowed_image_prefixes: list[str] = field(
        default_factory=lambda: _list("SANDBOX_ALLOWED_IMAGE_PREFIXES", "cerebrum-sandbox/"))

    # Hard ceilings: profiles and requests are clamped/refused above these.
    max_sandboxes: int = field(default_factory=lambda: _int("SANDBOX_MAX_SANDBOXES", 8))
    max_total_cpu: float = field(default_factory=lambda: _float("SANDBOX_MAX_TOTAL_CPU", 3.0))
    max_total_memory_mb: int = field(default_factory=lambda: _int("SANDBOX_MAX_TOTAL_MEMORY_MB", 12288))
    max_sandbox_cpu: float = field(default_factory=lambda: _float("SANDBOX_MAX_SANDBOX_CPU", 2.0))
    max_sandbox_memory_mb: int = field(default_factory=lambda: _int("SANDBOX_MAX_SANDBOX_MEMORY_MB", 4096))
    max_exec_seconds: int = field(default_factory=lambda: _int("SANDBOX_MAX_EXEC_SECONDS", 600))
    max_output_bytes: int = field(default_factory=lambda: _int("SANDBOX_MAX_OUTPUT_BYTES", 262144))
    audit_retention_days: int = field(default_factory=lambda: _int("SANDBOX_AUDIT_RETENTION_DAYS", 90))


def load() -> Settings:
    return Settings()
