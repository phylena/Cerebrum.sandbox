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

    # Which local runtimes this node offers: docker, gvisor, firecracker (comma separated).
    runtimes: list[str] = field(default_factory=lambda: _list("SANDBOX_RUNTIMES", "docker"))
    # Weakest isolation allowed on this node; weaker profiles are upgraded to this (e.g. "gvisor").
    min_isolation: str = field(default_factory=lambda: _env("SANDBOX_MIN_ISOLATION", "container"))
    docker_bin: str = field(default_factory=lambda: _env("SANDBOX_DOCKER_BIN", "docker"))
    gvisor_runtime: str = field(default_factory=lambda: _env("SANDBOX_GVISOR_RUNTIME", "runsc"))
    # Docker network that only reaches the egress proxy (needed for allowlist profiles; empty = refuse them)
    egress_network: str = field(default_factory=lambda: _env("SANDBOX_EGRESS_NETWORK"))
    egress_proxy_url: str = field(default_factory=lambda: _env("SANDBOX_EGRESS_PROXY_URL"))
    # Built-in egress proxy: 1 = create the internal network + run the proxy, and fill
    # egress_network / egress_proxy_url automatically.
    egress_enabled: bool = field(default_factory=lambda: _env("SANDBOX_EGRESS_ENABLED", "0") in ("1", "true", "yes"))
    egress_network_name: str = field(default_factory=lambda: _env("SANDBOX_EGRESS_NETWORK_NAME", "csb-egress"))
    egress_subnet: str = field(default_factory=lambda: _env("SANDBOX_EGRESS_SUBNET", "172.30.0.0/24"))
    egress_port: int = field(default_factory=lambda: _int("SANDBOX_EGRESS_PORT", 3128))
    egress_upstream_proxy: str = field(default_factory=lambda: _env("SANDBOX_EGRESS_UPSTREAM_PROXY"))
    netlog_retention_days: int = field(default_factory=lambda: _int("SANDBOX_NETLOG_RETENTION_DAYS", 30))
    allowed_image_prefixes: list[str] = field(
        default_factory=lambda: _list("SANDBOX_ALLOWED_IMAGE_PREFIXES", "cerebrum-sandbox/"))

    # Firecracker (microVM) runtime. Needs /dev/kvm, a kernel and a rootfs built by images/firecracker/.
    fc_bin: str = field(default_factory=lambda: _env("SANDBOX_FC_BIN", "firecracker"))
    fc_kernel: str = field(default_factory=lambda: _env("SANDBOX_FC_KERNEL"))
    fc_rootfs: str = field(default_factory=lambda: _env("SANDBOX_FC_ROOTFS"))
    fc_dir: str = field(default_factory=lambda: _env("SANDBOX_FC_DIR", "/var/lib/cerebrum-sandbox/fc"))
    fc_boot_args: str = field(default_factory=lambda: _env(
        "SANDBOX_FC_BOOT_ARGS", "console=ttyS0 reboot=k panic=1 pci=off init=/sbin/csb-init"))
    fc_agent_port: int = field(default_factory=lambda: _int("SANDBOX_FC_AGENT_PORT", 5252))
    fc_boot_timeout_s: int = field(default_factory=lambda: _int("SANDBOX_FC_BOOT_TIMEOUT_S", 30))
    # GPUs: restrict which host GPU indices sandboxes may use (empty = all detected), and cap GPU sandboxes.
    gpu_indices: list[int] = field(default_factory=lambda: [int(x) for x in _list("SANDBOX_GPU_INDICES")])
    max_gpu_sandboxes: int = field(default_factory=lambda: _int("SANDBOX_MAX_GPU_SANDBOXES", 2))
    # Worker fleet (other nodes running this same service)
    max_workers: int = field(default_factory=lambda: _int("SANDBOX_MAX_WORKERS", 16))
    worker_timeout_s: int = field(default_factory=lambda: _int("SANDBOX_WORKER_TIMEOUT_S", 30))

    # Credential broker: Fernet key (python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())").
    # Empty = the broker is disabled (no credential can be stored).
    secret_key: str = field(default_factory=lambda: _env("SANDBOX_SECRET_KEY"))
    github_api_url: str = field(default_factory=lambda: _env("SANDBOX_GITHUB_API_URL", "https://api.github.com"))
    # Git: clone only https URLs on these hosts (and, if set, only these owner/ or owner/repo prefixes)
    git_allowed_hosts: list[str] = field(default_factory=lambda: _list("SANDBOX_GIT_ALLOWED_HOSTS", "github.com"))
    git_allowed_repos: list[str] = field(default_factory=lambda: _list("SANDBOX_GIT_ALLOWED_REPOS"))
    git_max_bytes: int = field(default_factory=lambda: _int("SANDBOX_GIT_MAX_BYTES", 500 * 2**20))
    git_timeout_s: int = field(default_factory=lambda: _int("SANDBOX_GIT_TIMEOUT_S", 300))

    # Jobs (one-shot sandboxes run by the scheduler)
    max_concurrent_jobs: int = field(default_factory=lambda: _int("SANDBOX_MAX_CONCURRENT_JOBS", 2))
    max_queued_jobs: int = field(default_factory=lambda: _int("SANDBOX_MAX_QUEUED_JOBS", 200))
    job_hours_budget_daily: float = field(default_factory=lambda: _float("SANDBOX_JOB_HOURS_BUDGET_DAILY", 24.0))
    job_retry_backoff_s: int = field(default_factory=lambda: _int("SANDBOX_JOB_RETRY_BACKOFF_S", 10))
    # Maintenance loop and alerting
    maintenance_interval_s: int = field(default_factory=lambda: _int("SANDBOX_MAINTENANCE_INTERVAL_S", 60))
    backup_keep: int = field(default_factory=lambda: _int("SANDBOX_BACKUP_KEEP", 14))
    alert_webhook: str = field(default_factory=lambda: _env("SANDBOX_ALERT_WEBHOOK"))

    # Hard ceilings: profiles and requests are clamped/refused above these.
    max_sandboxes: int = field(default_factory=lambda: _int("SANDBOX_MAX_SANDBOXES", 8))
    max_total_cpu: float = field(default_factory=lambda: _float("SANDBOX_MAX_TOTAL_CPU", 3.0))
    max_total_memory_mb: int = field(default_factory=lambda: _int("SANDBOX_MAX_TOTAL_MEMORY_MB", 12288))
    max_sandbox_cpu: float = field(default_factory=lambda: _float("SANDBOX_MAX_SANDBOX_CPU", 2.0))
    max_sandbox_memory_mb: int = field(default_factory=lambda: _int("SANDBOX_MAX_SANDBOX_MEMORY_MB", 4096))
    max_exec_seconds: int = field(default_factory=lambda: _int("SANDBOX_MAX_EXEC_SECONDS", 600))
    max_file_bytes: int = field(default_factory=lambda: _int("SANDBOX_MAX_FILE_BYTES", 50 * 2**20))
    max_output_bytes: int = field(default_factory=lambda: _int("SANDBOX_MAX_OUTPUT_BYTES", 262144))
    audit_retention_days: int = field(default_factory=lambda: _int("SANDBOX_AUDIT_RETENTION_DAYS", 90))


def load() -> Settings:
    return Settings()
