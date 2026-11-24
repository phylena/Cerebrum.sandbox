"""Host resource discovery (CPU, memory, disk, GPUs). GPU is optional: absent = empty list."""
import os
import shutil
import subprocess
from pathlib import Path


def _meminfo() -> dict:
    out = {}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            k, v = line.split(":", 1)
            out[k] = int(v.split()[0]) // 1024
    except (OSError, ValueError):
        pass
    return {"total_mb": out.get("MemTotal"), "available_mb": out.get("MemAvailable")}


def detect_gpus() -> list[dict]:
    if not shutil.which("nvidia-smi"):
        return []
    try:
        r = subprocess.run(["nvidia-smi", "--query-gpu=index,name,memory.total,memory.used,utilization.gpu",
                            "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return []
    gpus = []
    for line in r.stdout.splitlines() if r.returncode == 0 else []:
        i, name, tot, used, util = [x.strip() for x in line.split(",")]
        gpus.append({"index": int(i), "name": name, "memory_total_mb": int(tot),
                     "memory_used_mb": int(used), "utilization_pct": int(util)})
    return gpus


def host_resources(data_dir: Path) -> dict:
    data_dir.mkdir(parents=True, exist_ok=True)
    du = shutil.disk_usage(data_dir)
    return {"cpu_count": os.cpu_count(), "load_avg": list(os.getloadavg()), "memory": _meminfo(),
            "disk": {"total_mb": du.total // 2**20, "free_mb": du.free // 2**20},
            "kvm": os.path.exists("/dev/kvm"), "gpus": detect_gpus()}
