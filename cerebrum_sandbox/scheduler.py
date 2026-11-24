"""Placement: which worker (local or remote) runs a new sandbox, and which GPUs it gets.

Pure function over the current sandbox list so it is easy to test. Never exceeds a worker's
CPU / memory / sandbox / GPU capacity and never exceeds the platform-wide GPU-sandbox cap.
GPUs are assigned exclusively (one sandbox per device) by index.
"""
from dataclasses import dataclass

from .profiles import Profile


class PlacementError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


@dataclass
class Capacity:
    name: str
    cpu: float
    memory_mb: int
    sandboxes: int
    gpus: list[int]  # device indices (remote workers: 0..n-1, only used for counting)


def place(profile: Profile, options: list[Capacity], active: list[dict], *, max_gpu_sandboxes: int,
          pin: str | None = None) -> tuple[str, list[int]]:
    if pin:
        options = [o for o in options if o.name == pin]
        if not options:
            raise PlacementError(422, f"worker '{pin}' is not available for this isolation level")
    if not options:
        raise PlacementError(503, "no worker offers the required runtime")
    if profile.gpus and sum(1 for s in active if s["profile_snapshot"].get("gpus")) >= max_gpu_sandboxes:
        raise PlacementError(429, f"GPU sandbox limit reached ({max_gpu_sandboxes})")
    best, reasons = None, []
    for o in options:
        mine = [s for s in active if s["worker"] == o.name]
        cpu = sum(s["profile_snapshot"]["cpu"] for s in mine)
        mem = sum(s["profile_snapshot"]["memory_mb"] for s in mine)
        if len(mine) >= o.sandboxes:
            reasons.append(f"{o.name}: sandbox limit ({o.sandboxes}) reached"); continue
        if cpu + profile.cpu > o.cpu:
            reasons.append(f"{o.name}: CPU quota would be exceeded"); continue
        if mem + profile.memory_mb > o.memory_mb:
            reasons.append(f"{o.name}: memory quota would be exceeded"); continue
        gpus: list[int] = []
        if profile.gpus:
            used = {i for s in mine for i in s["gpu_indices"]}
            free = [i for i in o.gpus if i not in used]
            if len(free) < profile.gpus:
                reasons.append(f"{o.name}: needs {profile.gpus} free GPU(s), has {len(free)}"); continue
            gpus = free[:profile.gpus]
        score = ((cpu + profile.cpu) / o.cpu if o.cpu else 1.0, o.name != "local", o.name)
        if best is None or score < best[0]:
            best = (score, o.name, gpus)
    if best is None:
        raise PlacementError(429, "No worker has capacity: " + "; ".join(reasons))
    return best[1], best[2]
