"""Runtime registry: the single place that knows which adapters exist. Adding a runtime =
one class implementing `Runtime` + one line here + its isolation level in profiles.RUNTIME_FOR.
No API change is needed because clients choose isolation, never a runtime class."""
from ..settings import Settings
from .base import Runtime
from .docker import DockerRuntime
from .firecracker import FirecrackerRuntime
from .gvisor import GVisorRuntime
from .process import ProcessRuntime

FACTORIES = {"docker": DockerRuntime, "gvisor": GVisorRuntime, "firecracker": FirecrackerRuntime,
             "process": ProcessRuntime}


def build_runtimes(st: Settings) -> dict[str, Runtime]:
    out: dict[str, Runtime] = {}
    for name in st.runtimes:
        if name not in FACTORIES:
            raise ValueError(f"unknown runtime '{name}' in SANDBOX_RUNTIMES (known: {sorted(FACTORIES)})")
        out[name] = FACTORIES[name](st)
    return out
