"""gVisor adapter: the same hardened Docker container, run by `runsc` (a user-space kernel)
so sandbox syscalls never reach the host kernel directly. It subclasses the Docker adapter,
so every hardening flag still applies; the only difference is `--runtime runsc`.

Refuses to create anything unless the daemon really has the runtime registered (it will not
fall back to runc). STATUS: runtime detection is unit-tested; running real workloads under
runsc is unverified in the build environment (no Docker daemon, no runsc).
"""
import json

from ..profiles import Isolation
from ..settings import Settings
from .base import RuntimeError_, SandboxSpec
from .docker import DockerRuntime, Runner


class GVisorRuntime(DockerRuntime):
    name = "gvisor"
    isolation = Isolation.GVISOR

    def __init__(self, st: Settings, runner: Runner | None = None):
        super().__init__(st, runner)

    def _runsc_registered(self) -> tuple[bool, str]:
        try:
            rc, out, err = self._runner([self.st.docker_bin, "info", "--format", "{{json .Runtimes}}"], 15)
        except RuntimeError_ as e:
            return False, str(e)
        if rc != 0:
            return False, err.strip()[:200]
        try:
            runtimes = json.loads(out.strip() or "{}")
        except json.JSONDecodeError:
            return False, "could not parse `docker info` runtimes"
        if self.st.gvisor_runtime not in runtimes:
            return False, f"runtime '{self.st.gvisor_runtime}' is not registered with Docker"
        return True, f"runtime '{self.st.gvisor_runtime}' registered"

    def create(self, spec: SandboxSpec) -> None:
        ok, detail = self._runsc_registered()
        if not ok:
            raise RuntimeError_(f"gVisor unavailable: {detail}")
        super().create(spec)

    def health(self) -> dict:
        base = super().health()
        ok, detail = self._runsc_registered()
        return {"runtime": "gvisor", "ok": bool(base.get("ok")) and ok, "detail": detail}
