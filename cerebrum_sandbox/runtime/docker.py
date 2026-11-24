"""Docker adapter. Talks to the daemon only through the `docker` CLI run by the controller;
the Docker socket is never mounted into a sandbox.

Hardening applied to every container (see `build_create_args`): non-root user, read-only root
filesystem, all capabilities dropped, no-new-privileges, pids/memory/cpu limits, no swap,
tmpfs /tmp, no host mounts, `--network none` unless an allowlist profile and an egress
network are both configured. gVisor (`runsc`) is used when the profile asks for it.

STATUS: command construction is unit-tested. Behaviour against a live daemon is covered by
tests marked `docker` and has NOT been verified in the build environment (no daemon).
"""
import re
import subprocess
import threading
import time
from typing import Callable

from ..policy import NetworkMode
from ..profiles import Isolation
from ..settings import Settings
from .base import ExecResult, Runtime, RuntimeError_, SandboxSpec, WORKSPACE, safe_workdir

UID = "10001:10001"
_ID = re.compile(r"^[a-f0-9]{12}$")
_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}(:[A-Za-z0-9._-]{1,64})?$")

Runner = Callable[[list[str], int | None], tuple[int, str, str]]


def container_name(sandbox_id: str) -> str:
    if not _ID.match(sandbox_id):
        raise RuntimeError_("invalid sandbox id")
    return f"csb-{sandbox_id}"


def build_create_args(spec: SandboxSpec, st: Settings) -> list[str]:
    p = spec.profile
    if not _IMAGE.match(p.image) or not any(p.image.startswith(x) for x in st.allowed_image_prefixes):
        raise RuntimeError_(f"image '{p.image}' is not allowed (allowed prefixes: {st.allowed_image_prefixes})")
    if p.gpus:
        if p.isolation != Isolation.CONTAINER:
            raise RuntimeError_("GPU sandboxes are only supported with container isolation "
                                "(gVisor GPU passthrough and microVM GPUs are not supported)")
        if len(spec.gpu_indices) != p.gpus or len(set(spec.gpu_indices)) != p.gpus:
            raise RuntimeError_(f"GPU sandboxes need {p.gpus} distinct GPU indices assigned by the scheduler")
    name = container_name(spec.sandbox_id)
    mem = f"{p.memory_mb}m"
    args = [
        "create", "--name", name,
        "--label", "cerebrum.sandbox=1", "--label", f"cerebrum.sandbox.id={spec.sandbox_id}",
        "--hostname", "sandbox", "--init",
        "--user", UID, "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", str(p.pids), "--memory", mem, "--memory-swap", mem,
        "--cpus", f"{p.cpu:g}", "--ulimit", "nofile=1024:1024", "--ulimit", "core=0",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={p.tmp_mb}m",
        "--tmpfs", f"/home/sandbox:rw,nosuid,nodev,uid=10001,gid=10001,mode=0700,size={p.tmp_mb}m",
        "--workdir", WORKSPACE,
    ]
    if p.persistent_workspace:  # named volume: survives the container; byte quota is enforced by the controller
        args += ["--mount", f"type=volume,source=csb-ws-{spec.sandbox_id},target={WORKSPACE}"]
    else:  # tmpfs: the kernel enforces the size limit, and it vanishes with the container
        args += ["--tmpfs", f"{WORKSPACE}:rw,nosuid,nodev,uid=10001,gid=10001,mode=0700,size={p.workspace_mb}m"]
    if p.isolation == Isolation.GVISOR:
        args += ["--runtime", st.gvisor_runtime]
    if p.gpus:  # exactly the assigned devices, never "all"; needs the NVIDIA container toolkit on the host
        args += ["--gpus", '"device=' + ",".join(str(int(i)) for i in spec.gpu_indices) + '"']
    env = {"HOME": "/home/sandbox", **p.env, **spec.env}
    if p.network.mode == NetworkMode.NONE:
        args += ["--network", "none"]
    else:
        if not st.egress_network or not st.egress_proxy_url:
            raise RuntimeError_("allowlist network needs SANDBOX_EGRESS_NETWORK and SANDBOX_EGRESS_PROXY_URL "
                                "(refusing to fall back to open networking)")
        args += ["--network", st.egress_network]
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            env[k] = st.egress_proxy_url
        env["NO_PROXY"] = env["no_proxy"] = "localhost,127.0.0.1"
    for k, v in sorted(env.items()):
        if not _ENV_KEY.match(k):
            raise RuntimeError_(f"bad environment variable name '{k}'")
        args += ["--env", f"{k}={v}"]
    args += [p.image, "sleep", "infinity"]
    return args


def _default_runner(args: list[str], timeout: int | None) -> tuple[int, str, str]:
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError_("docker command timed out") from e
    except FileNotFoundError as e:
        raise RuntimeError_(f"docker binary not found: {args[0]}") from e
    return r.returncode, r.stdout, r.stderr


class DockerRuntime(Runtime):
    name = "docker"
    isolation = Isolation.CONTAINER  # a runtime only accepts profiles of its own isolation level

    def __init__(self, st: Settings, runner: Runner | None = None):
        self.st = st
        self._runner = runner or _default_runner

    def _docker(self, *a: str, timeout: int | None = 60, check: bool = True) -> str:
        rc, out, err = self._runner([self.st.docker_bin, *a], timeout)
        if check and rc != 0:
            raise RuntimeError_(f"docker {a[0]} failed: {err.strip()[:300]}")
        return out

    def create(self, spec: SandboxSpec) -> None:
        if spec.profile.isolation != self.isolation:  # never silently run a profile at a weaker level
            raise RuntimeError_(f"runtime '{self.name}' only runs '{self.isolation}' sandboxes, "
                                f"not '{spec.profile.isolation}'")
        self._docker(*build_create_args(spec, self.st), timeout=120)

    def start(self, sandbox_id: str) -> None:
        self._docker("start", container_name(sandbox_id))

    def stop(self, sandbox_id: str) -> None:
        self._docker("stop", "-t", "5", container_name(sandbox_id))

    def pause(self, sandbox_id: str) -> None:
        self._docker("pause", container_name(sandbox_id))

    def resume(self, sandbox_id: str) -> None:
        self._docker("unpause", container_name(sandbox_id))

    def destroy(self, sandbox_id: str, *, delete_workspace: bool) -> None:
        self._docker("rm", "-f", "-v", container_name(sandbox_id), check=False)
        if delete_workspace:
            self._docker("volume", "rm", "-f", f"csb-ws-{sandbox_id}", check=False)

    def status(self, sandbox_id: str) -> str:
        rc, out, _ = self._runner([self.st.docker_bin, "inspect", "-f", "{{.State.Status}}",
                                   container_name(sandbox_id)], 30)
        if rc != 0:
            return "missing"
        return {"running": "running", "paused": "paused"}.get(out.strip(), "stopped")

    def logs(self, sandbox_id: str, tail: int = 200) -> str:
        rc, out, err = self._runner([self.st.docker_bin, "logs", "--tail", str(max(1, min(tail, 5000))),
                                     container_name(sandbox_id)], 30)
        return out + err

    def health(self) -> dict:
        try:
            rc, out, err = self._runner([self.st.docker_bin, "version", "--format", "{{.Server.Version}}"], 10)
        except RuntimeError_ as e:
            return {"runtime": "docker", "ok": False, "detail": str(e)}
        return {"runtime": "docker", "ok": rc == 0, "detail": out.strip() if rc == 0 else err.strip()[:200]}

    def execute(self, sandbox_id, argv, *, workdir, env, timeout_s, max_output_bytes) -> ExecResult:
        cmd = [self.st.docker_bin, "exec", "--user", UID, "--workdir", safe_workdir(workdir)]
        for k, v in sorted(env.items()):
            if not _ENV_KEY.match(k):
                raise RuntimeError_(f"bad environment variable name '{k}'")
            cmd += ["--env", f"{k}={v}"]
        # The in-container `timeout` kills runaway processes; the host-side limit is a backstop.
        cmd += [container_name(sandbox_id), "timeout", "-k", "2", str(timeout_s), *argv]
        t0 = time.monotonic()
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        bufs: dict[str, bytearray] = {"out": bytearray(), "err": bytearray()}
        over = {"out": False, "err": False}

        def drain(stream, key):  # bounded memory: keep the first max bytes, discard the rest
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
        host_timed_out = False
        try:
            proc.wait(timeout=timeout_s + 10)
        except subprocess.TimeoutExpired:
            host_timed_out = True
            proc.kill()
            proc.wait()
        for t in threads:
            t.join(timeout=5)
        rc = proc.returncode
        timed_out = host_timed_out or rc in (124, 137)  # timeout(1): 124 on TERM, 137 after -k KILL
        return ExecResult(exit_code=rc, stdout=bufs["out"].decode("utf-8", "replace"),
                          stderr=bufs["err"].decode("utf-8", "replace"), timed_out=timed_out,
                          truncated=over["out"] or over["err"], duration_s=round(time.monotonic() - t0, 3))
