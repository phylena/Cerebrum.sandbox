"""Firecracker microVM adapter (own implementation, no third-party SDK).

Per sandbox, under SANDBOX_FC_DIR/<id>/: a private copy of the guest rootfs (read-only drive),
a separate ext4 workspace disk whose file size is the quota, a Firecracker process driven over
its API unix socket, and a vsock channel to our guest agent (images/firecracker/csb_agent.py)
used for execution. Networking: NO network device is attached, so the guest has no network at
all; allowlist profiles and GPUs are refused (fail closed).

STATUS: the API-call sequence, vsock protocol, lifecycle and guest agent are unit/integration
tested against a fake Firecracker API and the real agent logic. Booting a real microVM needs
/dev/kvm, a guest kernel and the rootfs, none of which exist in the build environment, so
real-VM behaviour is UNVERIFIED. Not hardened with the Firecracker `jailer` yet: run the API
as a dedicated unprivileged user with /dev/kvm access and cgroup limits until that is added.
"""
import http.client
import json
import math
import re
import os
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

from ..policy import NetworkMode
from ..profiles import Isolation
from ..settings import Settings
from .base import ExecResult, Runtime, RuntimeError_, SandboxSpec, safe_workdir

_ID = re.compile(r"^[a-f0-9]{12}$")
_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 10):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def api_call(sock: str, method: str, path: str, body: dict | None = None, timeout: float = 10) -> tuple[int, str]:
    c = _UnixHTTP(sock, timeout)
    try:
        c.request(method, path, json.dumps(body) if body is not None else None,
                  {"Content-Type": "application/json", "Accept": "application/json"})
        r = c.getresponse()
        return r.status, r.read().decode("utf-8", "replace")
    finally:
        c.close()


def agent_call(vsock_uds: str, port: int, req: dict, timeout: float, max_bytes: int) -> dict:
    """Firecracker exposes guest vsock ports as a unix socket: send 'CONNECT <port>\\n', expect 'OK ...\\n'."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(vsock_uds)
        s.sendall(f"CONNECT {port}\n".encode())
        f = s.makefile("rwb")
        if not f.readline().startswith(b"OK"):
            raise RuntimeError_("guest agent refused the connection")
        f.write(json.dumps(req).encode() + b"\n")
        f.flush()
        line = f.readline(max_bytes)  # bounded read
        if not line.endswith(b"\n"):
            raise RuntimeError_("guest agent response too large or truncated")
        return json.loads(line)
    except (OSError, ValueError) as e:
        raise RuntimeError_(f"guest agent call failed: {e}") from e
    finally:
        s.close()


class Host:
    """Process/command seam (replaced in tests so no real Firecracker or kill is needed)."""

    def spawn(self, cmd: list[str], log: Path) -> int:
        with open(log, "ab") as lf:
            return subprocess.Popen(cmd, stdout=lf, stderr=lf, stdin=subprocess.DEVNULL,
                                    start_new_session=True).pid

    def alive(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        cmdline = Path(f"/proc/{pid}/cmdline")
        return "firecracker" in cmdline.read_text(errors="ignore") if cmdline.exists() else True

    def kill(self, pid: int) -> None:
        for sig, wait in ((signal.SIGTERM, 3.0), (signal.SIGKILL, 2.0)):
            try:
                os.kill(pid, sig)
            except OSError:
                return
            end = time.monotonic() + wait
            while time.monotonic() < end:
                if not self.alive(pid):
                    return
                time.sleep(0.05)

    def run(self, cmd: list[str]) -> None:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if r.returncode:
            raise RuntimeError_(f"{cmd[0]} failed: {r.stderr.strip()[:200]}")


def vcpus(cpu: float) -> int:
    n = max(1, math.ceil(cpu))
    return n if n == 1 else min(32, n + (n % 2))  # Firecracker wants 1 or an even number


class FirecrackerRuntime(Runtime):
    name = "firecracker"
    isolation = Isolation.MICROVM

    def __init__(self, st: Settings, host: Host | None = None):
        self.st, self.host = st, host or Host()
        self.root = Path(st.fc_dir)

    # ---- paths / state -------------------------------------------------------------
    def _dir(self, sid: str) -> Path:
        if not _ID.match(sid):
            raise RuntimeError_("invalid sandbox id")
        return self.root / sid

    def _pid(self, sid: str) -> int | None:
        try:
            return int((self._dir(sid) / "pid").read_text())
        except (OSError, ValueError):
            return None

    def _running(self, sid: str) -> bool:
        pid = self._pid(sid)
        return pid is not None and self.host.alive(pid)

    def _cfg(self, sid: str) -> dict:
        try:
            return json.loads((self._dir(sid) / "vm.json").read_text())
        except (OSError, ValueError) as e:
            raise RuntimeError_("sandbox not found on this runtime") from e

    # ---- lifecycle ---------------------------------------------------------------------
    def create(self, spec: SandboxSpec) -> None:
        p = spec.profile
        if p.isolation != self.isolation:
            raise RuntimeError_(f"runtime 'firecracker' only runs 'microvm' sandboxes, not '{p.isolation}'")
        if p.network.mode != NetworkMode.NONE:
            raise RuntimeError_("firecracker sandboxes have no network device; allowlist networking is not "
                                "supported by this runtime (needs tap + nftables enforcement)")
        if p.gpus:
            raise RuntimeError_("GPU sandboxes are not supported with microVM isolation")
        problems = self._missing()
        if problems:
            raise RuntimeError_("firecracker unavailable: " + "; ".join(problems))
        env = {**p.env, **spec.env}
        for k in env:
            if not _ENV_KEY.match(k):
                raise RuntimeError_(f"bad environment variable name '{k}'")
        d = self._dir(spec.sandbox_id)
        d.mkdir(parents=True, mode=0o700)
        try:
            self.host.run(["cp", "--reflink=auto", self.st.fc_rootfs, str(d / "rootfs.ext4")])
            ws = d / "workspace.ext4"
            with open(ws, "wb") as f:
                f.truncate(p.workspace_mb * 2**20)
            self.host.run(["mkfs.ext4", "-q", "-F", str(ws)])
            (d / "vm.json").write_text(json.dumps({"vcpus": vcpus(p.cpu), "mem_mib": p.memory_mb, "env": env}))
        except Exception:
            shutil.rmtree(d, ignore_errors=True)
            raise

    def start(self, sid: str) -> None:
        d, cfg = self._dir(sid), self._cfg(sid)
        if self._running(sid):
            return
        sock, vsock = str(d / "api.sock"), str(d / "v.sock")
        for stale in (sock, vsock):
            Path(stale).unlink(missing_ok=True)
        pid = self.host.spawn([self.st.fc_bin, "--api-sock", sock], d / "console.log")
        (d / "pid").write_text(str(pid))
        try:
            self._wait(lambda: Path(sock).exists() and api_call(sock, "GET", "/")[0] == 200, 10, "API socket")
            for method, path, body in self._boot_calls(d, cfg, vsock):
                code, text = api_call(sock, method, path, body)
                if code >= 300:
                    raise RuntimeError_(f"firecracker {path} failed ({code}): {text[:200]}")
            self._wait(lambda: self._ping(sid), self.st.fc_boot_timeout_s, "guest agent")
        except Exception as e:
            self.host.kill(pid)
            raise e if isinstance(e, RuntimeError_) else RuntimeError_(str(e)) from e

    def _boot_calls(self, d: Path, cfg: dict, vsock: str):
        return [
            ("PUT", "/machine-config", {"vcpu_count": cfg["vcpus"], "mem_size_mib": cfg["mem_mib"], "smt": False}),
            ("PUT", "/boot-source", {"kernel_image_path": self.st.fc_kernel, "boot_args": self.st.fc_boot_args}),
            ("PUT", "/drives/rootfs", {"drive_id": "rootfs", "path_on_host": str(d / "rootfs.ext4"),
                                       "is_root_device": True, "is_read_only": True}),
            ("PUT", "/drives/workspace", {"drive_id": "workspace", "path_on_host": str(d / "workspace.ext4"),
                                          "is_root_device": False, "is_read_only": False}),
            ("PUT", "/vsock", {"guest_cid": 3, "uds_path": vsock}),
            ("PUT", "/actions", {"action_type": "InstanceStart"}),
        ]

    @staticmethod
    def _wait(cond, timeout: float, what: str) -> None:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                if cond():
                    return
            except (OSError, RuntimeError_):
                pass
            time.sleep(0.1)
        raise RuntimeError_(f"timed out waiting for {what}")

    def _ping(self, sid: str) -> bool:
        r = agent_call(str(self._dir(sid) / "v.sock"), self.st.fc_agent_port, {"op": "ping"}, 3, 4096)
        return bool(r.get("ok"))

    def stop(self, sid: str) -> None:
        pid = self._pid(sid)
        if pid is not None and self.host.alive(pid):
            self.host.kill(pid)  # disks persist; start() boots again from them

    def _patch_vm(self, sid: str, state: str) -> None:
        code, text = api_call(str(self._dir(sid) / "api.sock"), "PATCH", "/vm", {"state": state})
        if code >= 300:
            raise RuntimeError_(f"firecracker {state.lower()} failed ({code}): {text[:200]}")

    def pause(self, sid: str) -> None:
        self._patch_vm(sid, "Paused")

    def resume(self, sid: str) -> None:
        self._patch_vm(sid, "Resumed")

    def destroy(self, sid: str, *, delete_workspace: bool) -> None:
        self.stop(sid)
        shutil.rmtree(self._dir(sid), ignore_errors=True)  # microVM disks are per-sandbox: always removed

    def status(self, sid: str) -> str:
        if not self._dir(sid).exists():
            return "missing"
        if not self._running(sid):
            return "stopped"
        try:
            code, text = api_call(str(self._dir(sid) / "api.sock"), "GET", "/", timeout=3)
            state = json.loads(text).get("state", "") if code == 200 else ""
        except (OSError, ValueError):
            return "stopped"
        return "paused" if state == "Paused" else ("running" if state == "Running" else "stopped")

    def logs(self, sid: str, tail: int = 200) -> str:
        try:
            lines = (self._dir(sid) / "console.log").read_text(errors="replace").splitlines()
        except OSError:
            return ""
        return "\n".join(lines[-max(1, min(tail, 5000)):])

    def _missing(self) -> list[str]:
        out = []
        if not shutil.which(self.st.fc_bin):
            out.append(f"binary '{self.st.fc_bin}' not found")
        if not os.path.exists("/dev/kvm"):
            out.append("/dev/kvm missing (needs a KVM-capable host)")
        for label, path in (("kernel", self.st.fc_kernel), ("rootfs", self.st.fc_rootfs)):
            if not path or not os.path.isfile(path):
                out.append(f"SANDBOX_FC_{label.upper()} not set or not a file")
        return out

    def health(self) -> dict:
        problems = self._missing()
        return {"runtime": "firecracker", "ok": not problems, "detail": "; ".join(problems) or "ready"}

    def execute(self, sid, argv, *, workdir, env, timeout_s, max_output_bytes, stdin=None) -> ExecResult:
        if self.status(sid) != "running":
            raise RuntimeError_("microVM is not running")
        for k in env:
            if not _ENV_KEY.match(k):
                raise RuntimeError_(f"bad environment variable name '{k}'")
        req = {"op": "exec", "argv": argv, "workdir": safe_workdir(workdir), "timeout_s": timeout_s,
               "max_output_bytes": max_output_bytes, "env": {**self._cfg(sid)["env"], **env}}
        if stdin is not None:
            import base64
            req["stdin_b64"] = base64.b64encode(stdin).decode()
        t0 = time.monotonic()
        # JSON escaping can inflate output (up to ~6x for control bytes): bound the read generously
        r = agent_call(str(self._dir(sid) / "v.sock"), self.st.fc_agent_port, req, timeout_s + 15,
                       max_output_bytes * 12 + 65536)
        if "error" in r:
            raise RuntimeError_(f"guest agent: {r['error']}")
        return ExecResult(exit_code=int(r["exit_code"]), stdout=r["stdout"], stderr=r["stderr"],
                          timed_out=bool(r["timed_out"]), truncated=bool(r["truncated"]),
                          duration_s=r.get("duration_s", round(time.monotonic() - t0, 3)))
