"""Live security tests against a real Docker daemon + the cerebrum-sandbox/base image.
Skipped when either is missing. These are the tests that justify the hardening claims."""
import shutil
import subprocess
import uuid

import pytest
from fastapi.testclient import TestClient

from cerebrum_sandbox.api.app import create_app
from cerebrum_sandbox.profiles import BUILTIN
from cerebrum_sandbox.runtime import RuntimeError_, SandboxSpec
from cerebrum_sandbox.runtime.docker import DockerRuntime
from cerebrum_sandbox.runtime.gvisor import GVisorRuntime
from cerebrum_sandbox.settings import Settings


def _have():
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", "cerebrum-sandbox/base:latest"],
                          capture_output=True).returncode == 0


pytestmark = [pytest.mark.docker, pytest.mark.skipif(not _have(), reason="no Docker daemon/base image")]


@pytest.fixture
def box():
    rt = DockerRuntime(Settings())
    made = []

    def make(profile="basic", **upd):
        sid = uuid.uuid4().hex[:12]
        p = BUILTIN[profile].model_copy(update=upd) if upd else BUILTIN[profile]
        rt.create(SandboxSpec(sid, p)); rt.start(sid); made.append(sid)
        run = lambda *a, t=20, max_out=20000, wd="/workspace": rt.execute(  # noqa: E731
            sid, list(a), workdir=wd, env={}, timeout_s=t, max_output_bytes=max_out)
        return sid, run
    yield rt, make
    for sid in made:
        rt.destroy(sid, delete_workspace=True)


def sh(run, script, **kw):
    return run("bash", "-c", script, **kw)


def test_identity_and_privileges(box):
    _, make = box
    _, run = make()
    assert run("id", "-u").stdout.strip() == "10001"
    assert "nobody" in run("ps", "-o", "user=", "-p", "1").stdout   # keeper is not the sandbox user
    status = sh(run, "grep -E '^(CapEff|CapBnd|NoNewPrivs|Seccomp):' /proc/self/status").stdout
    fields = dict(line.split(":\t") for line in status.strip().splitlines())
    assert int(fields["CapEff"].strip(), 16) == 0 and int(fields["CapBnd"].strip(), 16) == 0
    assert fields["NoNewPrivs"].strip() == "1"
    assert fields["Seccomp"].strip() == "2"  # Docker's default seccomp filter is active
    assert sh(run, "su -c id root </dev/null").exit_code != 0


def test_filesystem_restrictions(box):
    _, make = box
    _, run = make()
    assert run("touch", "/etc/x").exit_code != 0                 # read-only root
    assert run("touch", "/usr/bin/x").exit_code != 0
    assert sh(run, "echo hi > /workspace/a && cat /workspace/a").stdout.strip() == "hi"
    assert sh(run, "echo t > /tmp/t && cat /tmp/t").stdout.strip() == "t"
    assert sh(run, "printf '#!/bin/sh\\necho x' > /tmp/e && chmod +x /tmp/e && /tmp/e").exit_code != 0  # noexec
    assert sh(run, "ls /var/run/docker.sock /run/docker.sock 2>&1").exit_code != 0   # no Docker socket
    mounts = run("cat", "/proc/mounts").stdout
    assert "docker.sock" not in mounts and " /host" not in mounts


def test_workspace_quota_is_kernel_enforced(box):
    _, make = box
    _, run = make(workspace_mb=16)
    r = sh(run, "dd if=/dev/zero of=/workspace/big bs=1M count=64 2>&1; echo rc=$?")
    assert "No space left" in r.stdout


def test_no_network(box):
    _, make = box
    _, run = make()
    links = sh(run, "ls /sys/class/net").stdout.split()
    assert links == ["lo"]
    r = run("python3", "-c", "import socket;socket.create_connection(('1.1.1.1',443),3)")
    assert r.exit_code != 0
    assert run("python3", "-c", "import socket;socket.getaddrinfo('pypi.org',443)").exit_code != 0


def test_pid_limit_contains_fork_bomb(box):
    _, make = box
    _, run = make(pids=32)
    r = sh(run, "for i in $(seq 1 200); do sleep 20 & done 2>&1 | head -3; echo done", t=15)
    assert "Resource temporarily unavailable" in r.stdout + r.stderr or "retry" in (r.stdout + r.stderr)


def test_memory_limit_kills_hog(box):
    _, make = box
    _, run = make(memory_mb=128)
    r = run("python3", "-c", "b=[]\nwhile True: b.append(bytearray(10*2**20))", t=30)
    assert r.exit_code in (137, -9) or "MemoryError" in r.stderr


def test_timeout_and_output_bound(box):
    _, make = box
    _, run = make()
    r = run("sleep", "60", t=2)
    assert r.timed_out and r.duration_s < 10
    r = run("python3", "-c", "print('x'*500000)", max_out=1000)
    assert r.truncated and len(r.stdout) == 1000
    assert "sleep 60" not in run("ps", "-eo", "args").stdout.replace("ps -eo args", "")  # killed


def test_background_and_setsid_processes_reaped_keeper_survives(box):
    rt, make = box
    sid, run = make()
    sh(run, "sleep 301 & sleep 302", t=2)                         # same process group: killed by timeout
    sh(run, "setsid sleep 303 >/dev/null 2>&1 & echo ok")           # escaped its group: still alive
    assert "sleep 303" in run("ps", "-eo", "args").stdout
    assert "sleep 301" not in run("ps", "-eo", "args").stdout
    rt.kill_processes(sid)
    procs = run("ps", "-eo", "user,args").stdout
    assert "sleep 303" not in procs and rt.status(sid) == "running"  # keeper (nobody) survived
    assert run("id", "-u").stdout.strip() == "10001"


def test_file_operations_live(box):
    rt, make = box
    sid, _ = make()
    data = bytes(range(256)) * 100
    rt.write_file(sid, "dir/sub/bin.dat", data)
    assert rt.read_file(sid, "/workspace/dir/sub/bin.dat", max_bytes=10**6) == data
    names = {e["name"]: e for e in rt.list_dir(sid, "dir/sub")}
    assert names["bin.dat"]["size"] == len(data) and names["bin.dat"]["type"] == "file"
    with pytest.raises(RuntimeError_, match="too large"):
        rt.read_file(sid, "dir/sub/bin.dat", max_bytes=10)
    with pytest.raises(RuntimeError_):
        rt.read_file(sid, "/etc/passwd", max_bytes=10**6)
    assert rt.workspace_usage_bytes(sid) >= len(data)
    rt.delete_path(sid, "dir")
    assert rt.list_dir(sid, "/workspace") == []


def test_host_processes_invisible(box):
    _, make = box
    _, run = make()
    procs = run("ps", "-eo", "comm").stdout
    assert "dockerd" not in procs and "containerd" not in procs


def test_lifecycle_and_persistent_workspace(box):
    rt, make = box
    sid, run = make("development", network=BUILTIN["basic"].network)
    sh(run, "echo keep > /workspace/k")
    rt.pause(sid); assert rt.status(sid) == "paused"
    rt.resume(sid); assert rt.status(sid) == "running"
    rt.stop(sid); assert rt.status(sid) == "stopped"
    rt.start(sid)
    assert run("cat", "/workspace/k").stdout.strip() == "keep"  # named volume survives stop/start
    assert "csb-ws-" + sid in subprocess.run(["docker", "volume", "ls", "-q"], capture_output=True,
                                              text=True).stdout
    rt.destroy(sid, delete_workspace=True)
    assert rt.status(sid) == "missing"
    assert "csb-ws-" + sid not in subprocess.run(["docker", "volume", "ls", "-q"], capture_output=True,
                                                  text=True).stdout


def test_gvisor_refuses_without_runsc():
    if "runsc" in subprocess.run(["docker", "info", "--format", "{{json .Runtimes}}"],
                                 capture_output=True, text=True).stdout:
        pytest.skip("runsc is installed here")
    p = BUILTIN["basic"].model_copy(update={"isolation": "gvisor"})
    with pytest.raises(RuntimeError_, match="gVisor unavailable"):
        GVisorRuntime(Settings()).create(SandboxSpec(uuid.uuid4().hex[:12], p))


def test_api_end_to_end_real_docker(tmp_path):
    st = Settings(data_dir=tmp_path, operator_key="op", viewer_key="vw", admin_key="adm")
    c = TestClient(create_app(st))
    H = {"Authorization": "Bearer op"}
    sid = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=H).json()["id"]
    try:
        r = c.post(f"/api/v1/sandboxes/{sid}/execute", headers=H,
                   json={"argv": ["python3", "-c", "import os;print(os.getuid(), 6*7)"]}).json()
        assert r["stdout"].strip() == "10001 42" and r["status"] == "ok"
        assert c.get("/health").json()["runtime"]["ok"] is True
    finally:
        assert c.delete(f"/api/v1/sandboxes/{sid}", headers=H).json()["state"] == "terminated"
