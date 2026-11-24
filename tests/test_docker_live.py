"""Needs a live Docker daemon and the cerebrum-sandbox/base image; skipped otherwise."""
import shutil
import subprocess

import pytest

from cerebrum_sandbox.profiles import BUILTIN
from cerebrum_sandbox.runtime import SandboxSpec
from cerebrum_sandbox.runtime.docker import DockerRuntime
from cerebrum_sandbox.settings import Settings


def _have():
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", "cerebrum-sandbox/base:latest"],
                          capture_output=True).returncode == 0


pytestmark = [pytest.mark.docker, pytest.mark.skipif(not _have(), reason="no Docker daemon/base image")]


def test_live_isolation_and_timeout():
    rt = DockerRuntime(Settings())
    sid = "0123456789ab"
    rt.create(SandboxSpec(sid, BUILTIN["basic"])); rt.start(sid)
    try:
        run = lambda *a, t=10: rt.execute(sid, list(a), workdir="/workspace", env={}, timeout_s=t, max_output_bytes=10000)
        assert run("id", "-u").stdout.strip() == "10001"
        assert run("touch", "/etc/x").exit_code != 0                       # read-only root
        assert run("sh", "-c", "echo hi > /workspace/a && cat /workspace/a").stdout.strip() == "hi"
        assert run("python3", "-c", "import socket;socket.create_connection(('1.1.1.1',443),2)").exit_code != 0
        assert run("sleep", "30", t=2).timed_out
    finally:
        rt.destroy(sid, delete_workspace=True)
