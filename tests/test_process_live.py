"""Live tests of the process runtime: real processes, real Landlock / seccomp / namespaces.

Each test runs in both modes the host supports ("bwrap": user namespaces + seccomp + limits,
"landlock": Landlock + seccomp + limits). Skipped where the kernel offers neither.
These prove the isolation controls on this host; a deployment target (e.g. a Hugging Face Space)
must be checked with GET /api/v1/runtimes, which reports the layers that are actually active there.
"""
import base64
import os
import shutil
import socket
import time

import pytest
from fastapi.testclient import TestClient

from cerebrum_sandbox.api.app import create_app
from cerebrum_sandbox.runtime.process import ProcessRuntime, _bwrap_works, _landlock_abi
from cerebrum_sandbox.settings import Settings

MODES = [m for m, ok in (("landlock", _landlock_abi() >= 1), ("bwrap", _bwrap_works("bwrap"))) if ok]
pytestmark = pytest.mark.skipif(not MODES, reason="neither Landlock nor bubblewrap user namespaces available")
OP = {"Authorization": "Bearer op"}


@pytest.fixture(params=MODES)
def api(request, tmp_path, monkeypatch):
    monkeypatch.setenv("CSB_TEST_SECRET", "s3cr3t-value-in-controller-env")
    st = Settings(data_dir=tmp_path / "data", admin_key="adm", operator_key="op", viewer_key="vw",
                  runtimes=["process"], min_isolation="process", process_fallback=True,
                  process_mode=request.param, max_sandboxes=4, max_total_cpu=4, max_total_memory_mb=4096)
    app = create_app(st)
    rt = app.state.controller.runtimes["process"]
    assert rt.mode == request.param
    with TestClient(app) as c:
        c.mode = request.param
        c.root = rt.root
        yield c


def make(api, profile="basic"):
    r = api.post("/api/v1/sandboxes", json={"profile": profile, "ttl_s": 300}, headers=OP)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def run(api, sid, argv, timeout_s=20, stdin=None):
    body = {"argv": argv, "timeout_s": timeout_s}
    r = api.post(f"/api/v1/sandboxes/{sid}/execute", json=body, headers=OP)
    assert r.status_code == 200, r.text
    return r.json()


def test_runtime_reports_its_layers(api):
    rts = {r["name"]: r for r in api.get("/api/v1/runtimes", headers=OP).json()}
    p = rts["process"]
    assert p["ok"] is True and p["isolation"] == "process" and p["mode"] == api.mode
    assert p["layers"]["seccomp"] is True and p["layers"]["clean_env"] is True


def test_container_profile_runs_as_process_and_says_so(api):
    sid = make(api)
    s = api.get(f"/api/v1/sandboxes/{sid}", headers=OP).json()
    assert s["runtime"] == "process" and s["profile_snapshot"]["isolation"] == "process"
    # an explicit request for container isolation is refused, not silently downgraded
    r = api.post("/api/v1/sandboxes", json={"profile": "basic", "isolation": "container"}, headers=OP)
    assert r.status_code == 503 and "no worker offers the required runtime" in r.text


def test_cerebrum_run_code_flow(api):
    """The exact calls Cerebrum.model's run_code tool makes: create, upload, execute, delete."""
    sid = make(api)
    code = b"import math\nprint(sum(i*i for i in range(10)), round(math.pi, 4))\n"
    up = api.post(f"/api/v1/sandboxes/{sid}/files/upload", params={"path": "main.py"}, content=code, headers=OP)
    assert up.status_code == 201, up.text
    d = run(api, sid, ["python3", "main.py"])
    assert d["exit_code"] == 0 and d["stdout"].strip() == "285 3.1416", d
    assert api.delete(f"/api/v1/sandboxes/{sid}", headers=OP).status_code in (200, 204)


def test_files_round_trip_and_listing(api):
    sid = make(api)
    run(api, sid, ["sh", "-c", "mkdir -p out && echo result > out/r.txt"])
    files = api.get(f"/api/v1/sandboxes/{sid}/files", params={"path": "out"}, headers=OP).json()
    assert [f["name"] for f in files] == ["r.txt"]
    got = api.get(f"/api/v1/sandboxes/{sid}/files/download", params={"path": "out/r.txt"}, headers=OP)
    assert got.status_code == 200 and got.content == b"result\n"


def test_no_network(api):
    sid = make(api)
    d = run(api, sid, ["python3", "-c", "import socket; socket.create_connection(('1.1.1.1', 53), timeout=3)"])
    assert d["exit_code"] != 0 and ("Operation not permitted" in d["stderr"] or "Network is unreachable" in d["stderr"])


def test_no_controller_secrets_or_files(api):
    sid = make(api)
    d = run(api, sid, ["sh", "-c", "env; cat /proc/1/environ 2>&1; cat /proc/$PPID/environ 2>&1; true"])
    assert "s3cr3t-value-in-controller-env" not in d["stdout"] + d["stderr"]
    assert "CSB_SANDBOX_ID" in d["stdout"]
    # the controller's database and other sandboxes are out of reach
    db = str(api.root.parent / "sandbox.db")
    d = run(api, sid, ["sh", "-c", f"ls {api.root.parent}; cat {db} | head -c 20"])
    assert "SQLite" not in d["stdout"]
    other = make(api)
    run(api, other, ["sh", "-c", "echo private > mine.txt"])
    d = run(api, sid, ["cat", str(api.root / other / "workspace" / "mine.txt")])
    assert d["exit_code"] != 0 and "private" not in d["stdout"]


def test_cannot_kill_the_controller(api):
    sid = make(api)
    d = run(api, sid, ["python3", "-c", f"import os; os.kill({os.getpid()}, 9)"])
    assert d["exit_code"] != 0
    run(api, sid, ["python3", "-c", "import os; os.kill(-1, 9)"])
    assert api.get("/health").status_code == 200  # still alive


def test_memory_and_time_limits(api):
    sid = make(api)  # basic: 256 MB, max 60 s
    d = run(api, sid, ["python3", "-c", "x = bytearray(700 * 1024 * 1024); print('allocated')"])
    assert d["exit_code"] != 0 and "allocated" not in d["stdout"]
    t0 = time.time()
    d = run(api, sid, ["sh", "-c", "sleep 30"], timeout_s=2)
    assert d["timed_out"] is True and time.time() - t0 < 10


def test_background_processes_do_not_survive(api):
    sid = make(api)
    run(api, sid, ["sh", "-c", "(sleep 300 &) ; nohup sleep 300 >/dev/null 2>&1 & echo started"])
    time.sleep(0.5)
    leftover = [p for p in os.listdir("/proc") if p.isdigit() and _cmd(p).startswith("sleep300")]
    assert leftover == []


def _cmd(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\0", b"").decode()
    except OSError:
        return ""


def test_cannot_escape_with_namespaces_or_setsid(api):
    sid = make(api)
    for argv in (["unshare", "-U", "true"], ["python3", "-c", "import os; os.setsid()"]):
        d = run(api, sid, argv)
        assert d["exit_code"] != 0, argv


def test_workspace_paths(api):
    """In bwrap mode the sandbox sees /workspace; in landlock mode /workspace arguments are rewritten."""
    sid = make(api)
    d = run(api, sid, ["sh", "-c", "pwd"])
    if api.mode == "bwrap":
        assert d["stdout"].strip() == "/workspace"
    else:
        assert d["stdout"].strip().endswith(f"{sid}/workspace")
    run(api, sid, ["sh", "-c", "echo x > /workspace/abs.txt"] if api.mode == "bwrap" else
        ["cp", "/dev/null", "/workspace/abs.txt"])
    files = api.get(f"/api/v1/sandboxes/{sid}/files", headers=OP).json()
    assert "abs.txt" in [f["name"] for f in files]


def test_snapshot_and_restore(api):
    sid = make(api)
    run(api, sid, ["sh", "-c", "echo v1 > keep.txt"])
    snap = api.post(f"/api/v1/sandboxes/{sid}/snapshots", json={"label": "s1"}, headers=OP)
    assert snap.status_code in (200, 201), snap.text
    run(api, sid, ["sh", "-c", "echo v2 > keep.txt && echo junk > extra.txt"])
    r = api.post(f"/api/v1/sandboxes/{sid}/restore", json={"snapshot_id": snap.json()["id"], "clear": True},
                 headers=OP)
    assert r.status_code == 200, r.text
    assert run(api, sid, ["cat", "keep.txt"])["stdout"] == "v1\n"
    assert run(api, sid, ["ls"])["stdout"].split() == ["keep.txt"]
