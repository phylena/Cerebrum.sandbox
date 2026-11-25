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


def test_files_and_quota_via_api_real_docker(tmp_path):
    st = Settings(data_dir=tmp_path, operator_key="op", viewer_key="vw", admin_key="adm")
    c = TestClient(create_app(st))
    H, A = {"Authorization": "Bearer op"}, {"Authorization": "Bearer adm"}
    c.post("/api/v1/profiles", json={"name": "pers", "persistent_workspace": True, "workspace_mb": 16}, headers=A)
    sid = c.post("/api/v1/sandboxes", json={"profile": "pers"}, headers=H).json()["id"]
    try:
        payload = bytes(range(256)) * 4096  # 1 MiB binary
        assert c.post(f"/api/v1/sandboxes/{sid}/files/upload?path=d/p.bin", content=payload, headers=H).status_code == 201
        assert c.get(f"/api/v1/sandboxes/{sid}/files/download?path=d/p.bin", headers=H).content == payload
        r = c.post(f"/api/v1/sandboxes/{sid}/execute", headers=H,
                   json={"argv": ["sha256sum", "d/p.bin"]}).json()
        import hashlib
        assert r["stdout"].split()[0] == hashlib.sha256(payload).hexdigest()
        assert c.post(f"/api/v1/sandboxes/{sid}/files/upload?path=big", content=b"x" * (16 * 2**20),
                      headers=H).status_code == 507
        assert c.get(f"/api/v1/sandboxes/{sid}/workspace", headers=H).json()["used_bytes"] >= len(payload)
        c.post(f"/api/v1/sandboxes/{sid}/execute", headers=H,
               json={"argv": ["sh", "-c", "head -c 20000000 /dev/zero > /workspace/sneaky"]})
        assert c.app.state.controller.enforce_quotas() == [sid]  # caught, stopped, data kept
    finally:
        c.delete(f"/api/v1/sandboxes/{sid}", headers=H)


def test_git_workflow_in_networkless_sandbox(tmp_path):
    """Clone host-side, work inside a sandbox WITHOUT network, return a patch. Nothing is pushed."""
    from test_git_broker import fake_fetcher, local_repo
    st = Settings(data_dir=tmp_path / "d", operator_key="op", viewer_key="vw", admin_key="adm")
    c = TestClient(create_app(st))
    H = {"Authorization": "Bearer op"}
    c.app.state.controller.git_fetcher = fake_fetcher(local_repo(tmp_path), [])
    sid = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=H).json()["id"]
    base = f"/api/v1/sandboxes/{sid}"
    try:
        assert c.post(f"{base}/git/clone", json={"url": "https://github.com/acme/widget"}, headers=H).status_code == 201
        assert c.post(f"{base}/git/clone", json={"url": "https://github.com/acme/widget"}, headers=H).status_code == 409
        assert c.post(f"{base}/git/branch", json={"name": "cerebrum/improve"}, headers=H).json()["branch"] == "cerebrum/improve"
        c.post(f"{base}/files/upload?path=widget/app.py", content=b"print(2)\n", headers=H)
        c.post(f"{base}/files/upload?path=widget/new.txt", content=b"new\n", headers=H)
        st_ = c.get(f"{base}/git/status", headers=H).json()
        assert not st_["clean"] and {f["path"] for f in st_["files"]} == {"app.py", "new.txt"}
        assert "+print(2)" in c.get(f"{base}/git/diff", headers=H).json()["diff"]
        test = c.post(f"{base}/execute", headers=H, json={"argv": ["python3", "app.py"], "workdir": "widget"}).json()
        assert test["stdout"] == "2\n"                                           # "run the tests"
        sha = c.post(f"{base}/git/commit", json={"message": "Improve app"}, headers=H).json()["sha"]
        assert c.post(f"{base}/git/commit", json={"message": "again"}, headers=H).status_code == 409
        log = c.get(f"{base}/git/log", headers=H).json()
        assert log[0]["sha"] == sha and log[0]["author"] == "Cerebrum"
        rep = c.get(f"{base}/git/report", headers=H).json()
        assert len(rep["commits"]) == 1 and "Subject: [PATCH] Improve app" in rep["patch"] and "new.txt" in rep["diffstat"]
        assert c.post(f"{base}/git/branch", json={"name": "--force"}, headers=H).status_code == 422
        assert c.post(f"{base}/git/checkout", json={"ref": "main"}, headers=H).json()["branch"] == "main"
        net = c.post(f"{base}/execute", headers=H, json={"argv": ["sh", "-c", "ls /sys/class/net"]}).json()
        assert net["stdout"].split() == ["lo"]                                   # the sandbox never had network
    finally:
        c.delete(base, headers=H)


def _upstream():
    import os
    return os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")


def test_allowlist_network_enforced_live(tmp_path):
    """Real container on the internal network; only allowlisted hosts via our proxy; direct egress impossible."""
    import os
    st = Settings(data_dir=tmp_path, operator_key="op", admin_key="adm", viewer_key="vw", egress_enabled=True,
                  egress_network_name="csb-egress-test", egress_subnet="172.31.250.0/24", egress_port=0,
                  egress_upstream_proxy=_upstream() or "")
    # port 0 -> pick a free port, then publish the real one in the proxy URL
    from cerebrum_sandbox.egress import EgressProxy, ensure_network
    from cerebrum_sandbox.store import Store
    gw = ensure_network("docker", st.egress_network_name, st.egress_subnet)
    store = Store(tmp_path)
    proxy = EgressProxy(store, gw, 0, upstream=st.egress_upstream_proxy or None)
    proxy.start()
    st.egress_network, st.egress_proxy_url = st.egress_network_name, f"http://{gw}:{proxy.port}"
    c = TestClient(create_app(st, egress=proxy))
    A, H = {"Authorization": "Bearer adm"}, {"Authorization": "Bearer op"}
    c.post("/api/v1/profiles", headers=A, json={"name": "pypi-only", "network": {
        "mode": "allowlist", "allowed_domains": ["pypi.org"], "allowed_ports": [443]}})
    r = c.post("/api/v1/sandboxes", json={"profile": "pypi-only"}, headers=H)
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    py = lambda code: c.post(f"/api/v1/sandboxes/{sid}/execute", headers=H,  # noqa: E731
                             json={"argv": ["python3", "-c", code], "timeout_s": 40}).json()
    try:
        ca = "/etc/ssl/certs/ca-certificates.crt"
        if _upstream() and os.path.exists("/root/.ccr/ca-bundle.crt"):  # this build host intercepts TLS upstream
            c.post(f"/api/v1/sandboxes/{sid}/files/upload?path=ca.pem", headers=H,
                   content=open("/root/.ccr/ca-bundle.crt", "rb").read())
            ca = "/workspace/ca.pem"
        ok = py(f"import ssl,urllib.request;ctx=ssl.create_default_context(cafile='{ca}');"
                "print(urllib.request.urlopen('https://pypi.org/simple/pip/',context=ctx,timeout=30).status)")
        assert ok["stdout"].strip() == "200", ok
        denied = py("import urllib.request\ntry:\n urllib.request.urlopen('https://example.com',timeout=20)\n"
                    "except Exception as e: print('blocked', e)")
        assert "blocked" in denied["stdout"] and "403" in denied["stdout"]
        direct = py("import socket\ntry:\n socket.create_connection(('1.1.1.1',443),5); print('OPEN')\n"
                    "except OSError as e: print('no route')")
        assert direct["stdout"].strip() == "no route"                    # bypassing the proxy is impossible
        meta = py("import socket\ntry:\n socket.create_connection(('169.254.169.254',80),3); print('OPEN')\n"
                  "except OSError: print('no route')")
        assert meta["stdout"].strip() == "no route"
        log = c.get(f"/api/v1/sandboxes/{sid}/network", headers=H).json()["log"]
        assert {(l["host"], l["decision"]) for l in log} >= {("pypi.org", "allowed"), ("example.com", "denied")}
        c.post(f"/api/v1/sandboxes/{sid}/stop", headers=H)
        c.post(f"/api/v1/sandboxes/{sid}/start", headers=H)               # re-registered after restart
        if ca == "/workspace/ca.pem":  # temporary (tmpfs) workspace: emptied by stop, as designed
            assert py("import os;print(os.path.exists('/workspace/ca.pem'))")["stdout"].strip() == "False"
            c.post(f"/api/v1/sandboxes/{sid}/files/upload?path=ca.pem", headers=H,
                   content=open("/root/.ccr/ca-bundle.crt", "rb").read())
        assert py(f"import ssl,urllib.request;ctx=ssl.create_default_context(cafile='{ca}');"
                  "print(urllib.request.urlopen('https://pypi.org/simple/pip/',context=ctx,timeout=30).status)"
                  )["stdout"].strip() == "200"
    finally:
        c.delete(f"/api/v1/sandboxes/{sid}", headers=H)
        proxy.stop()
        subprocess.run(["docker", "network", "rm", st.egress_network_name], capture_output=True)


def test_job_and_live_metrics_real_docker(tmp_path):
    import base64
    st = Settings(data_dir=tmp_path, operator_key="op", viewer_key="vw", admin_key="adm")
    c = TestClient(create_app(st))
    H = {"Authorization": "Bearer op"}
    script = b"import json,sys\nopen('out.json','w').write(json.dumps({'sum': sum(range(10))}))\nprint('done')\n"
    jid = c.post("/api/v1/jobs", headers=H, json={"argv": ["python3", "job.py"], "files": {
        "job.py": base64.b64encode(script).decode()}, "outputs": ["out.json"]}).json()["id"]
    assert c.app.state.jobs.run_once()
    j = c.get(f"/api/v1/jobs/{jid}", headers=H).json()
    assert j["state"] == "succeeded" and j["result"]["stdout"] == "done\n"
    assert base64.b64decode(j["result"]["outputs"]["out.json"]) == b'{"sum": 45}'
    assert subprocess.run(["docker", "ps", "-aq", "--filter", "label=cerebrum.sandbox=1"], capture_output=True,
                          text=True).stdout.strip() == ""                    # job sandbox removed
    sid = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=H).json()["id"]
    try:
        m = c.get(f"/api/v1/sandboxes/{sid}/metrics", headers=H).json()
        assert m["live"]["pids"] is not None and "MiB" in m["live"]["memory"] and m["workspace_used_bytes"] == 0
    finally:
        c.delete(f"/api/v1/sandboxes/{sid}", headers=H)


def test_snapshot_restore_into_new_sandbox_real_docker(tmp_path):
    st = Settings(data_dir=tmp_path, operator_key="op", viewer_key="vw", admin_key="adm")
    c = TestClient(create_app(st))
    H = {"Authorization": "Bearer op"}
    a = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=H).json()["id"]
    b = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=H).json()["id"]
    run = lambda sid, s: c.post(f"/api/v1/sandboxes/{sid}/execute", headers=H,  # noqa: E731
                                json={"argv": ["bash", "-c", s]}).json()
    try:
        run(a, "mkdir -p d && echo v1 > d/f && ln -s /etc/passwd d/link && chmod 700 d")
        snap = c.post(f"/api/v1/sandboxes/{a}/snapshots", json={"label": "v1"}, headers=H).json()
        assert snap["kind"] == "workspace" and snap["size"] > 0
        run(a, "echo v2 > d/f && touch junk")
        c.post(f"/api/v1/sandboxes/{a}/restore", json={"snapshot_id": snap["id"]}, headers=H)
        assert run(a, "cat d/f; ls")["stdout"] == "v1\nd\n"                   # rolled back, junk removed
        r = c.post(f"/api/v1/sandboxes/{b}/restore", json={"snapshot_id": snap["id"]}, headers=H)
        assert r.status_code == 200 and run(b, "cat d/f; readlink d/link")["stdout"] == "v1\n/etc/passwd\n"
        assert run(b, "id -u; stat -c %u d/f")["stdout"] == "10001\n10001\n"
        assert len(c.get(f"/api/v1/sandboxes/{a}/snapshots", headers=H).json()) == 1
        assert c.delete(f"/api/v1/snapshots/{snap['id']}", headers=H).json()["ok"]
    finally:
        c.delete(f"/api/v1/sandboxes/{a}", headers=H)
        c.delete(f"/api/v1/sandboxes/{b}", headers=H)


# ---------------- gVisor (runs only when the daemon has `runsc` registered) ----------------
def _have_runsc():
    if not _have():
        return False
    out = subprocess.run(["docker", "info", "--format", "{{json .Runtimes}}"], capture_output=True, text=True).stdout
    return '"runsc"' in out


gvisor = pytest.mark.skipif(not _have_runsc(), reason="runsc not registered with Docker")


@pytest.fixture
def gbox():
    rt = GVisorRuntime(Settings())
    made = []

    def make(**upd):
        sid = uuid.uuid4().hex[:12]
        rt.create(SandboxSpec(sid, BUILTIN["basic"].model_copy(update={"isolation": "gvisor", **upd})))
        rt.start(sid); made.append(sid)
        return sid, lambda *a, t=20, max_out=20000: rt.execute(sid, list(a), workdir="/workspace", env={},
                                                               timeout_s=t, max_output_bytes=max_out)
    yield rt, make
    for sid in made:
        rt.destroy(sid, delete_workspace=True)


@gvisor
def test_gvisor_user_space_kernel_and_hardening(gbox):
    rt, make = gbox
    sid, run = make()
    assert "gvisor" in run("uname", "-r").stdout                       # syscalls hit gVisor, not the host kernel
    assert rt.health()["ok"] is True
    assert run("id", "-u").stdout.strip() == "10001"
    st = dict(l.split(":\t") for l in run("bash", "-c", "grep -E '^(CapEff|NoNewPrivs):' /proc/self/status")
              .stdout.strip().splitlines())
    assert int(st["CapEff"].strip(), 16) == 0 and st["NoNewPrivs"].strip() == "1"
    assert run("touch", "/etc/x").exit_code != 0
    ifaces = [l.split(":")[0].strip() for l in run("cat", "/proc/net/dev").stdout.splitlines()[2:]]
    assert ifaces in ([], ["lo"])                                           # no network interface but loopback
    r = run("python3", "-c", "import socket;socket.create_connection(('1.1.1.1',443),3)")
    assert r.exit_code != 0
    assert run("sleep", "30", t=2).timed_out
    rt.write_file(sid, "x/y.bin", bytes(range(256)))
    assert rt.read_file(sid, "x/y.bin", max_bytes=1000) == bytes(range(256))


@gvisor
def test_gvisor_limits(gbox):
    _, make = gbox
    _, run = make(workspace_mb=16, memory_mb=128)
    assert "No space left" in run("bash", "-c", "dd if=/dev/zero of=/workspace/big bs=1M count=64 2>&1").stdout
    r = run("python3", "-c", "b=[]\nwhile True: b.append(bytearray(10*2**20))", t=30)
    assert r.exit_code != 0


@gvisor
def test_gvisor_via_api_isolation_request(tmp_path):
    from cerebrum_sandbox.runtime.docker import DockerRuntime as D
    st = Settings(data_dir=tmp_path, operator_key="op", viewer_key="vw", admin_key="adm", min_isolation="container")
    c = TestClient(create_app(st, runtimes={"docker": D(st), "gvisor": GVisorRuntime(st)}))
    H = {"Authorization": "Bearer op"}
    r = c.post("/api/v1/sandboxes", json={"profile": "basic", "isolation": "gvisor"}, headers=H).json()
    try:
        assert r["runtime"] == "gvisor"
        out = c.post(f"/api/v1/sandboxes/{r['id']}/execute", json={"argv": ["uname", "-r"]}, headers=H).json()
        assert "gvisor" in out["stdout"]
        assert c.post(f"/api/v1/sandboxes/{r['id']}/pause", headers=H).json()["state"] == "paused"
        assert c.post(f"/api/v1/sandboxes/{r['id']}/resume", headers=H).json()["state"] == "running"
    finally:
        c.delete(f"/api/v1/sandboxes/{r['id']}", headers=H)
    st2 = Settings(data_dir=tmp_path / "b", operator_key="op", min_isolation="gvisor")
    c2 = TestClient(create_app(st2, runtimes={"docker": D(st2), "gvisor": GVisorRuntime(st2)}))
    r2 = c2.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=H).json()   # floor upgrades it
    try:
        assert r2["runtime"] == "gvisor" and r2["profile_snapshot"]["isolation"] == "gvisor"
    finally:
        c2.delete(f"/api/v1/sandboxes/{r2['id']}", headers=H)


# ---------------- profile images (run when the images exist) ----------------
def _img(name):
    return _have() and subprocess.run(["docker", "image", "inspect", f"cerebrum-sandbox/{name}:latest"],
                                      capture_output=True).returncode == 0


def _api(tmp_path):
    st = Settings(data_dir=tmp_path, operator_key="op", viewer_key="vw", admin_key="adm")
    return TestClient(create_app(st)), {"Authorization": "Bearer op"}


@pytest.mark.skipif(not _img("research"), reason="research image not built")
def test_research_profile_live(tmp_path):
    c, H = _api(tmp_path)
    sid = c.post("/api/v1/sandboxes", json={"profile": "research"}, headers=H).json()["id"]
    try:
        code = ("import numpy as np, pandas as pd\nfrom sklearn.linear_model import LinearRegression\n"
                "x=np.arange(10).reshape(-1,1); y=3*x.ravel()+2\nm=LinearRegression().fit(x,y)\n"
                "import matplotlib.pyplot as plt; plt.plot(x,y); plt.savefig('plot.png')\n"
                "print(round(m.coef_[0],3), round(m.intercept_,3), pd.Series(y).sum())")
        r = c.post(f"/api/v1/sandboxes/{sid}/execute", json={"argv": ["python3", "-c", code], "timeout_s": 120},
                   headers=H).json()
        assert r["stdout"].split() == ["3.0", "2.0", "155"], r
        png = c.get(f"/api/v1/sandboxes/{sid}/files/download?path=plot.png", headers=H).content
        assert png[:8] == b"\x89PNG\r\n\x1a\n"
    finally:
        c.delete(f"/api/v1/sandboxes/{sid}", headers=H)


@pytest.mark.skipif(not _img("mcp"), reason="mcp image not built")
def test_mcp_profile_runs_an_isolated_mcp_server_live(tmp_path):
    c, H = _api(tmp_path)
    sid = c.post("/api/v1/sandboxes", json={"profile": "mcp"}, headers=H).json()["id"]
    server = (b"from mcp.server.mcpserver import MCPServer\nmcp = MCPServer('calc')\n"
              b"@mcp.tool()\ndef add(a: int, b: int) -> int:\n    return a + b\n"
              b"if __name__ == '__main__':\n    mcp.run()\n")
    client = (b"import asyncio\nfrom mcp import ClientSession, StdioServerParameters\n"
              b"from mcp.client.stdio import stdio_client\n"
              b"async def main():\n"
              b"    p = StdioServerParameters(command='python3', args=['server.py'])\n"
              b"    async with stdio_client(p) as (r, w):\n"
              b"        async with ClientSession(r, w) as s:\n"
              b"            await s.initialize()\n"
              b"            tools = [t.name for t in (await s.list_tools()).tools]\n"
              b"            res = await s.call_tool('add', {'a': 2, 'b': 40})\n"
              b"            print(tools, res.content[0].text)\n"
              b"asyncio.run(main())\n")
    try:
        c.post(f"/api/v1/sandboxes/{sid}/files/upload?path=server.py", content=server, headers=H)
        c.post(f"/api/v1/sandboxes/{sid}/files/upload?path=client.py", content=client, headers=H)
        r = c.post(f"/api/v1/sandboxes/{sid}/execute", json={"argv": ["python3", "client.py"], "timeout_s": 60},
                   headers=H).json()
        assert r["stdout"].strip() == "['add'] 42", r
    finally:
        c.delete(f"/api/v1/sandboxes/{sid}", headers=H)


@pytest.mark.skipif(not _img("browser"), reason="browser image not built")
def test_browser_profile_headless_chromium_live(tmp_path):
    c, H = _api(tmp_path)
    r = c.post("/api/v1/sandboxes", json={"profile": "browser"}, headers=H)
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    script = (b"from playwright.sync_api import sync_playwright\n"
              b"with sync_playwright() as p:\n"
              b"    b = p.chromium.launch()\n"
              b"    pg = b.new_page()\n"
              b"    pg.set_content('<h1 id=t>Cerebrum</h1><script>document.getElementById(\"t\").textContent+=\" ok\"</script>')\n"
              b"    print(pg.inner_text('#t'))\n"
              b"    pg.screenshot(path='shot.png')\n"
              b"    try:\n"
              b"        pg.goto('https://example.com', timeout=5000); print('NETWORK OPEN')\n"
              b"    except Exception as e:\n"
              b"        print('offline')\n"
              b"    b.close()\n")
    try:
        c.post(f"/api/v1/sandboxes/{sid}/files/upload?path=b.py", content=script, headers=H)
        r = c.post(f"/api/v1/sandboxes/{sid}/execute", json={"argv": ["python3", "b.py"], "timeout_s": 120},
                   headers=H).json()
        assert r["stdout"].split("\n")[:2] == ["Cerebrum ok", "offline"], r
        assert c.get(f"/api/v1/sandboxes/{sid}/files/download?path=shot.png", headers=H).content[:4] == b"\x89PNG"
    finally:
        c.delete(f"/api/v1/sandboxes/{sid}", headers=H)
