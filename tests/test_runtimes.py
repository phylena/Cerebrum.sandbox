"""gVisor, GPU scheduling, isolation policy, Firecracker (fake FC API + real guest agent), workers."""
import importlib.util
import json
import socket
import socketserver
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cerebrum_sandbox.api.app import create_app
from cerebrum_sandbox.profiles import BUILTIN
from cerebrum_sandbox.runtime import RuntimeError_, SandboxSpec
from cerebrum_sandbox.runtime.docker import DockerRuntime, build_create_args
from cerebrum_sandbox.runtime.firecracker import FirecrackerRuntime, Host, vcpus
from cerebrum_sandbox.runtime.gvisor import GVisorRuntime
from cerebrum_sandbox.settings import Settings
from conftest import ADM, OP, VW, FakeRuntime

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("csb_agent", ROOT / "images/firecracker/csb_agent.py")
csb_agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(csb_agent)


def mk(st, runtimes=None, **kw):
    return TestClient(create_app(st, runtimes=runtimes or {"docker": FakeRuntime()}, **kw))


def big(tmp_path, **kw):
    base = dict(data_dir=tmp_path, admin_key="adm", operator_key="op", viewer_key="vw", max_sandboxes=10,
                max_total_cpu=32, max_total_memory_mb=65536)
    return Settings(**{**base, **kw})


# ============================ gVisor ============================
def _docker_info(runtimes):
    return lambda args, t: (0, json.dumps(runtimes), "") if args[1] == "info" else (0, "", "")


def test_gvisor_creates_only_with_runsc_and_only_gvisor_profiles():
    calls = []

    def runner(args, t):
        calls.append(args)
        return (0, json.dumps({"runc": {}, "runsc": {}}), "") if args[1] == "info" else (0, "", "")
    rt = GVisorRuntime(Settings(), runner)
    p = BUILTIN["basic"].model_copy(update={"isolation": "gvisor"})
    rt.create(SandboxSpec("abcdef012345", p))
    create = next(c for c in calls if c[1] == "create")
    assert create[create.index("--runtime") + 1] == "runsc" and "--cap-drop" in create  # hardening kept
    with pytest.raises(RuntimeError_, match="only runs 'gvisor'"):
        rt.create(SandboxSpec("abcdef012345", BUILTIN["basic"]))


def test_gvisor_refuses_when_runsc_not_registered_no_fallback():
    rt = GVisorRuntime(Settings(), _docker_info({"runc": {}}))
    p = BUILTIN["basic"].model_copy(update={"isolation": "gvisor"})
    with pytest.raises(RuntimeError_, match="gVisor unavailable"):
        rt.create(SandboxSpec("abcdef012345", p))
    assert rt.health()["ok"] is False


def test_plain_docker_never_runs_stronger_or_weaker_profile():
    rt = DockerRuntime(Settings(), lambda a, t: (0, "", ""))
    p = BUILTIN["basic"].model_copy(update={"isolation": "gvisor"})
    with pytest.raises(RuntimeError_, match="only runs 'container'"):
        rt.create(SandboxSpec("abcdef012345", p))


# ============================ isolation policy ============================
def test_isolation_routing_and_rules(tmp_path):
    d, g = FakeRuntime(), FakeRuntime()
    c = mk(big(tmp_path), {"docker": d, "gvisor": g})
    r = c.post("/api/v1/sandboxes", json={"profile": "basic", "isolation": "gvisor"}, headers=OP).json()
    assert r["runtime"] == "gvisor" and r["profile_snapshot"]["isolation"] == "gvisor" and r["id"] in g.boxes
    assert c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["runtime"] == "docker"
    assert c.post("/api/v1/sandboxes", json={"profile": "basic", "isolation": "microvm"},
                  headers=OP).status_code == 503  # no firecracker enabled: clear error, no downgrade
    assert c.post("/api/v1/sandboxes", json={"profile": "basic", "isolation": "bogus"}, headers=OP).status_code == 422
    c.post("/api/v1/profiles", json={"name": "strict", "isolation": "gvisor"}, headers=ADM)
    assert c.post("/api/v1/sandboxes", json={"profile": "strict", "isolation": "container"},
                  headers=OP).status_code == 422  # overrides may only strengthen


def test_min_isolation_floor_upgrades_weak_profiles(tmp_path):
    g = FakeRuntime()
    c = mk(big(tmp_path, min_isolation="gvisor"), {"docker": FakeRuntime(), "gvisor": g})
    r = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()
    assert r["runtime"] == "gvisor" and r["id"] in g.boxes


# ============================ GPU workers ============================
GPU2 = lambda: [{"index": 0, "name": "T4"}, {"index": 1, "name": "T4"}]  # noqa: E731


def _train(c, **extra):
    return c.post("/api/v1/sandboxes", json={"profile": "training", **extra}, headers=OP)


def test_gpu_exclusive_assignment_and_release(tmp_path):
    rt = FakeRuntime()
    c = mk(big(tmp_path, max_gpu_sandboxes=5), {"docker": rt}, gpu_detector=GPU2)
    a, b = _train(c).json(), _train(c).json()
    assert (a["gpu_indices"], b["gpu_indices"]) == ([0], [1])
    assert rt.specs[a["id"]].gpu_indices == [0]
    r = _train(c)
    assert r.status_code == 429 and "free GPU" in r.json()["detail"]
    c.delete(f"/api/v1/sandboxes/{a['id']}", headers=OP)
    assert _train(c).json()["gpu_indices"] == [0]  # freed device is reused, never shared


def test_gpu_caps_and_cpu_only_host(tmp_path):
    c = mk(big(tmp_path, max_gpu_sandboxes=1), gpu_detector=GPU2)
    assert _train(c).status_code == 201
    r = _train(c)
    assert r.status_code == 429 and "GPU sandbox limit" in r.json()["detail"]
    cpu_only = mk(big(tmp_path / "x"), gpu_detector=lambda: [])
    r = _train(cpu_only)
    assert r.status_code == 429 and "has 0" in r.json()["detail"]
    assert cpu_only.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).status_code == 201  # CPU still fine


def test_gpu_index_restriction(tmp_path):
    c = mk(big(tmp_path, gpu_indices=[1]), gpu_detector=GPU2)
    assert _train(c).json()["gpu_indices"] == [1]
    assert _train(c).status_code == 429  # device 0 is reserved for other uses


def test_gpu_flag_exact_devices_and_unsupported_combos():
    p = BUILTIN["training"]
    args = build_create_args(SandboxSpec("abcdef012345", p, gpu_indices=[1]), Settings())
    assert args[args.index("--gpus") + 1] == '"device=1"' and "all" not in args[args.index("--gpus") + 1]
    with pytest.raises(RuntimeError_, match="distinct GPU indices"):
        build_create_args(SandboxSpec("abcdef012345", p, gpu_indices=[]), Settings())
    gv = p.model_copy(update={"isolation": "gvisor"})
    with pytest.raises(RuntimeError_, match="container isolation"):
        build_create_args(SandboxSpec("abcdef012345", gv, gpu_indices=[0]), Settings())


def test_resources_reports_gpus(tmp_path):
    c = mk(big(tmp_path), gpu_detector=GPU2)
    _train(c)
    r = c.get("/api/v1/resources", headers=VW).json()
    assert len(r["host"]["gpus"]) == 2 and r["usage"]["gpus_assigned"] == 1


# ============================ guest agent (real code) ============================
@pytest.fixture
def agent(tmp_path):
    return csb_agent.Agent(workspace=str(tmp_path), run_as=None)


def ex(agent, tmp_path, argv, **kw):
    return agent.handle({"op": "exec", "argv": argv, "workdir": str(tmp_path), **kw})


def test_agent_exec_exit_code_and_streams(agent, tmp_path):
    r = ex(agent, tmp_path, ["sh", "-c", "echo out; echo err >&2; exit 3"])
    assert (r["exit_code"], r["stdout"], r["stderr"], r["timed_out"]) == (3, "out\n", "err\n", False)
    assert ex(agent, tmp_path, ["/nonexistent"])["exit_code"] == 127


def test_agent_timeout_kills_whole_process_group(agent, tmp_path):
    t0 = time.monotonic()
    r = ex(agent, tmp_path, ["sh", "-c", "sleep 30 & sleep 30"], timeout_s=1)
    assert r["timed_out"] and time.monotonic() - t0 < 6


def test_agent_env_isolated_and_output_bounded(agent, tmp_path, monkeypatch):
    monkeypatch.setenv("HOST_SECRET_X", "leaky")
    out = ex(agent, tmp_path, ["env"], env={"FOO": "bar"})["stdout"]
    assert "leaky" not in out and "FOO=bar" in out
    r = ex(agent, tmp_path, ["python3", "-c", "print('x'*100000)"], max_output_bytes=1000)
    assert r["truncated"] and len(r["stdout"]) == 1000


def test_agent_validation_and_workdir_confinement(agent, tmp_path):
    assert "error" in agent.handle({"op": "exec", "argv": []})
    assert "error" in agent.handle({"op": "exec", "argv": ["ls"], "env": {"A": 1}})
    assert "error" in agent.handle({"op": "exec", "argv": ["ls"], "workdir": "/etc"})
    assert "error" in agent.handle({"op": "exec", "argv": ["ls"], "workdir": str(tmp_path) + "/../etc"})
    assert agent.handle({"op": "ping"}) == {"ok": True}
    assert "error" in agent.handle({"op": "nope"})


# ============================ Firecracker (fake FC API + real agent over the vsock protocol) ============
class FakeFC:
    def __init__(self, sock, workspace):
        self.calls, self.state, self.fail = [], "Not started", set()
        fc = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def _go(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                fc.calls.append((self.command, self.path, body))
                code, out = 204, b""
                if self.path in fc.fail:
                    code, out = 400, b'{"fault_message":"nope"}'
                elif self.command == "GET":
                    code, out = 200, json.dumps({"state": fc.state}).encode()
                elif body and body.get("action_type") == "InstanceStart":
                    fc.state = "Running"
                elif self.path == "/vm":
                    fc.state = body["state"] if body["state"] == "Paused" else "Running"
                self.send_response(code); self.send_header("Content-Length", str(len(out))); self.end_headers()
                self.wfile.write(out)
            do_GET = do_PUT = do_PATCH = _go

        class S(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
            daemon_threads = True
        self.api = S(sock, H)
        threading.Thread(target=self.api.serve_forever, daemon=True).start()
        # vsock UDS: "CONNECT <port>\n" -> "OK ..\n" -> then the real guest agent protocol
        self.agent = csb_agent.Agent(workspace=workspace, run_as=None)
        self.ws = workspace
        vs = str(Path(sock).parent / "v.sock")
        lst = socket.socket(socket.AF_UNIX); lst.bind(vs); lst.listen(8); self.lst = lst
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.lst.accept()
            except OSError:
                return
            line = b""
            while not line.endswith(b"\n"):
                line += conn.recv(1)
            conn.sendall(b"OK 1\n")
            fc = self

            class A:  # map the guest's /workspace onto a temp dir
                def handle(self, req):
                    if req.get("workdir"):
                        req = {**req, "workdir": req["workdir"].replace("/workspace", fc.ws, 1)}
                    return fc.agent.handle(req)
            threading.Thread(target=csb_agent.serve_connection, args=(conn, A()), daemon=True).start()

    def close(self):
        self.api.shutdown(); self.api.server_close(); self.lst.close()


class FakeHost(Host):
    def __init__(self, ws):
        self.fc, self.ws, self.runs, self.up = None, ws, [], False
        self.fail = set()

    def spawn(self, cmd, log):
        sock = cmd[cmd.index("--api-sock") + 1]
        self.fc = FakeFC(sock, self.ws); self.fc.fail = self.fail; self.up = True
        Path(log).write_text("boot line 1\nboot line 2\n")
        return 4242

    def alive(self, pid): return self.up
    def kill(self, pid): self.up = False; self.fc.close()
    def run(self, cmd): self.runs.append(cmd)


@pytest.fixture
def fcenv(tmp_path, monkeypatch):
    d = Path(tempfile.mkdtemp(prefix="fc"))  # short path: unix sockets are limited to ~108 chars
    (tmp_path / "ws").mkdir()
    kernel, rootfs = tmp_path / "vmlinux", tmp_path / "rootfs.ext4"
    kernel.write_bytes(b"k"); rootfs.write_bytes(b"r")
    st = Settings(fc_dir=str(d), fc_kernel=str(kernel), fc_rootfs=str(rootfs), fc_bin="sh", fc_boot_timeout_s=5)
    host = FakeHost(str(tmp_path / "ws"))
    rt = FirecrackerRuntime(st, host)
    monkeypatch.setattr(FirecrackerRuntime, "_missing", lambda self: [])  # no /dev/kvm here
    return rt, host, st


def mvm(**kw):
    return BUILTIN["basic"].model_copy(update={"isolation": "microvm", **kw})


def test_vcpu_rounding():
    assert [vcpus(x) for x in (0.5, 1, 1.5, 2, 3, 99)] == [1, 1, 2, 2, 4, 32]


def test_firecracker_boot_sequence_and_exec(fcenv):
    rt, host, st = fcenv
    rt.create(SandboxSpec("abcdef012345", mvm(cpu=1.5, memory_mb=512, workspace_mb=64, env={"A": "1"})))
    assert (Path(st.fc_dir) / "abcdef012345/workspace.ext4").stat().st_size == 64 * 2**20  # size == quota
    assert any(c[0] == "mkfs.ext4" for c in host.runs) and any(c[0] == "cp" for c in host.runs)
    rt.start("abcdef012345")
    calls = [(m, p) for m, p, _ in host.fc.calls if m != "GET"]
    assert calls == [("PUT", "/machine-config"), ("PUT", "/boot-source"), ("PUT", "/drives/rootfs"),
                     ("PUT", "/drives/workspace"), ("PUT", "/vsock"), ("PUT", "/actions")]
    body = {p: b for m, p, b in host.fc.calls if b}
    assert body["/machine-config"] == {"vcpu_count": 2, "mem_size_mib": 512, "smt": False}
    assert body["/drives/rootfs"]["is_read_only"] is True
    assert body["/boot-source"]["kernel_image_path"] == st.fc_kernel
    assert not any(p == "/network-interfaces" for _, p, _ in host.fc.calls)  # no NIC at all
    r = rt.execute("abcdef012345", ["sh", "-c", "echo hi $A; exit 3"], workdir="/workspace", env={},
                   timeout_s=10, max_output_bytes=10000)
    assert (r.exit_code, r.stdout) == (3, "hi 1\n")
    with pytest.raises(RuntimeError_, match="working directory"):
        rt.execute("abcdef012345", ["ls"], workdir="/etc", env={}, timeout_s=5, max_output_bytes=100)


def test_firecracker_timeout_via_agent(fcenv):
    rt, *_ = fcenv
    rt.create(SandboxSpec("abcdef012345", mvm())); rt.start("abcdef012345")
    r = rt.execute("abcdef012345", ["sleep", "30"], workdir="/workspace", env={}, timeout_s=1, max_output_bytes=100)
    assert r.timed_out


def test_firecracker_pause_resume_stop_start_destroy(fcenv):
    rt, host, st = fcenv
    s = "abcdef012345"
    rt.create(SandboxSpec(s, mvm())); assert rt.status(s) == "stopped"
    rt.start(s); assert rt.status(s) == "running"
    rt.pause(s); assert rt.status(s) == "paused"
    rt.resume(s); assert rt.status(s) == "running"
    rt.stop(s); assert rt.status(s) == "stopped"
    with pytest.raises(RuntimeError_, match="not running"):
        rt.execute(s, ["ls"], workdir="/workspace", env={}, timeout_s=5, max_output_bytes=100)
    rt.start(s); assert rt.status(s) == "running"  # disks persisted; boots again
    assert "boot line" in rt.logs(s, 5)
    rt.destroy(s, delete_workspace=True)
    assert rt.status(s) == "missing" and not (Path(st.fc_dir) / s).exists()


def test_firecracker_start_failure_kills_vm(fcenv):
    rt, host, _ = fcenv
    host.fail.add("/boot-source")
    rt.create(SandboxSpec("abcdef012345", mvm()))
    with pytest.raises(RuntimeError_, match="boot-source"):
        rt.start("abcdef012345")
    assert host.up is False


def test_firecracker_refusals(fcenv):
    rt, *_ = fcenv
    from cerebrum_sandbox.policy import NetworkPolicy
    allow = mvm(network=NetworkPolicy(mode="allowlist", allowed_domains=["pypi.org"]))
    for prof, msg in ((allow, "no network device"), (mvm(gpus=1), "GPU"), (BUILTIN["basic"], "only runs 'microvm'"),
                      (mvm(env={"bad key": "x"}), "environment variable")):
        with pytest.raises(RuntimeError_, match=msg):
            rt.create(SandboxSpec("abcdef012345", prof))
    with pytest.raises(RuntimeError_, match="invalid sandbox id"):
        rt.create(SandboxSpec("../../etc", mvm()))


def test_firecracker_reports_missing_prereqs_honestly(tmp_path):
    rt = FirecrackerRuntime(Settings(fc_dir=str(tmp_path), fc_bin="definitely-not-installed"))
    h = rt.health()
    assert h["ok"] is False and "not found" in h["detail"] and "SANDBOX_FC_KERNEL" in h["detail"]
    with pytest.raises(RuntimeError_, match="firecracker unavailable"):
        rt.create(SandboxSpec("abcdef012345", mvm()))


def test_firecracker_through_controller_api(fcenv, tmp_path):
    rt, host, st = fcenv
    c = mk(big(tmp_path), {"docker": FakeRuntime(), "firecracker": rt})
    r = c.post("/api/v1/sandboxes", json={"profile": "basic", "isolation": "microvm"}, headers=OP)
    assert r.status_code == 201 and r.json()["runtime"] == "firecracker"
    sid = r.json()["id"]
    out = c.post(f"/api/v1/sandboxes/{sid}/execute", json={"argv": ["echo", "vm"]}, headers=OP).json()
    assert out["stdout"] == "vm\n" and out["status"] == "ok"
    assert c.post(f"/api/v1/sandboxes/{sid}/pause", headers=OP).json()["state"] == "paused"
    assert c.delete(f"/api/v1/sandboxes/{sid}", headers=OP).json()["state"] == "terminated"


# ============================ workers (fleet) ============================
def make_fleet(tmp_path, worker_gpus=None, **master_kw):
    wrt = FakeRuntime()
    wst = Settings(data_dir=tmp_path / "w", admin_key="wadm", operator_key="wop12345", viewer_key="wvw",
                   max_sandboxes=10, max_total_cpu=32, max_total_memory_mb=65536, max_gpu_sandboxes=4)
    wapp = create_app(wst, runtimes={"docker": wrt}, gpu_detector=(lambda: worker_gpus or []))
    state = {"up": True}

    def factory(url):
        if not state["up"]:
            import httpx
            return httpx.Client(base_url=url, transport=httpx.MockTransport(
                lambda req: (_ for _ in ()).throw(httpx.ConnectError("down"))))
        return TestClient(wapp, base_url=url)
    mst = big(tmp_path / "m", **master_kw)
    mapp = create_app(mst, runtimes={"docker": FakeRuntime()}, http_factory=factory, gpu_detector=lambda: [])
    return TestClient(mapp), TestClient(wapp), wrt, state, mapp.state.controller


W = {"name": "w1", "url": "http://10.0.0.5:8300", "key": "wop12345"}


def test_worker_registration_security(tmp_path):
    m, *_ = make_fleet(tmp_path)
    assert m.post("/api/v1/workers", json=W, headers=OP).status_code == 403
    r = m.post("/api/v1/workers", json=W, headers=ADM)
    assert r.status_code == 201 and "key" not in r.json() and r.json()["caps"]["runtimes"] == ["docker"]
    assert "wop12345" not in m.get("/api/v1/workers", headers=VW).text
    assert m.post("/api/v1/workers", json=W, headers=ADM).status_code == 409
    for bad in ({"url": "http://169.254.169.254/"}, {"url": "http://metadata.google.internal"},
                {"url": "file:///etc/passwd"}, {"url": "http://u:p@10.0.0.5"}, {"name": "local"}):
        assert m.post("/api/v1/workers", json={**W, "name": "w2", **bad}, headers=ADM).status_code == 422


def test_worker_wrong_key_or_down_is_refused(tmp_path):
    m, _w, _wrt, state, _ = make_fleet(tmp_path)
    assert m.post("/api/v1/workers", json={**W, "key": "wrongkey123"}, headers=ADM).status_code == 502
    state["up"] = False
    assert m.post("/api/v1/workers", json=W, headers=ADM).status_code == 502


def test_sandbox_runs_on_worker_end_to_end(tmp_path):
    m, w, wrt, _, _ = make_fleet(tmp_path)
    m.post("/api/v1/workers", json=W, headers=ADM)
    r = m.post("/api/v1/sandboxes", json={"profile": "basic", "worker": "w1"}, headers=OP)
    assert r.status_code == 201 and r.json()["worker"] == "w1"
    sid = r.json()["id"]
    assert w.get(f"/api/v1/sandboxes/{sid}", headers={"Authorization": "Bearer wvw"}).json()["state"] == "running"
    assert sid in wrt.boxes                               # same id on both sides
    out = m.post(f"/api/v1/sandboxes/{sid}/execute", json={"argv": ["echo"]}, headers=OP).json()
    assert out["status"] == "ok" and wrt.calls[-1][0] == sid
    assert m.post(f"/api/v1/sandboxes/{sid}/pause", headers=OP).json()["state"] == "paused"
    assert wrt.boxes[sid] == "paused"
    assert m.post(f"/api/v1/sandboxes/{sid}/resume", headers=OP).json()["state"] == "running"
    assert "REDACTED" in m.get(f"/api/v1/sandboxes/{sid}/logs", headers=VW).json()["logs"]
    assert m.delete(f"/api/v1/workers/w1", headers=ADM).status_code == 409   # still has a sandbox
    assert m.delete(f"/api/v1/sandboxes/{sid}", headers=OP).json()["state"] == "terminated"
    assert sid not in wrt.boxes
    assert m.delete("/api/v1/workers/w1", headers=ADM).status_code == 204


def test_overflow_goes_to_worker_when_local_full(tmp_path):
    m, *_ = make_fleet(tmp_path, max_sandboxes=1)
    m.post("/api/v1/workers", json=W, headers=ADM)
    where = [m.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["worker"] for _ in range(3)]
    assert where[0] == "local" and where[1:] == ["w1", "w1"]


def test_gpu_worker_end_to_end(tmp_path):
    m, w, wrt, _, _ = make_fleet(tmp_path, worker_gpus=[{"index": 0}, {"index": 1}])
    assert m.post("/api/v1/workers", json=W, headers=ADM).json()["caps"]["gpus"] == 2
    # the master itself has no GPU: training can only land on the GPU worker
    r = m.post("/api/v1/sandboxes", json={"profile": "training"}, headers=OP)
    assert r.status_code == 201 and r.json()["worker"] == "w1"
    assert wrt.specs[r.json()["id"]].gpu_indices == [0]   # the worker allocated its own device


def test_unreachable_worker_marked_offline_and_state_kept(tmp_path):
    m, _w, _wrt, state, ctl = make_fleet(tmp_path)
    m.post("/api/v1/workers", json=W, headers=ADM)
    sid = m.post("/api/v1/sandboxes", json={"profile": "basic", "worker": "w1"}, headers=OP).json()["id"]
    state["up"] = False
    ws = m.get("/api/v1/workers?refresh=true", headers=VW).json()
    assert ws[0]["state"] == "offline" and ws[0]["last_error"]
    assert m.post("/api/v1/sandboxes", json={"profile": "basic", "worker": "w1"}, headers=OP).status_code == 422
    assert ctl.recover().get("unreachable") == 1                       # not failed just because the worker is down
    assert m.get(f"/api/v1/sandboxes/{sid}", headers=VW).json()["state"] == "running"
    state["up"] = True
    assert m.get("/api/v1/workers?refresh=true", headers=VW).json()[0]["state"] == "online"


def test_client_chosen_id_validated(tmp_path):
    m, *_ = make_fleet(tmp_path)
    assert m.post("/api/v1/sandboxes", json={"profile": "basic", "id": "../../x"}, headers=OP).status_code == 422
    ok = m.post("/api/v1/sandboxes", json={"profile": "basic", "id": "abcdef012345"}, headers=OP)
    assert ok.status_code == 201
    assert m.post("/api/v1/sandboxes", json={"profile": "basic", "id": "abcdef012345"}, headers=OP).status_code == 409


# ============================ persistence ============================
def test_old_database_is_migrated(tmp_path):
    import sqlite3
    db = sqlite3.connect(tmp_path / "sandbox.db")
    db.executescript("""CREATE TABLE sandboxes (id TEXT PRIMARY KEY, owner TEXT NOT NULL, profile TEXT NOT NULL,
      profile_json TEXT NOT NULL, state TEXT NOT NULL, runtime TEXT NOT NULL, error TEXT, created_at REAL NOT NULL,
      updated_at REAL NOT NULL, expires_at REAL);
      INSERT INTO sandboxes VALUES ('abcdef012345','o','basic','{}','terminated','docker',NULL,1,1,NULL);""")
    db.commit(); db.close()
    from cerebrum_sandbox.store import Store
    row = Store(tmp_path).q("SELECT worker, gpu_indices FROM sandboxes")[0]
    assert (row["worker"], row["gpu_indices"]) == ("local", "[]")
    assert oct((tmp_path / "sandbox.db").stat().st_mode & 0o777) == "0o600"


def test_health_lists_all_runtimes_and_keeps_old_shape(tmp_path):
    c = mk(big(tmp_path), {"docker": FakeRuntime(), "gvisor": FakeRuntime()})
    h = c.get("/health").json()
    assert h["runtime"]["ok"] is True and len(h["runtimes"]) == 2
    assert {r["name"] for r in c.get("/api/v1/runtimes", headers=VW).json()} == {"docker", "gvisor"}
