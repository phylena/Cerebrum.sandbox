import base64
import time

from fastapi.testclient import TestClient

from cerebrum_sandbox.api.app import create_app
from cerebrum_sandbox.settings import Settings
from conftest import ADM, OP, VW, FakeRuntime


def app(tmp_path, **kw):
    st = Settings(data_dir=tmp_path, admin_key="adm", operator_key="op", viewer_key="vw", max_sandboxes=10,
                  max_total_cpu=32, max_total_memory_mb=65536, **kw)
    rt = FakeRuntime()
    return TestClient(create_app(st, runtimes={"docker": rt})), rt


def new(c, profile="basic", h=OP):
    return c.post("/api/v1/sandboxes", json={"profile": profile}, headers=h).json()["id"]


# ---- files ----
def test_upload_download_list_delete(tmp_path):
    c, rt = app(tmp_path)
    sid = new(c)
    data = bytes(range(256))
    r = c.post(f"/api/v1/sandboxes/{sid}/files/upload?path=src/a.bin", content=data, headers=OP)
    assert r.status_code == 201 and r.json()["bytes"] == 256
    d = c.get(f"/api/v1/sandboxes/{sid}/files/download?path=/workspace/src/a.bin", headers=VW)
    assert d.content == data and "a.bin" in d.headers["content-disposition"]
    assert c.get(f"/api/v1/sandboxes/{sid}/files", headers=VW).json()[0]["name"] == "a.bin"
    assert c.post(f"/api/v1/sandboxes/{sid}/files/upload?path=x", content=b"1", headers=VW).status_code == 403
    assert c.delete(f"/api/v1/sandboxes/{sid}/files?path=src/a.bin", headers=OP).json()["ok"]
    assert c.get(f"/api/v1/sandboxes/{sid}/files/download?path=src/a.bin", headers=VW).status_code == 404


def test_file_path_confinement_and_limits(tmp_path):
    c, _ = app(tmp_path, max_file_bytes=100)
    sid = new(c)
    for bad in ("/etc/passwd", "../../etc/passwd", "/workspace/../root/x"):
        assert c.post(f"/api/v1/sandboxes/{sid}/files/upload?path={bad}", content=b"x", headers=OP).status_code == 422
    assert c.post(f"/api/v1/sandboxes/{sid}/files/upload?path=big", content=b"x" * 101, headers=OP).status_code == 413
    c.post(f"/api/v1/sandboxes/{sid}/stop", headers=OP)
    assert c.post(f"/api/v1/sandboxes/{sid}/files/upload?path=a", content=b"x", headers=OP).status_code == 409


def test_persistent_workspace_quota(tmp_path):
    c, rt = app(tmp_path)
    c.post("/api/v1/profiles", json={"name": "tiny", "persistent_workspace": True, "workspace_mb": 16}, headers=ADM)
    sid = new(c, "tiny")
    assert c.post(f"/api/v1/sandboxes/{sid}/files/upload?path=a", content=b"x" * (10 * 2**20), headers=OP).status_code == 201
    r = c.post(f"/api/v1/sandboxes/{sid}/files/upload?path=b", content=b"x" * (7 * 2**20), headers=OP)
    assert r.status_code == 507 and "quota" in r.json()["detail"]
    w = c.get(f"/api/v1/sandboxes/{sid}/workspace", headers=VW).json()
    assert w["used_bytes"] == 10 * 2**20 and w["quota_bytes"] == 16 * 2**20 and w["persistent"]
    # data written behind the API's back (e.g. by a command) is caught by the periodic scan
    rt.files[(sid, "/workspace/sneaky")] = b"x" * (8 * 2**20)
    ctl = c.app.state.controller
    assert ctl.enforce_quotas() == [sid]
    assert c.get(f"/api/v1/sandboxes/{sid}", headers=VW).json()["state"] == "stopped"
    assert any(a["action"] == "security.quota_exceeded" for a in c.get("/api/v1/audit", headers=ADM).json())


def test_kill_processes_and_stdin(tmp_path):
    c, rt = app(tmp_path)
    sid = new(c)
    assert c.post(f"/api/v1/sandboxes/{sid}/processes/kill", headers=OP).json()["ok"]
    assert rt.calls[-1] == (sid, "kill")
    ok = c.post(f"/api/v1/sandboxes/{sid}/execute", json={"argv": ["cat"], "stdin_b64": base64.b64encode(b"hi").decode()},
                headers=OP)
    assert ok.status_code == 200
    assert c.post(f"/api/v1/sandboxes/{sid}/execute", json={"argv": ["cat"], "stdin_b64": "!!notb64"},
                  headers=OP).status_code == 422


# ---- scoped keys / tenant isolation ----
def mkkey(c, **kw):
    r = c.post("/api/v1/keys", json={"name": kw.pop("name", "k1"), **kw}, headers=ADM)
    assert r.status_code == 201, r.text
    return r.json()


def test_scoped_keys_isolate_tenants(tmp_path):
    c, _ = app(tmp_path)
    a = {"Authorization": "Bearer " + mkkey(c, name="alice", owner="alice")["key"]}
    b = {"Authorization": "Bearer " + mkkey(c, name="bob", owner="bob")["key"]}
    sa = c.post("/api/v1/sandboxes", json={"profile": "basic", "owner": "bob"}, headers=a).json()
    assert sa["owner"] == "alice"                                       # cannot create for someone else
    sb = new(c, h=b)
    assert [s["id"] for s in c.get("/api/v1/sandboxes", headers=a).json()] == [sa["id"]]
    for method, path in (("get", ""), ("post", "/stop"), ("delete", ""), ("get", "/logs"), ("get", "/files")):
        assert getattr(c, method)(f"/api/v1/sandboxes/{sb}{path}", headers=a).status_code == 404
    assert c.post(f"/api/v1/sandboxes/{sb}/execute", json={"argv": ["id"]}, headers=a).status_code == 404
    assert len(c.get("/api/v1/sandboxes", headers=OP).json()) == 2     # unscoped operator sees all
    assert c.get("/api/v1/audit", headers=a).status_code == 403


def test_key_lifecycle_hash_only_revoke_expire(tmp_path):
    c, _ = app(tmp_path)
    k = mkkey(c, name="tmp", role="viewer", ttl_s=60)
    h = {"Authorization": "Bearer " + k["key"]}
    assert c.get("/api/v1/sandboxes", headers=h).status_code == 200
    assert c.post("/api/v1/sandboxes", json={}, headers=h).status_code == 403   # viewer
    store = c.app.state.store
    assert k["key"] not in str([dict(r) for r in store.q("SELECT * FROM api_keys")])  # only the hash
    assert "key" not in c.get("/api/v1/keys", headers=ADM).json()[0]
    store.x("UPDATE api_keys SET expires_at=? WHERE id=?", (time.time() - 1, k["id"]))
    assert c.get("/api/v1/sandboxes", headers=h).status_code == 401
    k2 = mkkey(c, name="rev")
    h2 = {"Authorization": "Bearer " + k2["key"]}
    assert c.delete(f"/api/v1/keys/{k2['id']}", headers=ADM).json()["ok"]
    assert c.get("/api/v1/sandboxes", headers=h2).status_code == 401
    assert c.post("/api/v1/keys", json={"name": "x", "role": "admin"}, headers=ADM).status_code == 422
    assert c.post("/api/v1/keys", json={"name": "x"}, headers=OP).status_code == 403
