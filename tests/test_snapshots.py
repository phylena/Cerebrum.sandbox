from fastapi.testclient import TestClient

from cerebrum_sandbox.api.app import create_app
from cerebrum_sandbox.settings import Settings
from conftest import ADM, OP, VW, FakeRuntime


def mk(tmp_path, **kw):
    st = Settings(**{**dict(data_dir=tmp_path, admin_key="adm", operator_key="op", viewer_key="vw",
                            max_sandboxes=10, max_total_cpu=32, max_total_memory_mb=65536), **kw})
    rt = FakeRuntime()
    return TestClient(create_app(st, runtimes={"docker": rt})), rt


def test_snapshot_restore_and_retention(tmp_path):
    c, rt = mk(tmp_path, snapshots_per_sandbox=2)
    sid = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["id"]
    c.post(f"/api/v1/sandboxes/{sid}/files/upload?path=a", content=b"v1", headers=OP)
    s1 = c.post(f"/api/v1/sandboxes/{sid}/snapshots", json={"label": "one"}, headers=OP).json()
    c.post(f"/api/v1/sandboxes/{sid}/files/upload?path=a", content=b"v2", headers=OP)
    c.post(f"/api/v1/sandboxes/{sid}/restore", json={"snapshot_id": s1["id"]}, headers=OP)
    assert c.get(f"/api/v1/sandboxes/{sid}/files/download?path=a", headers=VW).content == b"v1"
    for _ in range(2):
        c.post(f"/api/v1/sandboxes/{sid}/snapshots", headers=OP)
    snaps = c.get(f"/api/v1/sandboxes/{sid}/snapshots", headers=VW).json()
    assert len(snaps) == 2 and s1["id"] not in {s["id"] for s in snaps}      # oldest pruned
    assert not (tmp_path / "snapshots" / f"{s1['id']}.tar.gz").exists()


def test_snapshot_integrity_quota_and_tenancy(tmp_path):
    c, rt = mk(tmp_path, snapshot_storage_mb=0)
    sid = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["id"]
    assert c.post(f"/api/v1/sandboxes/{sid}/snapshots", headers=OP).status_code == 507
    c2, _ = mk(tmp_path / "b")
    sid = c2.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["id"]
    snap = c2.post(f"/api/v1/sandboxes/{sid}/snapshots", headers=OP).json()
    f = tmp_path / "b" / "snapshots" / f"{snap['id']}.tar.gz"
    f.write_bytes(f.read_bytes() + b"tamper")
    r = c2.post(f"/api/v1/sandboxes/{sid}/restore", json={"snapshot_id": snap["id"]}, headers=OP)
    assert r.status_code == 500 and "checksum" in r.json()["detail"]
    k = c2.post("/api/v1/keys", json={"name": "tt", "owner": "t"}, headers=ADM).json()["key"]
    h = {"Authorization": f"Bearer {k}"}
    mine = c2.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=h).json()["id"]
    r = c2.post(f"/api/v1/sandboxes/{mine}/restore", json={"snapshot_id": snap["id"]}, headers=h)
    assert r.status_code == 404                                              # someone else's snapshot
    assert c2.delete(f"/api/v1/snapshots/{snap['id']}", headers=h).status_code == 404
    assert c2.get("/api/v1/whoami", headers=h).json() == {"role": "operator", "name": "key:tt", "owner": "t"}
