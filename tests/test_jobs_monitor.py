import base64
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from cerebrum_sandbox.api.app import create_app
from cerebrum_sandbox.runtime import ExecResult
from cerebrum_sandbox.settings import Settings
from conftest import ADM, OP, VW, FakeRuntime


def mk(tmp_path, **kw):
    base = dict(data_dir=tmp_path, admin_key="adm", operator_key="op", viewer_key="vw", max_sandboxes=10,
                max_total_cpu=32, max_total_memory_mb=65536, job_retry_backoff_s=0)
    st = Settings(**{**base, **kw})
    rt = FakeRuntime()
    c = TestClient(create_app(st, runtimes={"docker": rt}))
    return c, rt, c.app.state.jobs


def submit(c, h=OP, **spec):
    r = c.post("/api/v1/jobs", json={"argv": ["python3", "run.py"], **spec}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def job(c, jid, h=VW):
    return c.get(f"/api/v1/jobs/{jid}", headers=h).json()


def test_job_runs_with_inputs_outputs_and_cleans_up(tmp_path):
    c, rt, jobs = mk(tmp_path)
    jid = submit(c, files={"run.py": base64.b64encode(b"print(1)").decode()}, outputs=["run.py", "missing.txt"])
    assert job(c, jid)["state"] == "queued"
    assert jobs.run_once()
    j = job(c, jid)
    assert j["state"] == "succeeded" and j["result"]["stdout"] == "hi\n" and j["attempts"] == 1
    assert base64.b64decode(j["result"]["outputs"]["run.py"]) == b"print(1)"
    assert j["result"]["outputs"]["missing.txt"] is None and "missing.txt" in j["result"]["output_errors"]
    assert rt.boxes == {}                                                      # sandbox destroyed
    assert "files" not in j["spec"]
    assert not jobs.run_once()                                                 # queue empty


def test_priority_then_fifo(tmp_path):
    c, _, jobs = mk(tmp_path)
    low, high, high2 = submit(c, priority=1), submit(c, priority=9), submit(c, priority=9)
    jobs.run_once()
    assert job(c, high)["state"] == "succeeded" and job(c, low)["state"] == "queued" and job(c, high2)["state"] == "queued"
    jobs.run_once()
    assert job(c, high2)["state"] == "succeeded"


def test_concurrency_cap_and_capacity_wait(tmp_path):
    c, _, jobs = mk(tmp_path, max_concurrent_jobs=1)
    a, b = submit(c), submit(c)
    c.app.state.store.x("UPDATE jobs SET state='running' WHERE id=?", (a,))
    assert not jobs.run_once()                                                 # cap reached
    c2, _, jobs2 = mk(tmp_path / "x", max_sandboxes=0)
    j = submit(c2)
    jobs2.run_once()
    d = job(c2, j)
    assert d["state"] == "queued" and "capacity" in d["wait_reason"] and d["attempts"] == 0   # not a failure


def test_infrastructure_retry_then_fail(tmp_path):
    c, rt, jobs = mk(tmp_path)
    rt.fail_create = True
    jid = submit(c, max_retries=1)
    jobs.run_once()
    assert job(c, jid)["state"] == "queued" and "infrastructure" in job(c, jid)["wait_reason"]
    jobs.run_once()
    d = job(c, jid)
    assert d["state"] == "failed" and d["attempts"] == 2
    assert any(e["kind"] == "job_failed" for e in c.get("/api/v1/events", headers=VW).json())


def test_nonzero_exit_retry_only_when_asked(tmp_path):
    c, rt, jobs = mk(tmp_path)
    rt.next_exec = ExecResult(3, "", "boom")
    plain = submit(c)
    jobs.run_once()
    assert job(c, plain)["state"] == "failed" and job(c, plain)["result"]["exit_code"] == 3
    retry = submit(c, retry_on_failure=True, max_retries=1)
    jobs.run_once()
    assert job(c, retry)["state"] == "queued"
    rt.next_exec = ExecResult(0, "ok", "")
    jobs.run_once()
    assert job(c, retry)["state"] == "succeeded" and job(c, retry)["attempts"] == 2


def test_cancel_queued_and_running(tmp_path):
    c, rt, jobs = mk(tmp_path)
    q = submit(c)
    assert c.delete(f"/api/v1/jobs/{q}", headers=OP).json()["state"] == "cancelled"
    assert not jobs.run_once()
    r = submit(c)
    sid = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["id"]
    c.app.state.store.x("UPDATE jobs SET state='running', sandbox_id=? WHERE id=?", (sid, r))
    c.delete(f"/api/v1/jobs/{r}", headers=OP)
    assert sid not in rt.boxes and job(c, r)["cancel_requested"]               # sandbox destroyed


def test_budget_blocks_new_jobs(tmp_path):
    c, _, jobs = mk(tmp_path, job_hours_budget_daily=0)
    jid = submit(c)
    assert not jobs.run_once()
    assert job(c, jid)["state"] == "queued" and "budget" in job(c, jid)["wait_reason"]


def test_recover_requeues_interrupted_jobs(tmp_path):
    c, _, jobs = mk(tmp_path)
    a, b = submit(c, max_retries=1), submit(c, max_retries=0)
    store = c.app.state.store
    store.x("UPDATE jobs SET state='running', attempts=1 WHERE id IN (?,?)", (a, b))
    assert jobs.recover() == 2
    assert job(c, a)["state"] == "queued" and job(c, b)["state"] == "failed"


def test_job_tenancy_and_validation(tmp_path):
    c, _, _ = mk(tmp_path)
    k = c.post("/api/v1/keys", json={"name": "t1", "owner": "t1"}, headers=ADM).json()["key"]
    h = {"Authorization": f"Bearer {k}"}
    mine = submit(c, h=h)
    other = submit(c)
    assert [j["id"] for j in c.get("/api/v1/jobs", headers=h).json()] == [mine]
    assert c.get(f"/api/v1/jobs/{other}", headers=h).status_code == 404
    assert c.post("/api/v1/jobs", json={"argv": ["x"], "profile": "nope"}, headers=OP).status_code == 404
    assert c.post("/api/v1/jobs", json={"argv": ["x"], "files": {"a": "!!"}}, headers=OP).status_code == 422
    assert c.post("/api/v1/jobs", json={"argv": []}, headers=OP).status_code == 422
    assert c.post("/api/v1/jobs", json={"argv": ["x"]}, headers=VW).status_code == 403


def test_background_runner_threads(tmp_path):
    c, _, jobs = mk(tmp_path, max_concurrent_jobs=2)
    ids = [submit(c) for _ in range(4)]
    jobs.start(interval=0.05)
    try:
        deadline = time.time() + 10
        while time.time() < deadline and any(job(c, i)["state"] != "succeeded" for i in ids):
            time.sleep(0.05)
        assert all(job(c, i)["state"] == "succeeded" for i in ids)
    finally:
        jobs.stop()


# ---- events / maintenance / metrics ----
def test_events_dedupe_and_webhook(tmp_path):
    from cerebrum_sandbox.monitor import Events
    from cerebrum_sandbox.store import Store
    posted = []
    ev = Events(Store(tmp_path), "https://hooks.example/x",
                http_factory=lambda: httpx.Client(transport=httpx.MockTransport(
                    lambda r: posted.append(r) or httpx.Response(200))))
    ev.emit("worker_offline", "critical", "w1", "down token=abcdef123456")
    ev.emit("worker_offline", "critical", "w1", "still down")
    ev.emit("worker_offline", "critical", "w2", "down")
    rows = ev.list_events()
    assert {(r["target"], r["count"]) for r in rows} == {("w1", 2), ("w2", 1)}
    assert all("abcdef123456" not in r["message"] for r in rows)
    time.sleep(0.3)
    assert len(posted) == 2                                                      # one per new problem, not per repeat


def test_maintenance_detects_and_cleans(tmp_path):
    c, rt, _ = mk(tmp_path)
    m, store = c.app.state.maintenance, c.app.state.store
    lost = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["id"]
    exp = c.post("/api/v1/sandboxes", json={"profile": "basic", "ttl_s": 10}, headers=OP).json()["id"]
    store.x("UPDATE sandboxes SET expires_at=1 WHERE id=?", (exp,))
    rt.boxes.pop(lost)                                                            # runtime lost it
    store.x("INSERT INTO netlog(ts,sandbox_id,decision,host,port) VALUES (?,?,?,?,?)",
            (time.time(), lost, "denied", "evil.com", 443))
    rt.fail_create = True
    c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP)
    rep = c.post("/api/v1/maintenance/run", headers=ADM).json()
    assert rep["expired"] == [exp] and rep["lost"] == 1 and rep["backup"]
    assert c.get(f"/api/v1/sandboxes/{lost}", headers=VW).json()["state"] == "failed"
    kinds = {e["kind"] for e in c.get("/api/v1/events", headers=VW).json()}
    assert {"sandbox_lost", "network_violation", "sandbox_create_failed"} <= kinds
    assert c.post("/api/v1/maintenance/run", headers=ADM).json()["backup"] is None   # once a day
    assert c.post("/api/v1/maintenance/run", headers=OP).status_code == 403


def test_prometheus_metrics(tmp_path):
    c, _, _ = mk(tmp_path)
    sid = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["id"]
    c.post(f"/api/v1/sandboxes/{sid}/execute", json={"argv": ["true"]}, headers=OP)
    assert c.get("/metrics").status_code == 401
    t = c.get("/metrics", headers=VW).text
    assert 'csb_sandboxes{state="running"} 1' in t and 'csb_executions_total{status="ok"} 1' in t
    assert 'csb_runtime_up{runtime="docker"} 1' in t and "# TYPE csb_jobs gauge" in t
    m = c.get(f"/api/v1/sandboxes/{sid}/metrics", headers=VW).json()
    assert m["limits"]["memory_mb"] == 256 and m["executions"] == {"ok": 1}


def test_events_are_scoped_for_tenant_keys(tmp_path):
    c, rt, _ = mk(tmp_path)
    k = c.post("/api/v1/keys", json={"name": "ten", "owner": "ten"}, headers=ADM).json()["key"]
    h = {"Authorization": f"Bearer {k}"}
    mine = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=h).json()["id"]
    other = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["id"]
    ev = c.app.state.controller.events
    ev.emit("sandbox_lost", "critical", mine, "mine"); ev.emit("sandbox_lost", "critical", other, "theirs")
    ev.emit("resource_exhaustion", "critical", "memory", "host")
    assert [e["target"] for e in c.get("/api/v1/events", headers=h).json()] == [mine]
    assert len(c.get("/api/v1/events", headers=VW).json()) == 3


def test_cleanup_continues_when_one_destroy_fails(tmp_path):
    c, rt, _ = mk(tmp_path)
    ctl, store = c.app.state.controller, c.app.state.store
    a = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["id"]
    b = c.post("/api/v1/sandboxes", json={"profile": "basic"}, headers=OP).json()["id"]
    store.x("UPDATE sandboxes SET expires_at=1")
    from cerebrum_sandbox.runtime import RuntimeError_
    orig = rt.destroy
    rt.destroy = lambda sid, **kw: (_ for _ in ()).throw(RuntimeError_("worker down")) if sid == a else orig(sid, **kw)
    assert ctl.cleanup_expired() == [b]
    assert any(e["kind"] == "cleanup_failed" and e["target"] == a for e in ctl.events.list_events())
