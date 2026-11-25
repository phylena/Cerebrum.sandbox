from fastapi.testclient import TestClient

from cerebrum_sandbox.api.app import create_app
from cerebrum_sandbox.client import SandboxClient, SandboxError
from cerebrum_sandbox.settings import Settings
from conftest import FakeRuntime


def test_sdk_roundtrip(tmp_path):
    app = create_app(Settings(data_dir=tmp_path, operator_key="op"), runtimes={"docker": FakeRuntime()})
    sb = SandboxClient("http://x", "op", client=TestClient(app))
    with sb.sandbox("basic") as box:
        box.write("a.txt", b"hello")
        assert box.read("a.txt") == b"hello"
        r = box.run(["echo"], stdin=b"x")
        assert r.ok and r.stdout == "hi\n"
        assert box.info()["state"] == "running"
    assert sb.list_sandboxes("terminated")[0]["id"] == box.id
    job = sb.submit_job(["python3", "x.py"], files={"x.py": b"print(1)"}, outputs=["x.py"])
    app.state.jobs.run_once()
    assert sb.wait_job(job["id"], timeout=5)["state"] == "succeeded"
    try:
        sb.create("nope")
    except SandboxError as e:
        assert e.status == 404
    bad = SandboxClient("http://x", "wrong", client=TestClient(app))
    try:
        bad.list_sandboxes()
    except SandboxError as e:
        assert e.status == 401
