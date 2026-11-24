import pytest
from fastapi.testclient import TestClient

from cerebrum_sandbox.api.app import create_app
from cerebrum_sandbox.runtime import ExecResult, Runtime, RuntimeError_
from cerebrum_sandbox.settings import Settings


class FakeRuntime(Runtime):
    """In-memory runtime. Proves controller/API behaviour, NOT isolation."""
    name = "fake"

    def __init__(self):
        self.boxes: dict[str, str] = {}
        self.fail_create = False
        self.next_exec = ExecResult(0, "hi\n", "")
        self.calls: list = []
        self.specs: dict = {}

    def create(self, spec):
        if self.fail_create:
            raise RuntimeError_("boom")
        self.specs[spec.sandbox_id] = spec
        self.boxes[spec.sandbox_id] = "stopped"

    def start(self, sid): self.boxes[sid] = "running"
    def stop(self, sid): self.boxes[sid] = "stopped"
    def pause(self, sid): self.boxes[sid] = "paused"
    def resume(self, sid): self.boxes[sid] = "running"
    def destroy(self, sid, *, delete_workspace): self.boxes.pop(sid, None)
    def status(self, sid): return self.boxes.get(sid, "missing")
    def logs(self, sid, tail=200): return "token=abcdef123456 started"
    def health(self): return {"runtime": "fake", "ok": True}

    def execute(self, sid, argv, *, workdir, env, timeout_s, max_output_bytes):
        self.calls.append((sid, argv, workdir, env, timeout_s))
        return self.next_exec


@pytest.fixture
def st(tmp_path):
    return Settings(data_dir=tmp_path, admin_key="adm", operator_key="op", viewer_key="vw",
                    max_sandboxes=3, max_total_cpu=2.0, max_total_memory_mb=1024)


@pytest.fixture
def rt():
    return FakeRuntime()


@pytest.fixture
def client(st, rt):
    return TestClient(create_app(st, rt))


OP = {"Authorization": "Bearer op"}
ADM = {"Authorization": "Bearer adm"}
VW = {"Authorization": "Bearer vw"}
