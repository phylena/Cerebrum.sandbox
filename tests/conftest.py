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
        self.files = {}

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

    # in-memory files (the real implementations are exercised live in test_docker_live.py)
    files: dict = {}

    def write_file(self, sid, path, data, *, mode="644"):
        from cerebrum_sandbox.runtime.base import safe_path
        self.files[(sid, safe_path(path))] = data

    def read_file(self, sid, path, *, max_bytes):
        from cerebrum_sandbox.runtime.base import safe_path
        d = self.files.get((sid, safe_path(path)))
        if d is None:
            raise RuntimeError_("read failed: not a regular file")
        if len(d) > max_bytes:
            raise RuntimeError_(f"read failed: too large: {len(d)} bytes")
        return d

    def list_dir(self, sid, path, *, limit=1000):
        return [{"name": p.rsplit("/", 1)[-1], "type": "file", "size": len(d), "mtime": 0.0}
                for (s, p), d in self.files.items() if s == sid]

    def delete_path(self, sid, path):
        from cerebrum_sandbox.runtime.base import safe_path
        self.files.pop((sid, safe_path(path)), None)

    def workspace_usage_bytes(self, sid):
        return sum(len(d) for (s, _), d in self.files.items() if s == sid)

    def export_workspace(self, sid, *, max_bytes):
        import json as _j
        blob = _j.dumps({p: d.decode("latin-1") for (s, p), d in self.files.items() if s == sid}).encode()
        if len(blob) > max_bytes:
            raise RuntimeError_("snapshot failed: workspace larger than the snapshot limit")
        return blob

    def import_workspace(self, sid, tar, *, clear):
        import json as _j
        if clear:
            self.files = {k: v for k, v in self.files.items() if k[0] != sid}
        for p, d in _j.loads(tar).items():
            self.files[(sid, p)] = d.encode("latin-1")

    def kill_processes(self, sid):
        self.calls.append((sid, "kill"))

    def execute(self, sid, argv, *, workdir, env, timeout_s, max_output_bytes, stdin=None):
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
