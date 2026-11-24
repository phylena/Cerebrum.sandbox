"""HTTP API (OpenAPI at /docs). Roles: viewer reads, operator runs sandboxes, admin manages profiles."""
from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from .. import __version__, settings as settings_mod
from ..auth import require
from ..controller import Controller, ControllerError
from ..profiles import Profile
from ..resources import host_resources
from ..runtime import Runtime
from ..runtime.registry import build_runtimes
from ..settings import Settings
from ..store import Store


class CreateSandbox(BaseModel):
    profile: str = "basic"
    owner: str | None = Field(None, max_length=128)
    env: dict[str, str] = Field(default_factory=dict, max_length=32)
    ttl_s: int | None = Field(None, ge=10, le=7 * 86400)
    # Optional and additive (existing clients are unaffected):
    isolation: str | None = Field(None, description="container | gvisor | microvm; may only strengthen the profile")
    worker: str | None = Field(None, description="pin to a registered worker (or 'local')")
    id: str | None = Field(None, description="client-chosen 12-hex id (used by the master when it forwards to a worker)")


class RegisterWorker(BaseModel):
    name: str
    url: str
    key: str = Field(min_length=8, description="the worker's operator API key; stored, never returned")


class ExecuteRequest(BaseModel):
    argv: list[str] = Field(min_length=1, max_length=256)  # an argument vector, never a shell string
    workdir: str | None = None
    env: dict[str, str] = Field(default_factory=dict, max_length=32)
    timeout_s: int | None = Field(None, ge=1)


def create_app(st: Settings | None = None, runtime: Runtime | None = None, *,
               runtimes: dict[str, Runtime] | None = None, http_factory=None, gpu_detector=None) -> FastAPI:
    st = st or settings_mod.load()
    store = Store(st.data_dir)
    runtimes = runtimes or ({"docker": runtime} if runtime else build_runtimes(st))
    ctl = Controller(st, store, runtimes, http_factory=http_factory, gpu_detector=gpu_detector)
    keys = lambda: {"admin": st.admin_key, "operator": st.operator_key, "viewer": st.viewer_key}  # noqa: E731
    viewer, operator, admin = (Depends(require(r, keys)) for r in ("viewer", "operator", "admin"))

    app = FastAPI(title="Cerebrum.sandbox", version=__version__,
                  description="Isolated execution infrastructure controlled by Cerebrum.")
    app.state.controller = ctl

    @app.exception_handler(ControllerError)
    async def _err(_req, e: ControllerError):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": e.message}, status_code=e.status)

    def actor(role: str) -> str:
        return role

    @app.get("/health")
    def health():
        rts = ctl.runtime_status()
        ok = bool(rts) and all(r.get("ok") for r in rts)
        # "runtime" keeps the original shape (first runtime) for existing clients
        return {"status": "ok" if ok else "degraded", "version": __version__,
                "runtime": rts[0] if rts else {"ok": False}, "runtimes": rts}

    @app.get("/api/v1/sandboxes")
    def list_sandboxes(state: str | None = Query(None), _r=viewer):
        return ctl.list_sandboxes(state)

    @app.post("/api/v1/sandboxes", status_code=201)
    def create(body: CreateSandbox, role: str = operator):
        return ctl.create(body.profile, actor(role), body.owner, body.env, body.ttl_s,
                          isolation=body.isolation, worker=body.worker, sandbox_id=body.id)

    @app.get("/api/v1/sandboxes/{sid}")
    def get(sid: str, _r=viewer):
        return ctl.get(sid)

    for verb in ("start", "stop", "pause", "resume"):
        def make(v):
            def h(sid: str, role: str = operator):
                return getattr(ctl, v)(sid, actor(role))
            return h
        app.post(f"/api/v1/sandboxes/{{sid}}/{verb}")(make(verb))

    @app.delete("/api/v1/sandboxes/{sid}")
    def destroy(sid: str, role: str = operator):
        return ctl.destroy(sid, actor(role))

    @app.post("/api/v1/sandboxes/{sid}/execute")
    def execute(sid: str, body: ExecuteRequest, role: str = operator):
        return ctl.execute(sid, body.argv, actor(role), workdir=body.workdir, env=body.env,
                           timeout_s=body.timeout_s)

    @app.get("/api/v1/sandboxes/{sid}/executions")
    def executions(sid: str, limit: int = Query(50, ge=1, le=500), _r=viewer):
        return ctl.executions(sid, limit)

    @app.get("/api/v1/sandboxes/{sid}/logs")
    def logs(sid: str, tail: int = Query(200, ge=1, le=5000), _r=viewer):
        return {"logs": ctl.logs(sid, tail)}

    @app.get("/api/v1/runtimes")
    def runtimes_(_r=viewer):
        return ctl.runtime_status()

    @app.get("/api/v1/workers")
    def workers(refresh: bool = Query(False), _r=viewer):
        return ctl.refresh_workers() if refresh else ctl.workers()

    @app.post("/api/v1/workers", status_code=201)
    def add_worker(body: RegisterWorker, role: str = admin):
        return ctl.add_worker(body.name, body.url, body.key, actor(role))

    @app.delete("/api/v1/workers/{name}", status_code=204)
    def remove_worker(name: str, role: str = admin):
        ctl.remove_worker(name, actor(role))

    @app.get("/api/v1/profiles")
    def profiles(_r=viewer):
        return list(ctl.profiles().values())

    @app.post("/api/v1/profiles", status_code=201)
    def add_profile(body: Profile, role: str = admin):
        return ctl.add_profile(body, actor(role))

    @app.get("/api/v1/resources")
    def resources(_r=viewer):
        return {"host": host_resources(st.data_dir, ctl._gpu_detector()), "usage": ctl.usage(),
                "workers": ctl.workers(),
                "limits": {"max_sandboxes": st.max_sandboxes, "max_total_cpu": st.max_total_cpu,
                           "max_total_memory_mb": st.max_total_memory_mb,
                           "max_exec_seconds": st.max_exec_seconds,
                           "max_gpu_sandboxes": st.max_gpu_sandboxes}}

    @app.get("/api/v1/audit")
    def audit(limit: int = Query(100, ge=1, le=1000), _r=admin):
        return [dict(r) for r in store.q("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]

    return app
