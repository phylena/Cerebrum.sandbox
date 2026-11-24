"""HTTP API (OpenAPI at /docs). Roles: viewer reads, operator runs sandboxes, admin manages profiles."""
from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from .. import __version__, settings as settings_mod
from ..auth import require
from ..controller import Controller, ControllerError
from ..profiles import Profile
from ..resources import host_resources
from ..runtime import Runtime
from ..runtime.docker import DockerRuntime
from ..settings import Settings
from ..store import Store


class CreateSandbox(BaseModel):
    profile: str = "basic"
    owner: str | None = Field(None, max_length=128)
    env: dict[str, str] = Field(default_factory=dict, max_length=32)
    ttl_s: int | None = Field(None, ge=10, le=7 * 86400)


class ExecuteRequest(BaseModel):
    argv: list[str] = Field(min_length=1, max_length=256)  # an argument vector, never a shell string
    workdir: str | None = None
    env: dict[str, str] = Field(default_factory=dict, max_length=32)
    timeout_s: int | None = Field(None, ge=1)


def create_app(st: Settings | None = None, runtime: Runtime | None = None) -> FastAPI:
    st = st or settings_mod.load()
    store = Store(st.data_dir)
    runtime = runtime or DockerRuntime(st)
    ctl = Controller(st, store, runtime)
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
        rt = runtime.health()
        return {"status": "ok" if rt.get("ok") else "degraded", "version": __version__, "runtime": rt}

    @app.get("/api/v1/sandboxes")
    def list_sandboxes(state: str | None = Query(None), _r=viewer):
        return ctl.list_sandboxes(state)

    @app.post("/api/v1/sandboxes", status_code=201)
    def create(body: CreateSandbox, role: str = operator):
        return ctl.create(body.profile, actor(role), body.owner, body.env, body.ttl_s)

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

    @app.get("/api/v1/profiles")
    def profiles(_r=viewer):
        return list(ctl.profiles().values())

    @app.post("/api/v1/profiles", status_code=201)
    def add_profile(body: Profile, role: str = admin):
        return ctl.add_profile(body, actor(role))

    @app.get("/api/v1/resources")
    def resources(_r=viewer):
        return {"host": host_resources(st.data_dir), "usage": ctl.usage(),
                "limits": {"max_sandboxes": st.max_sandboxes, "max_total_cpu": st.max_total_cpu,
                           "max_total_memory_mb": st.max_total_memory_mb,
                           "max_exec_seconds": st.max_exec_seconds}}

    @app.get("/api/v1/audit")
    def audit(limit: int = Query(100, ge=1, le=1000), _r=admin):
        return [dict(r) for r in store.q("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]

    return app
