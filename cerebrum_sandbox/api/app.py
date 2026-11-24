"""HTTP API (OpenAPI at /docs). Roles: viewer reads, operator runs sandboxes, admin manages
profiles, workers and keys. Scoped keys only see their own owner's sandboxes."""
import base64
import time
import uuid

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from .. import __version__, settings as settings_mod
from ..auth import Principal, hash_key, new_key, require
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


class ExecuteRequest(BaseModel):
    argv: list[str] = Field(min_length=1, max_length=256)  # an argument vector, never a shell string
    workdir: str | None = None
    env: dict[str, str] = Field(default_factory=dict, max_length=32)
    timeout_s: int | None = Field(None, ge=1)
    stdin_b64: str | None = Field(None, max_length=8 * 2**20)


class RegisterWorker(BaseModel):
    name: str
    url: str
    key: str = Field(min_length=8, description="the worker's operator API key; stored, never returned")


class CreateKey(BaseModel):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{1,63}$")
    role: str = Field("operator", pattern="^(viewer|operator)$")  # admin keys only via environment
    owner: str | None = Field(None, max_length=128, description="scope: only this owner's sandboxes")
    ttl_s: int | None = Field(None, ge=60, le=365 * 86400)


def create_app(st: Settings | None = None, runtime: Runtime | None = None, *,
               runtimes: dict[str, Runtime] | None = None, http_factory=None, gpu_detector=None) -> FastAPI:
    st = st or settings_mod.load()
    store = Store(st.data_dir)
    runtimes = runtimes or ({"docker": runtime} if runtime else build_runtimes(st))
    ctl = Controller(st, store, runtimes, http_factory=http_factory, gpu_detector=gpu_detector)
    keys = lambda: {"admin": st.admin_key, "operator": st.operator_key, "viewer": st.viewer_key}  # noqa: E731
    viewer, operator, admin = (Depends(require(r, keys, store)) for r in ("viewer", "operator", "admin"))

    app = FastAPI(title="Cerebrum.sandbox", version=__version__,
                  description="Isolated execution infrastructure controlled by Cerebrum.")
    app.state.controller, app.state.store, app.state.settings = ctl, store, st

    @app.exception_handler(ControllerError)
    async def _err(_req, e: ControllerError):
        return JSONResponse({"detail": e.message}, status_code=e.status)

    def own(sid: str, p: Principal) -> dict:
        s = ctl.get(sid)
        if not p.may_see(s["owner"]):
            raise HTTPException(404, "Sandbox not found")  # do not reveal other tenants' sandboxes
        return s

    @app.get("/health")
    def health():
        rts = ctl.runtime_status()
        ok = bool(rts) and all(r.get("ok") for r in rts)
        # "runtime" keeps the original shape (first runtime) for existing clients
        return {"status": "ok" if ok else "degraded", "version": __version__,
                "runtime": rts[0] if rts else {"ok": False}, "runtimes": rts}

    # ---- sandboxes ----------------------------------------------------------------
    @app.get("/api/v1/sandboxes")
    def list_sandboxes(state: str | None = Query(None), p: Principal = viewer):
        return [s for s in ctl.list_sandboxes(state) if p.may_see(s["owner"])]

    @app.post("/api/v1/sandboxes", status_code=201)
    def create(body: CreateSandbox, p: Principal = operator):
        owner = p.owner or body.owner  # a scoped key can never create for someone else
        return ctl.create(body.profile, p.name, owner, body.env, body.ttl_s,
                          isolation=body.isolation, worker=body.worker, sandbox_id=body.id)

    @app.get("/api/v1/sandboxes/{sid}")
    def get(sid: str, p: Principal = viewer):
        return own(sid, p)

    for verb in ("start", "stop", "pause", "resume"):
        def make(v):
            def h(sid: str, p: Principal = operator):
                own(sid, p)
                return getattr(ctl, v)(sid, p.name)
            h.__name__ = f"sandbox_{v}"
            return h
        app.post(f"/api/v1/sandboxes/{{sid}}/{verb}")(make(verb))

    @app.delete("/api/v1/sandboxes/{sid}")
    def destroy(sid: str, p: Principal = operator):
        own(sid, p)
        return ctl.destroy(sid, p.name)

    @app.post("/api/v1/sandboxes/{sid}/execute")
    def execute(sid: str, body: ExecuteRequest, p: Principal = operator):
        own(sid, p)
        stdin = None
        if body.stdin_b64 is not None:
            try:
                stdin = base64.b64decode(body.stdin_b64, validate=True)
            except ValueError as e:
                raise HTTPException(422, "stdin_b64 is not valid base64") from e
        return ctl.execute(sid, body.argv, p.name, workdir=body.workdir, env=body.env,
                           timeout_s=body.timeout_s, stdin=stdin)

    @app.get("/api/v1/sandboxes/{sid}/executions")
    def executions(sid: str, limit: int = Query(50, ge=1, le=500), p: Principal = viewer):
        own(sid, p)
        return ctl.executions(sid, limit)

    @app.get("/api/v1/sandboxes/{sid}/logs")
    def logs(sid: str, tail: int = Query(200, ge=1, le=5000), p: Principal = viewer):
        own(sid, p)
        return {"logs": ctl.logs(sid, tail)}

    @app.post("/api/v1/sandboxes/{sid}/processes/kill")
    def kill_processes(sid: str, p: Principal = operator):
        own(sid, p)
        ctl.kill_processes(sid, p.name)
        return {"ok": True}

    # ---- files and workspace ------------------------------------------------------
    @app.post("/api/v1/sandboxes/{sid}/files/upload", status_code=201)
    async def upload(sid: str, request: Request, path: str = Query(...), mode: str = Query("644"),
                     p: Principal = operator):
        own(sid, p)
        size = int(request.headers.get("content-length") or 0)
        if size > st.max_file_bytes:
            raise HTTPException(413, f"file larger than {st.max_file_bytes} bytes")
        data = b""
        async for chunk in request.stream():
            data += chunk
            if len(data) > st.max_file_bytes:
                raise HTTPException(413, f"file larger than {st.max_file_bytes} bytes")
        return ctl.write_file(sid, path, data, p.name, mode=mode)

    @app.get("/api/v1/sandboxes/{sid}/files/download")
    def download(sid: str, path: str = Query(...), p: Principal = viewer):
        own(sid, p)
        data = ctl.read_file(sid, path, p.name)
        name = path.rstrip("/").rsplit("/", 1)[-1].replace('"', "")
        return Response(data, media_type="application/octet-stream",
                        headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @app.get("/api/v1/sandboxes/{sid}/files")
    def list_files(sid: str, path: str = Query("/workspace"), p: Principal = viewer):
        own(sid, p)
        return ctl.list_dir(sid, path)

    @app.delete("/api/v1/sandboxes/{sid}/files")
    def delete_file(sid: str, path: str = Query(...), p: Principal = operator):
        own(sid, p)
        ctl.delete_path(sid, path, p.name)
        return {"ok": True}

    @app.get("/api/v1/sandboxes/{sid}/workspace")
    def workspace(sid: str, p: Principal = viewer):
        own(sid, p)
        return ctl.workspace_info(sid)

    # ---- platform -----------------------------------------------------------------
    @app.get("/api/v1/runtimes")
    def runtimes_(_p: Principal = viewer):
        return ctl.runtime_status()

    @app.get("/api/v1/workers")
    def workers(refresh: bool = Query(False), _p: Principal = viewer):
        return ctl.refresh_workers() if refresh else ctl.workers()

    @app.post("/api/v1/workers", status_code=201)
    def add_worker(body: RegisterWorker, p: Principal = admin):
        return ctl.add_worker(body.name, body.url, body.key, p.name)

    @app.delete("/api/v1/workers/{name}", status_code=204)
    def remove_worker(name: str, p: Principal = admin):
        ctl.remove_worker(name, p.name)

    @app.get("/api/v1/profiles")
    def profiles(_p: Principal = viewer):
        return list(ctl.profiles().values())

    @app.post("/api/v1/profiles", status_code=201)
    def add_profile(body: Profile, p: Principal = admin):
        return ctl.add_profile(body, p.name)

    @app.get("/api/v1/resources")
    def resources(_p: Principal = viewer):
        return {"host": host_resources(st.data_dir, ctl._gpu_detector()), "usage": ctl.usage(),
                "workers": ctl.workers(),
                "limits": {"max_sandboxes": st.max_sandboxes, "max_total_cpu": st.max_total_cpu,
                           "max_total_memory_mb": st.max_total_memory_mb,
                           "max_exec_seconds": st.max_exec_seconds,
                           "max_gpu_sandboxes": st.max_gpu_sandboxes}}

    @app.get("/api/v1/audit")
    def audit(limit: int = Query(100, ge=1, le=1000), _p: Principal = admin):
        return [dict(r) for r in store.q("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]

    # ---- API keys (admin) -----------------------------------------------------------
    @app.post("/api/v1/keys", status_code=201)
    def create_key(body: CreateKey, p: Principal = admin):
        key, kid, now = new_key(), uuid.uuid4().hex[:12], time.time()
        store.x("INSERT INTO api_keys(id,name,role,owner,hash,created_at,expires_at) VALUES (?,?,?,?,?,?,?)",
                (kid, body.name, body.role, body.owner, hash_key(key), now, now + body.ttl_s if body.ttl_s else None))
        store.audit(p.name, "key.create", kid, "ok", {"name": body.name, "role": body.role, "owner": body.owner})
        return {"id": kid, "key": key, "name": body.name, "role": body.role, "owner": body.owner,
                "note": "the key is shown once; only its hash is stored"}

    @app.get("/api/v1/keys")
    def list_keys(_p: Principal = admin):
        return [{k: r[k] for k in ("id", "name", "role", "owner", "created_at", "expires_at", "revoked_at")}
                for r in store.q("SELECT * FROM api_keys ORDER BY created_at DESC")]

    @app.delete("/api/v1/keys/{kid}")
    def revoke_key(kid: str, p: Principal = admin):
        if not store.q("SELECT 1 FROM api_keys WHERE id=?", (kid,)):
            raise HTTPException(404, "key not found")
        store.x("UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (time.time(), kid))
        store.audit(p.name, "key.revoke", kid, "ok")
        return {"ok": True}

    return app
