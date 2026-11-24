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


class GitClone(BaseModel):
    url: str
    branch: str | None = None
    depth: int = Field(1, ge=1, le=1000)
    dest: str | None = None
    credential_lease: str | None = Field(None, description="lease id from POST /sandboxes/{id}/leases")


class GitBranch(BaseModel):
    name: str
    start: str | None = None
    repo: str | None = None


class GitCheckout(BaseModel):
    ref: str
    repo: str | None = None


class GitCommit(BaseModel):
    message: str = Field(min_length=1, max_length=10000)
    all: bool = True
    repo: str | None = None


class AddCredential(BaseModel):
    name: str
    kind: str = Field(description="token | github_app")
    secret: str = Field(min_length=8, description="write-only; never returned")
    hosts: list[str] = Field(default_factory=lambda: ["github.com"])
    scopes: list[str] = Field(default_factory=lambda: ["git:clone"])
    max_ttl_s: int = 3600


class LeaseRequest(BaseModel):
    credential_id: str
    scope: str = "git:clone"
    ttl_s: int = Field(600, ge=30, le=86400)


def create_app(st: Settings | None = None, runtime: Runtime | None = None, *,
               runtimes: dict[str, Runtime] | None = None, http_factory=None, gpu_detector=None,
               egress=None) -> FastAPI:
    st = st or settings_mod.load()
    store = Store(st.data_dir)
    if egress is None and st.egress_enabled:
        from ..egress import EgressProxy, ensure_network
        gateway = ensure_network(st.docker_bin, st.egress_network_name, st.egress_subnet)
        st.egress_network, st.egress_proxy_url = st.egress_network_name, f"http://{gateway}:{st.egress_port}"
        egress = EgressProxy(store, gateway, st.egress_port, upstream=st.egress_upstream_proxy or None)
        egress.start()
    runtimes = runtimes or ({"docker": runtime} if runtime else build_runtimes(st))
    ctl = Controller(st, store, runtimes, http_factory=http_factory, gpu_detector=gpu_detector)
    ctl.egress = egress
    if egress:
        ctl.recover()  # re-register policies of sandboxes that survived a restart
    keys = lambda: {"admin": st.admin_key, "operator": st.operator_key, "viewer": st.viewer_key}  # noqa: E731
    viewer, operator, admin = (Depends(require(r, keys, store)) for r in ("viewer", "operator", "admin"))

    app = FastAPI(title="Cerebrum.sandbox", version=__version__,
                  description="Isolated execution infrastructure controlled by Cerebrum.")
    app.state.controller, app.state.store, app.state.settings = ctl, store, st

    from ..broker import BrokerError

    @app.exception_handler(BrokerError)
    async def _berr(_req, e: BrokerError):
        return JSONResponse({"detail": e.message}, status_code=e.status)

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

    @app.get("/api/v1/sandboxes/{sid}/network")
    def sandbox_network(sid: str, limit: int = Query(200, ge=1, le=5000), p: Principal = viewer):
        s = own(sid, p)
        return {"policy": s["profile_snapshot"]["network"], "log": ctl.network_log(sid, limit)}

    @app.get("/api/v1/network/log")
    def network_log(limit: int = Query(200, ge=1, le=5000), decision: str | None = Query(None),
                    _p: Principal = admin):
        return {"stats": vars(ctl.egress.stats) if ctl.egress else None,
                "log": ctl.network_log(None, limit, decision)}

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

    # ---- git ----------------------------------------------------------------------
    @app.post("/api/v1/sandboxes/{sid}/git/clone", status_code=201)
    def git_clone(sid: str, body: GitClone, p: Principal = operator):
        own(sid, p)
        return ctl.git_clone(sid, p.name, body.url, branch=body.branch, depth=body.depth, dest=body.dest,
                             lease=body.credential_lease)

    @app.post("/api/v1/sandboxes/{sid}/git/branch")
    def git_branch(sid: str, body: GitBranch, p: Principal = operator):
        own(sid, p)
        return ctl.git(sid, p.name, "create_branch", body.repo, name=body.name, start=body.start)

    @app.post("/api/v1/sandboxes/{sid}/git/checkout")
    def git_checkout(sid: str, body: GitCheckout, p: Principal = operator):
        own(sid, p)
        return ctl.git(sid, p.name, "checkout", body.repo, ref=body.ref)

    @app.get("/api/v1/sandboxes/{sid}/git/status")
    def git_status(sid: str, repo: str | None = None, p: Principal = viewer):
        own(sid, p)
        return ctl.git(sid, p.name, "status", repo)

    @app.get("/api/v1/sandboxes/{sid}/git/branches")
    def git_branches(sid: str, repo: str | None = None, p: Principal = viewer):
        own(sid, p)
        return ctl.git(sid, p.name, "branches", repo)

    @app.get("/api/v1/sandboxes/{sid}/git/diff")
    def git_diff(sid: str, repo: str | None = None, staged: bool = False, base: str | None = None,
                 stat: bool = False, p: Principal = viewer):
        own(sid, p)
        return {"diff": ctl.git(sid, p.name, "diff", repo, staged=staged, base=base, stat=stat)}

    @app.post("/api/v1/sandboxes/{sid}/git/commit")
    def git_commit(sid: str, body: GitCommit, p: Principal = operator):
        own(sid, p)
        return ctl.git(sid, p.name, "commit", body.repo, message=body.message, add_all=body.all)

    @app.get("/api/v1/sandboxes/{sid}/git/log")
    def git_log(sid: str, repo: str | None = None, n: int = Query(20, ge=1, le=500), p: Principal = viewer):
        own(sid, p)
        return ctl.git(sid, p.name, "log", repo, n=n)

    @app.get("/api/v1/sandboxes/{sid}/git/report")
    def git_report(sid: str, repo: str | None = None, p: Principal = viewer):
        own(sid, p)
        return ctl.git_report(sid, p.name, repo)

    # ---- credential broker ------------------------------------------------------------
    @app.post("/api/v1/credentials", status_code=201)
    def add_credential(body: AddCredential, p: Principal = admin):
        return ctl.broker.add(body.name, body.kind, body.secret, body.hosts, body.scopes, body.max_ttl_s, p.name)

    @app.get("/api/v1/credentials")
    def list_credentials(_p: Principal = admin):
        return ctl.broker.list_credentials()

    @app.delete("/api/v1/credentials/{cid}")
    def revoke_credential(cid: str, p: Principal = admin):
        ctl.broker.revoke(cid, p.name)
        return {"ok": True}

    @app.post("/api/v1/sandboxes/{sid}/leases", status_code=201)
    def create_lease(sid: str, body: LeaseRequest, p: Principal = operator):
        s = own(sid, p)
        if s["state"] in ("terminated", "failed"):
            raise HTTPException(409, "sandbox is not active")
        return ctl.broker.lease(body.credential_id, sid, body.scope, body.ttl_s, p.name)

    @app.get("/api/v1/sandboxes/{sid}/leases")
    def list_leases(sid: str, p: Principal = viewer):
        own(sid, p)
        return ctl.broker.leases(sid)

    @app.delete("/api/v1/sandboxes/{sid}/leases/{lid}")
    def revoke_lease(sid: str, lid: str, p: Principal = operator):
        own(sid, p)
        if not any(l["id"] == lid for l in ctl.broker.leases(sid)):
            raise HTTPException(404, "lease not found")
        ctl.broker.revoke_lease(lid, p.name)
        return {"ok": True}

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
