"""The Sandbox Controller: lifecycle, quotas, profiles, execution, audit, recovery."""
import json
import re
import threading
import time
import uuid

from . import lifecycle
from .lifecycle import State
from .profiles import BUILTIN, RANK, RUNTIME_FOR, Isolation, Profile, clamp_check
from .redact import redact
from .resources import detect_gpus
from .runtime import Runtime, RuntimeError_, SandboxSpec
from .runtime.base import safe_path, safe_workdir
from .runtime.remote import RemoteRuntime, validate_worker_url
from .scheduler import Capacity, PlacementError, place
from .settings import Settings
from .store import Store

ACTIVE = (State.PENDING, State.PROVISIONING, State.RUNNING, State.PAUSED, State.STOPPING, State.STOPPED)


class ControllerError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class Controller:
    def __init__(self, st: Settings, store: Store, runtimes: "Runtime | dict[str, Runtime]",
                 http_factory=None, gpu_detector=None):
        self.st, self.store = st, store
        # a bare Runtime is registered as the container runtime (single-runtime setups and tests)
        self.runtimes: dict[str, Runtime] = runtimes if isinstance(runtimes, dict) else {"docker": runtimes}
        self._http_factory = http_factory or self._default_http
        self._gpu_detector = gpu_detector or detect_gpus
        from .broker import Broker
        self.broker = Broker(st, store)
        self.egress = None  # EgressProxy when SANDBOX_EGRESS_ENABLED (set by the app)
        self.git_fetcher = None  # tests may replace host-side cloning; default: git_ops.host_clone
        self._locks: dict[str, threading.Lock] = {}
        self._guard = threading.Lock()  # serialises quota check + insert
        self.recover()

    # ---- profiles ---------------------------------------------------------------
    def profiles(self) -> dict[str, Profile]:
        out = dict(BUILTIN)
        for r in self.store.q("SELECT json FROM profiles"):
            p = Profile.model_validate_json(r["json"])
            out[p.name] = p
        return out

    def add_profile(self, p: Profile, actor: str) -> Profile:
        if p.name in BUILTIN:
            raise ControllerError(409, f"'{p.name}' is a built-in profile and cannot be replaced")
        p = p.model_copy(update={"builtin": False})
        try:
            clamp_check(p, max_cpu=self.st.max_sandbox_cpu, max_memory_mb=self.st.max_sandbox_memory_mb,
                        max_timeout=self.st.max_exec_seconds)
        except ValueError as e:
            raise ControllerError(422, str(e)) from e
        self.store.x("INSERT OR REPLACE INTO profiles(name,json) VALUES (?,?)", (p.name, p.model_dump_json()))
        self.store.audit(actor, "profile.save", p.name, "ok")
        return p

    # ---- queries ----------------------------------------------------------------
    @staticmethod
    def _view(r) -> dict:
        d = dict(r)
        d["profile_snapshot"] = json.loads(d.pop("profile_json"))
        d["gpu_indices"] = json.loads(d["gpu_indices"])
        return d

    def list_sandboxes(self, state: str | None = None) -> list[dict]:
        rows = self.store.q("SELECT * FROM sandboxes" + (" WHERE state=?" if state else "") +
                            " ORDER BY created_at DESC", (state,) if state else ())
        return [self._view(r) for r in rows]

    def get(self, sid: str) -> dict:
        rows = self.store.q("SELECT * FROM sandboxes WHERE id=?", (sid,))
        if not rows:
            raise ControllerError(404, "Sandbox not found")
        return self._view(rows[0])

    def usage(self) -> dict:
        cpu = mem = n = gpus = 0
        by_worker: dict[str, int] = {}
        for s in self.list_sandboxes():
            if s["state"] in ("terminated", "failed"):
                continue
            p = s["profile_snapshot"]
            n += 1; cpu += p["cpu"]; mem += p["memory_mb"]; gpus += len(s["gpu_indices"])
            by_worker[s["worker"]] = by_worker.get(s["worker"], 0) + 1
        return {"sandboxes": n, "cpu": cpu, "memory_mb": mem, "gpus_assigned": gpus, "by_worker": by_worker}

    # ---- runtimes and workers -------------------------------------------------------
    def _default_http(self, url: str):
        import httpx
        return httpx.Client(base_url=url, timeout=self.st.worker_timeout_s)

    def _worker_row(self, name: str):
        rows = self.store.q("SELECT * FROM workers WHERE name=?", (name,))
        if not rows:
            raise RuntimeError_(f"worker '{name}' is not registered")
        return rows[0]

    def _rt(self, s: dict) -> Runtime:
        if s["worker"] == "local":
            rt = self.runtimes.get(s["runtime"])
            if rt is None:
                raise RuntimeError_(f"runtime '{s['runtime']}' is not enabled on this node")
            return rt
        w = self._worker_row(s["worker"])
        return RemoteRuntime(self._http_factory(w["url"]), w["key"])

    def runtime_status(self) -> list[dict]:
        return [{"name": n, "isolation": getattr(r, "isolation", Isolation.CONTAINER).value, **r.health()}
                for n, r in self.runtimes.items()]

    @staticmethod
    def _worker_view(r) -> dict:
        d = dict(r)
        d.pop("key", None)  # never leaves the controller
        d["caps"] = json.loads(d["caps"])
        return d

    def workers(self) -> list[dict]:
        return [self._worker_view(r) for r in self.store.q("SELECT * FROM workers ORDER BY name")]

    def _probe(self, url: str, key: str) -> dict:
        rt = RemoteRuntime(self._http_factory(url), key)
        h = rt.health()
        if not h["ok"]:
            raise RuntimeError_(f"worker is not healthy: {h['detail']}")
        res = rt._req("GET", "/api/v1/resources")
        runtimes = [r["name"] for r in rt._req("GET", "/api/v1/runtimes") if r.get("ok")]
        lim = res["limits"]
        return {"runtimes": runtimes, "cpu": lim["max_total_cpu"], "memory_mb": lim["max_total_memory_mb"],
                "sandboxes": lim["max_sandboxes"], "gpus": len(res["host"].get("gpus", []))}

    def add_worker(self, name: str, url: str, key: str, actor: str) -> dict:
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,39}", name) or name == "local":
            raise ControllerError(422, "worker name: lowercase letters, digits, dashes (2-40), not 'local'")
        try:
            url = validate_worker_url(url)
        except ValueError as e:
            raise ControllerError(422, str(e)) from e
        if len(self.workers()) >= self.st.max_workers:
            raise ControllerError(429, f"Worker limit reached ({self.st.max_workers})")
        if self.store.q("SELECT 1 FROM workers WHERE name=?", (name,)):
            raise ControllerError(409, f"worker '{name}' already exists")
        try:
            caps = self._probe(url, key)
        except RuntimeError_ as e:
            self.store.audit(actor, "worker.add", name, "failed", {"error": str(e)})
            raise ControllerError(502, f"Could not register worker: {e}") from e
        self.store.x("INSERT INTO workers VALUES (?,?,?,?,?,?,?,?,?)",
                     (uuid.uuid4().hex[:12], name, url, key, "online", json.dumps(caps), time.time(), None, time.time()))
        self.store.audit(actor, "worker.add", name, "ok", {"url": url, "caps": caps})
        return self._worker_view(self._worker_row(name))

    def refresh_workers(self) -> list[dict]:
        for w in self.store.q("SELECT * FROM workers"):
            try:
                caps = self._probe(w["url"], w["key"])
                self.store.x("UPDATE workers SET state='online', caps=?, last_seen=?, last_error=NULL WHERE name=?",
                             (json.dumps(caps), time.time(), w["name"]))
            except RuntimeError_ as e:
                self.store.x("UPDATE workers SET state='offline', last_error=? WHERE name=?",
                             (redact(str(e))[:300], w["name"]))
        return self.workers()

    def remove_worker(self, name: str, actor: str) -> None:
        if any(x["worker"] == name and x["state"] not in ("terminated", "failed") for x in self.list_sandboxes()):
            raise ControllerError(409, f"worker '{name}' still has active sandboxes")
        self.store.x("DELETE FROM workers WHERE name=?", (name,))
        self.store.audit(actor, "worker.remove", name, "ok")

    # ---- egress policy registration -------------------------------------------------
    def _egress_register(self, sid: str) -> None:
        if not self.egress:
            return
        s = self.get(sid)
        net = s["profile_snapshot"]["network"]
        if s["worker"] != "local" or net["mode"] != "allowlist":
            return
        ip = self._rt(s).address(sid, self.st.egress_network)
        if not ip:
            raise RuntimeError_("allowlist sandbox has no address on the egress network")
        self.egress.remove_sandbox(sid)
        self.egress.set_policy(ip, sid, net["allowed_domains"], net["allowed_ports"], net.get("log_requests", True))

    def _egress_remove(self, sid: str) -> None:
        if self.egress:
            self.egress.remove_sandbox(sid)

    def network_log(self, sid: str | None = None, limit: int = 200, decision: str | None = None) -> list[dict]:
        where, args = [], []
        if sid:
            where.append("sandbox_id=?"); args.append(sid)
        if decision:
            where.append("decision=?"); args.append(decision)
        q = "SELECT * FROM netlog" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY id DESC LIMIT ?"
        return [dict(r) for r in self.store.q(q, (*args, limit))]

    # ---- lifecycle --------------------------------------------------------------
    def _lock(self, sid: str) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(sid, threading.Lock())

    def _set(self, sid: str, target: State, error: str | None = None) -> None:
        cur = State(self.get(sid)["state"])
        try:
            lifecycle.check(cur, target)
        except lifecycle.InvalidTransition as e:
            raise ControllerError(409, str(e)) from e
        self.store.x("UPDATE sandboxes SET state=?, error=?, updated_at=? WHERE id=?",
                     (target.value, error, time.time(), sid))

    def _effective_isolation(self, profile: Profile, requested: str | None) -> Isolation:
        base = profile.isolation
        if requested:
            try:
                want = Isolation(requested)
            except ValueError as e:
                raise ControllerError(422, f"unknown isolation '{requested}'") from e
            if RANK[want] < RANK[base]:  # an override may only strengthen, never weaken a profile
                raise ControllerError(422, f"isolation '{want}' is weaker than the profile's '{base}'")
            base = want
        try:
            floor = Isolation(self.st.min_isolation)
        except ValueError as e:
            raise ControllerError(500, f"bad SANDBOX_MIN_ISOLATION '{self.st.min_isolation}'") from e
        return base if RANK[base] >= RANK[floor] else floor

    def _local_capacity(self) -> Capacity:
        gpus = sorted(g["index"] for g in self._gpu_detector())
        if self.st.gpu_indices:
            gpus = [i for i in gpus if i in self.st.gpu_indices]
        return Capacity("local", self.st.max_total_cpu, self.st.max_total_memory_mb, self.st.max_sandboxes, gpus)

    def _options(self, runtime_name: str, need_gpu: bool) -> list[Capacity]:
        out = []
        if runtime_name in self.runtimes:
            out.append(self._local_capacity() if need_gpu else
                       Capacity("local", self.st.max_total_cpu, self.st.max_total_memory_mb,
                                self.st.max_sandboxes, []))
        for w in self.workers():
            c = w["caps"]
            if w["state"] == "online" and runtime_name in c.get("runtimes", []):
                out.append(Capacity(w["name"], c.get("cpu", 0), c.get("memory_mb", 0), c.get("sandboxes", 0),
                                    list(range(c.get("gpus", 0)))))
        return out

    def create(self, profile_name: str, actor: str, owner: str | None = None,
               env: dict[str, str] | None = None, ttl_s: int | None = None,
               isolation: str | None = None, worker: str | None = None, sandbox_id: str | None = None) -> dict:
        profile = self.profiles().get(profile_name)
        if not profile:
            raise ControllerError(404, f"Unknown profile '{profile_name}'")
        iso = self._effective_isolation(profile, isolation)
        profile = profile.model_copy(update={"isolation": iso})
        runtime_name = RUNTIME_FOR[iso]
        sid = sandbox_id or uuid.uuid4().hex[:12]
        if sandbox_id and not re.fullmatch(r"[a-f0-9]{12}", sandbox_id):
            raise ControllerError(422, "id must be 12 lowercase hex characters")
        with self._guard:  # placement, quota check and insert are one atomic step
            if self.store.q("SELECT 1 FROM sandboxes WHERE id=?", (sid,)):
                raise ControllerError(409, "A sandbox with this id already exists")
            active = [x for x in self.list_sandboxes() if x["state"] not in ("terminated", "failed")]
            try:
                where, gpus = place(profile, self._options(runtime_name, bool(profile.gpus)), active,
                                    max_gpu_sandboxes=self.st.max_gpu_sandboxes, pin=worker)
            except PlacementError as e:
                self.store.audit(actor, "sandbox.create", None, "denied", {"reason": e.message})
                raise ControllerError(e.status, e.message) from e
            now = time.time()
            self.store.x("INSERT INTO sandboxes(id,owner,profile,profile_json,state,runtime,error,created_at,"
                         "updated_at,expires_at,worker,gpu_indices) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                         (sid, owner or actor, profile.name, profile.model_dump_json(), State.PENDING.value,
                          runtime_name, None, now, now, now + ttl_s if ttl_s else None, where, json.dumps(gpus)))
        with self._lock(sid):
            self._set(sid, State.PROVISIONING)
            rt = self._rt(self.get(sid))
            try:
                rt.create(SandboxSpec(sid, profile, env or {}, gpus))
                rt.start(sid)
                self._egress_register(sid)
            except RuntimeError_ as e:
                self._fail(sid, str(e))
                self.store.audit(actor, "sandbox.create", sid, "failed", {"error": str(e)})
                raise ControllerError(502, f"Could not create the sandbox: {e}") from e
            self._set(sid, State.RUNNING)
        self.store.audit(actor, "sandbox.create", sid, "ok",
                         {"profile": profile.name, "isolation": iso.value, "worker": where, "gpus": gpus})
        return self.get(sid)

    def _fail(self, sid: str, error: str) -> None:
        self._egress_remove(sid)
        try:
            self._rt(self.get(sid)).destroy(sid, delete_workspace=True)
        except RuntimeError_:
            pass
        self._set(sid, State.FAILED, redact(error)[:500])

    def _transition(self, sid: str, actor: str, action: str, need: tuple[State, ...], via: State | None,
                    op, final: State) -> dict:
        with self._lock(sid):
            cur = State(self.get(sid)["state"])
            if cur not in need:
                raise ControllerError(409, f"Sandbox is {cur}; {action} needs one of {[s.value for s in need]}")
            if via:
                self._set(sid, via)
            try:
                op(self._rt(self.get(sid)), sid)
                if final == State.RUNNING:
                    self._egress_register(sid)  # a (re)started container may have a new address
                elif final == State.STOPPED:
                    self._egress_remove(sid)
            except RuntimeError_ as e:
                self._set(sid, State.FAILED, redact(str(e))[:500])
                self.store.audit(actor, f"sandbox.{action}", sid, "failed", {"error": str(e)})
                raise ControllerError(502, str(e)) from e
            self._set(sid, final)
        self.store.audit(actor, f"sandbox.{action}", sid, "ok")
        return self.get(sid)

    def stop(self, sid, actor):
        return self._transition(sid, actor, "stop", (State.RUNNING, State.PAUSED), State.STOPPING,
                                lambda rt, i: rt.stop(i), State.STOPPED)

    def start(self, sid, actor):
        return self._transition(sid, actor, "start", (State.STOPPED,), None, lambda rt, i: rt.start(i), State.RUNNING)

    def pause(self, sid, actor):
        return self._transition(sid, actor, "pause", (State.RUNNING,), None, lambda rt, i: rt.pause(i), State.PAUSED)

    def resume(self, sid, actor):
        return self._transition(sid, actor, "resume", (State.PAUSED,), None, lambda rt, i: rt.resume(i), State.RUNNING)

    def destroy(self, sid: str, actor: str) -> dict:
        with self._lock(sid):
            s = self.get(sid)
            if s["state"] == State.TERMINATED:
                return s
            try:
                self._rt(s).destroy(sid, delete_workspace=True)
            except RuntimeError_ as e:
                self.store.audit(actor, "sandbox.destroy", sid, "failed", {"error": str(e)})
                raise ControllerError(502, str(e)) from e
            self._set(sid, State.TERMINATED)
        self._egress_remove(sid)
        self.broker.revoke_for_sandbox(sid)
        self.store.audit(actor, "sandbox.destroy", sid, "ok")
        return self.get(sid)

    # ---- execution --------------------------------------------------------------
    def execute(self, sid: str, argv: list[str], actor: str, *, workdir: str | None = None,
                env: dict[str, str] | None = None, timeout_s: int | None = None,
                stdin: bytes | None = None) -> dict:
        s = self.get(sid)
        if s["state"] != State.RUNNING:
            raise ControllerError(409, f"Sandbox is {s['state']}; it must be running to execute")
        profile = Profile.model_validate(s["profile_snapshot"])
        if not argv or any(not isinstance(a, str) or "\x00" in a for a in argv):
            raise ControllerError(422, "argv must be a non-empty list of strings")
        exe = argv[0].rsplit("/", 1)[-1]
        if profile.allowed_executables is not None and exe not in profile.allowed_executables:
            self.store.audit(actor, "sandbox.execute", sid, "denied", {"argv0": argv[0]})
            raise ControllerError(403, f"'{exe}' is not allowed by profile '{profile.name}'")
        timeout = min(timeout_s or profile.default_timeout_s, profile.max_timeout_s, self.st.max_exec_seconds)
        try:
            wd = safe_workdir(workdir)
            res = self._rt(s).execute(sid, argv, workdir=wd, env=env or {}, timeout_s=timeout,
                                       max_output_bytes=self.st.max_output_bytes, stdin=stdin)
        except RuntimeError_ as e:
            self.store.audit(actor, "sandbox.execute", sid, "failed", {"error": str(e)})
            raise ControllerError(422 if "working directory" in str(e) else 502, str(e)) from e
        status = "timeout" if res.timed_out else ("ok" if res.exit_code == 0 else "error")
        out, err = redact(res.stdout), redact(res.stderr)
        eid = uuid.uuid4().hex[:12]
        self.store.x("INSERT INTO executions VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (eid, sid, redact(json.dumps(argv)), status, res.exit_code, out, err,
                      int(res.truncated), res.duration_s, time.time()))
        self.store.audit(actor, "sandbox.execute", sid, status, {"execution": eid, "argv0": argv[0]})
        return {"id": eid, "status": status, "exit_code": res.exit_code, "stdout": out, "stderr": err,
                "truncated": res.truncated, "timed_out": res.timed_out, "duration_s": res.duration_s}

    # ---- files and workspace ---------------------------------------------------------
    def _running(self, sid: str) -> tuple[dict, Runtime]:
        s = self.get(sid)
        if s["state"] != State.RUNNING:
            raise ControllerError(409, f"Sandbox is {s['state']}; it must be running")
        return s, self._rt(s)

    def _op(self, actor: str, action: str, sid: str, fn, detail: dict | None = None):
        try:
            out = fn()
        except RuntimeError_ as e:
            self.store.audit(actor, action, sid, "failed", {**(detail or {}), "error": str(e)})
            msg = str(e)
            code = 422 if any(k in msg for k in ("inside /workspace", "path", "mode")) else \
                404 if any(k in msg for k in ("not a regular file", "not a directory", "No such file")) else \
                413 if "too large" in msg else 502
            raise ControllerError(code, msg) from e
        self.store.audit(actor, action, sid, "ok", detail)
        return out

    def _quota_bytes(self, s: dict) -> int:
        return s["profile_snapshot"]["workspace_mb"] * 2**20

    def write_file(self, sid: str, path: str, data: bytes, actor: str, *, mode: str = "644") -> dict:
        s, rt = self._running(sid)
        if len(data) > self.st.max_file_bytes:
            raise ControllerError(413, f"file larger than {self.st.max_file_bytes} bytes")
        if s["profile_snapshot"].get("persistent_workspace"):
            # named volumes have no kernel quota: check before writing (tmpfs ones are kernel-enforced)
            used = self._op(actor, "workspace.usage", sid, lambda: rt.workspace_usage_bytes(sid))
            if used + len(data) > self._quota_bytes(s):
                self.store.audit(actor, "file.write", sid, "denied", {"path": path, "reason": "quota"})
                raise ControllerError(507, f"workspace quota exceeded ({used + len(data)} > {self._quota_bytes(s)} bytes)")
        self._op(actor, "file.write", sid, lambda: rt.write_file(sid, path, data, mode=mode),
                 {"path": path, "bytes": len(data)})
        return {"path": path, "bytes": len(data)}

    def read_file(self, sid: str, path: str, actor: str) -> bytes:
        _, rt = self._running(sid)
        return self._op(actor, "file.read", sid, lambda: rt.read_file(sid, path, max_bytes=self.st.max_file_bytes),
                        {"path": path})

    def list_dir(self, sid: str, path: str) -> list[dict]:
        _, rt = self._running(sid)
        try:
            return rt.list_dir(sid, path)
        except RuntimeError_ as e:
            raise ControllerError(404 if "not a directory" in str(e) else
                                  422 if "inside /workspace" in str(e) else 502, str(e)) from e

    def delete_path(self, sid: str, path: str, actor: str) -> None:
        _, rt = self._running(sid)
        self._op(actor, "file.delete", sid, lambda: rt.delete_path(sid, path), {"path": path})

    def workspace_info(self, sid: str) -> dict:
        s, rt = self._running(sid)
        try:
            used = rt.workspace_usage_bytes(sid)
        except RuntimeError_ as e:
            raise ControllerError(502, str(e)) from e
        return {"path": "/workspace", "used_bytes": used, "quota_bytes": self._quota_bytes(s),
                "persistent": bool(s["profile_snapshot"].get("persistent_workspace")),
                "enforcement": "application check + periodic scan" if s["profile_snapshot"].get(
                    "persistent_workspace") else "kernel (size-limited tmpfs or block device)"}

    def kill_processes(self, sid: str, actor: str) -> None:
        _, rt = self._running(sid)
        self._op(actor, "sandbox.kill_processes", sid, lambda: rt.kill_processes(sid))

    def enforce_quotas(self, actor: str = "system") -> list[str]:
        """Stop running persistent-workspace sandboxes that exceed their quota (data is kept)."""
        stopped = []
        for s in self.list_sandboxes("running"):
            if not s["profile_snapshot"].get("persistent_workspace"):
                continue
            try:
                used = self._rt(s).workspace_usage_bytes(s["id"])
            except RuntimeError_:
                continue
            if used > self._quota_bytes(s):
                self.store.audit(actor, "security.quota_exceeded", s["id"], "stopped",
                                 {"used": used, "quota": self._quota_bytes(s)})
                try:
                    self.stop(s["id"], actor)
                    stopped.append(s["id"])
                except ControllerError:
                    pass
        return stopped

    # ---- git --------------------------------------------------------------------------
    def _repo(self, sid: str, repo: str | None) -> str:
        if repo:
            return safe_path(repo)
        rows = self.store.q("SELECT path FROM git_repos WHERE sandbox_id=?", (sid,))
        if len(rows) != 1:
            raise ControllerError(422, "specify 'repo' (the sandbox has " + str(len(rows)) + " cloned repositories)")
        return rows[0]["path"]

    def _git(self, sid: str):
        from .git_ops import SandboxGit
        _, rt = self._running(sid)
        return SandboxGit(rt, sid, timeout_s=min(self.st.max_exec_seconds, 300))

    def git(self, sid: str, actor: str, op: str, repo: str | None = None, **kw):
        from .broker import BrokerError
        from .git_ops import GitError
        g = self._git(sid)
        path = self._repo(sid, repo)
        try:
            out = getattr(g, op)(path, **kw)
        except (GitError, BrokerError) as e:
            self.store.audit(actor, f"git.{op}", sid, "failed", {"repo": path, "error": e.message})
            raise ControllerError(e.status, e.message) from e
        except RuntimeError_ as e:
            raise ControllerError(502, str(e)) from e
        if op in ("create_branch", "checkout", "commit"):
            self.store.audit(actor, f"git.{op}", sid, "ok", {"repo": path, **{k: v for k, v in kw.items()
                                                                              if k != "message"}})
        return out

    def git_clone(self, sid: str, actor: str, url: str, *, branch: str | None = None, depth: int = 1,
                  dest: str | None = None, lease: str | None = None) -> dict:
        from .broker import BrokerError
        from .git_ops import GitError, host_clone, parse_repo_url
        g = self._git(sid)
        try:
            norm, host, repo = parse_repo_url(url, self.st.git_allowed_hosts, self.st.git_allowed_repos)
            path = safe_path(dest or repo.split("/", 1)[1])
            header = self.broker.resolve_git_header(lease, sid, host, repo, actor) if lease else None
            fetch = self.git_fetcher or host_clone
            tar, head = fetch(norm, branch, depth, header, workdir=self.st.data_dir / "tmp",
                              max_bytes=self.st.git_max_bytes, timeout_s=self.st.git_timeout_s)
            g.extract(tar, path)
        except (GitError, BrokerError) as e:
            self.store.audit(actor, "git.clone", sid, "failed", {"url": url, "error": e.message})
            raise ControllerError(e.status, e.message) from e
        except RuntimeError_ as e:
            raise ControllerError(422 if "inside /workspace" in str(e) else 502, str(e)) from e
        self.store.x("INSERT OR REPLACE INTO git_repos VALUES (?,?,?,?,?,?)",
                     (sid, path, norm, branch, head, time.time()))
        self.store.audit(actor, "git.clone", sid, "ok", {"url": norm, "path": path, "head": head,
                                                       "credential": bool(lease)})
        return {"path": path, "url": norm, "branch": branch, "head": head}

    def git_report(self, sid: str, actor: str, repo: str | None = None) -> dict:
        path = self._repo(sid, repo)
        rows = self.store.q("SELECT * FROM git_repos WHERE sandbox_id=? AND path=?", (sid, path))
        if not rows:
            raise ControllerError(404, "repository was not cloned through the API (no base recorded)")
        base = rows[0]["base_sha"]
        rep = {"url": rows[0]["url"], "path": path, "base": base,
               "status": self.git(sid, actor, "status", path),
               "commits": self.git(sid, actor, "log", path, n=500, base=base),
               "diffstat": self.git(sid, actor, "diff", path, base=base, stat=True),
               "patch": self.git(sid, actor, "patch", path, base=base),
               "uncommitted_diff": self.git(sid, actor, "diff", path)}
        self.store.audit(actor, "git.report", sid, "ok", {"repo": path, "commits": len(rep["commits"])})
        return rep

    def executions(self, sid: str, limit: int = 50) -> list[dict]:
        self.get(sid)
        return [dict(r) for r in self.store.q(
            "SELECT * FROM executions WHERE sandbox_id=? ORDER BY created_at DESC LIMIT ?", (sid, limit))]

    def logs(self, sid: str, tail: int = 200) -> str:
        s = self.get(sid)
        try:
            return redact(self._rt(s).logs(sid, tail))
        except RuntimeError_ as e:
            raise ControllerError(502, str(e)) from e

    # ---- recovery and cleanup ---------------------------------------------------
    def recover(self) -> dict:
        """After a restart: reconcile stored state with what the runtime really has."""
        fixed = {"failed": 0, "corrected": 0}
        for s in self.list_sandboxes():
            sid, state = s["id"], State(s["state"])
            if state in (State.TERMINATED, State.FAILED):
                continue
            if state in (State.PENDING, State.PROVISIONING, State.STOPPING):
                self._fail(sid, f"interrupted in state '{state}' by a restart"); fixed["failed"] += 1
                continue
            try:
                real = self._rt(s).status(sid)
            except RuntimeError_:
                fixed["unreachable"] = fixed.get("unreachable", 0) + 1  # worker down: do not guess, keep state
                continue
            want = {"running": State.RUNNING, "paused": State.PAUSED, "stopped": State.STOPPED}.get(real)
            if want is None:
                self._set(sid, State.FAILED, "runtime lost the sandbox"); fixed["failed"] += 1
            elif want != state:
                self.store.x("UPDATE sandboxes SET state=?, updated_at=? WHERE id=?", (want.value, time.time(), sid))
                fixed["corrected"] += 1
            if want in (State.RUNNING, State.PAUSED):
                try:
                    self._egress_register(sid)
                except RuntimeError_:
                    pass
        return fixed

    def cleanup_expired(self, actor: str = "system") -> list[str]:
        gone = []
        for s in self.list_sandboxes():
            if s["expires_at"] and s["expires_at"] < time.time() and s["state"] not in ("terminated",):
                self.destroy(s["id"], actor)
                gone.append(s["id"])
        self.store.purge_audit(self.st.audit_retention_days)
        return gone
