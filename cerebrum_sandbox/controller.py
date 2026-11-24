"""The Sandbox Controller: lifecycle, quotas, profiles, execution, audit, recovery."""
import json
import threading
import time
import uuid

from . import lifecycle
from .lifecycle import State
from .profiles import BUILTIN, Profile, clamp_check
from .redact import redact
from .runtime import Runtime, RuntimeError_, SandboxSpec
from .runtime.base import safe_workdir
from .settings import Settings
from .store import Store

ACTIVE = (State.PENDING, State.PROVISIONING, State.RUNNING, State.PAUSED, State.STOPPING, State.STOPPED)


class ControllerError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class Controller:
    def __init__(self, st: Settings, store: Store, runtime: Runtime):
        self.st, self.store, self.runtime = st, store, runtime
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
        cpu = mem = n = 0
        for s in self.list_sandboxes():
            if s["state"] in ("terminated", "failed"):
                continue
            p = s["profile_snapshot"]
            n += 1; cpu += p["cpu"]; mem += p["memory_mb"]
        return {"sandboxes": n, "cpu": cpu, "memory_mb": mem}

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

    def create(self, profile_name: str, actor: str, owner: str | None = None,
               env: dict[str, str] | None = None, ttl_s: int | None = None) -> dict:
        profile = self.profiles().get(profile_name)
        if not profile:
            raise ControllerError(404, f"Unknown profile '{profile_name}'")
        sid = uuid.uuid4().hex[:12]
        with self._guard:  # quota check and insert are one atomic step
            u = self.usage()
            if u["sandboxes"] >= self.st.max_sandboxes:
                self.store.audit(actor, "sandbox.create", None, "denied", {"reason": "max_sandboxes"})
                raise ControllerError(429, f"Sandbox limit reached ({self.st.max_sandboxes})")
            if u["cpu"] + profile.cpu > self.st.max_total_cpu:
                raise ControllerError(429, "Total CPU quota would be exceeded")
            if u["memory_mb"] + profile.memory_mb > self.st.max_total_memory_mb:
                raise ControllerError(429, "Total memory quota would be exceeded")
            now = time.time()
            self.store.x("INSERT INTO sandboxes VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (sid, owner or actor, profile.name, profile.model_dump_json(), State.PENDING.value,
                          self.runtime.name, None, now, now, now + ttl_s if ttl_s else None))
        with self._lock(sid):
            self._set(sid, State.PROVISIONING)
            try:
                self.runtime.create(SandboxSpec(sid, profile, env or {}))
                self.runtime.start(sid)
            except RuntimeError_ as e:
                self._fail(sid, str(e))
                self.store.audit(actor, "sandbox.create", sid, "failed", {"error": str(e)})
                raise ControllerError(502, f"Could not create the sandbox: {e}") from e
            self._set(sid, State.RUNNING)
        self.store.audit(actor, "sandbox.create", sid, "ok", {"profile": profile.name})
        return self.get(sid)

    def _fail(self, sid: str, error: str) -> None:
        try:
            self.runtime.destroy(sid, delete_workspace=True)
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
                op(sid)
            except RuntimeError_ as e:
                self._set(sid, State.FAILED, redact(str(e))[:500])
                self.store.audit(actor, f"sandbox.{action}", sid, "failed", {"error": str(e)})
                raise ControllerError(502, str(e)) from e
            self._set(sid, final)
        self.store.audit(actor, f"sandbox.{action}", sid, "ok")
        return self.get(sid)

    def stop(self, sid, actor):
        return self._transition(sid, actor, "stop", (State.RUNNING, State.PAUSED), State.STOPPING,
                                self.runtime.stop, State.STOPPED)

    def start(self, sid, actor):
        return self._transition(sid, actor, "start", (State.STOPPED,), None, self.runtime.start, State.RUNNING)

    def pause(self, sid, actor):
        return self._transition(sid, actor, "pause", (State.RUNNING,), None, self.runtime.pause, State.PAUSED)

    def resume(self, sid, actor):
        return self._transition(sid, actor, "resume", (State.PAUSED,), None, self.runtime.resume, State.RUNNING)

    def destroy(self, sid: str, actor: str) -> dict:
        with self._lock(sid):
            s = self.get(sid)
            if s["state"] == State.TERMINATED:
                return s
            try:
                self.runtime.destroy(sid, delete_workspace=True)
            except RuntimeError_ as e:
                self.store.audit(actor, "sandbox.destroy", sid, "failed", {"error": str(e)})
                raise ControllerError(502, str(e)) from e
            self._set(sid, State.TERMINATED)
        self.store.audit(actor, "sandbox.destroy", sid, "ok")
        return self.get(sid)

    # ---- execution --------------------------------------------------------------
    def execute(self, sid: str, argv: list[str], actor: str, *, workdir: str | None = None,
                env: dict[str, str] | None = None, timeout_s: int | None = None) -> dict:
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
            res = self.runtime.execute(sid, argv, workdir=wd, env=env or {}, timeout_s=timeout,
                                       max_output_bytes=self.st.max_output_bytes)
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

    def executions(self, sid: str, limit: int = 50) -> list[dict]:
        self.get(sid)
        return [dict(r) for r in self.store.q(
            "SELECT * FROM executions WHERE sandbox_id=? ORDER BY created_at DESC LIMIT ?", (sid, limit))]

    def logs(self, sid: str, tail: int = 200) -> str:
        self.get(sid)
        try:
            return redact(self.runtime.logs(sid, tail))
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
            real = self.runtime.status(sid)
            want = {"running": State.RUNNING, "paused": State.PAUSED, "stopped": State.STOPPED}.get(real)
            if want is None:
                self._set(sid, State.FAILED, "runtime lost the sandbox"); fixed["failed"] += 1
            elif want != state:
                self.store.x("UPDATE sandboxes SET state=?, updated_at=? WHERE id=?", (want.value, time.time(), sid))
                fixed["corrected"] += 1
        return fixed

    def cleanup_expired(self, actor: str = "system") -> list[str]:
        gone = []
        for s in self.list_sandboxes():
            if s["expires_at"] and s["expires_at"] < time.time() and s["state"] not in ("terminated",):
                self.destroy(s["id"], actor)
                gone.append(s["id"])
        self.store.purge_audit(self.st.audit_retention_days)
        return gone
