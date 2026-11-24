"""Job queue: one-shot sandboxes run by a bounded pool of runner threads.

A job = create sandbox -> place input files -> run argv -> collect output files -> destroy.
States: queued -> running -> succeeded | failed | cancelled (queued again on retry).
  * priority (higher first), then FIFO;
  * never more than SANDBOX_MAX_CONCURRENT_JOBS running; capacity refusals (429/503) are not
    failures: the job waits (wait_reason) and is retried later;
  * infrastructure failures (502) are retried up to max_retries with backoff; a non-zero exit
    is retried only if retry_on_failure;
  * cancel works for queued and running jobs (the sandbox is destroyed);
  * a daily job-hours budget stops new jobs from starting (they wait, they are not dropped);
  * after a controller restart, jobs that were running are re-queued (or failed when out of retries).
"""
import base64
import json
import threading
import time
import uuid

from pydantic import BaseModel, Field

from .controller import ControllerError

TERMINAL = ("succeeded", "failed", "cancelled")


class JobSpec(BaseModel):
    profile: str = "basic"
    argv: list[str] = Field(min_length=1, max_length=256)
    isolation: str | None = None
    worker: str | None = None
    env: dict[str, str] = Field(default_factory=dict, max_length=32)
    workdir: str | None = None
    timeout_s: int | None = Field(None, ge=1)
    files: dict[str, str] = Field(default_factory=dict, max_length=64, description="path -> base64 content")
    outputs: list[str] = Field(default_factory=list, max_length=32, description="paths to collect after the run")
    priority: int = Field(5, ge=0, le=9)
    max_retries: int = Field(1, ge=0, le=5)
    retry_on_failure: bool = False
    git_url: str | None = Field(None, description="optional: clone this repository first (host-side, no credentials)")


class JobRunner:
    def __init__(self, ctl, st, store):
        self.ctl, self.st, self.store = ctl, st, store
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._not_before: dict[str, float] = {}

    # ---- API side ------------------------------------------------------------------------
    def submit(self, spec: JobSpec, actor: str, owner: str) -> dict:
        if spec.profile not in self.ctl.profiles():
            raise ControllerError(404, f"Unknown profile '{spec.profile}'")
        queued = self.store.q("SELECT COUNT(*) n FROM jobs WHERE state='queued'")[0]["n"]
        if queued >= self.st.max_queued_jobs:
            raise ControllerError(429, f"job queue is full ({self.st.max_queued_jobs})")
        for b in spec.files.values():
            try:
                base64.b64decode(b, validate=True)
            except ValueError as e:
                raise ControllerError(422, "files must be base64") from e
        jid = "job_" + uuid.uuid4().hex[:12]
        self.store.x("INSERT INTO jobs(id,owner,actor,spec,priority,state,max_retries,created_at) VALUES (?,?,?,?,?,?,?,?)",
                     (jid, owner, actor, spec.model_dump_json(), spec.priority, "queued", spec.max_retries, time.time()))
        self.store.audit(actor, "job.submit", jid, "ok", {"profile": spec.profile, "priority": spec.priority})
        return self.get(jid)

    def get(self, jid: str) -> dict:
        rows = self.store.q("SELECT * FROM jobs WHERE id=?", (jid,))
        if not rows:
            raise ControllerError(404, "Job not found")
        d = dict(rows[0])
        d["spec"] = json.loads(d["spec"])
        d["spec"].pop("files", None)  # inputs can be large; not echoed back
        d["result"] = json.loads(d["result"]) if d["result"] else None
        d["cancel_requested"] = bool(d["cancel_requested"])
        return d

    def list_jobs(self, state: str | None = None, limit: int = 100) -> list[dict]:
        rows = self.store.q("SELECT id FROM jobs" + (" WHERE state=?" if state else "") +
                            " ORDER BY created_at DESC LIMIT ?", ((state, limit) if state else (limit,)))
        return [self.get(r["id"]) for r in rows]

    def cancel(self, jid: str, actor: str) -> dict:
        j = self.get(jid)
        if j["state"] in TERMINAL:
            return j
        with self._lock:
            self.store.x("UPDATE jobs SET cancel_requested=1 WHERE id=?", (jid,))
            if j["state"] == "queued":
                self.store.x("UPDATE jobs SET state='cancelled', finished_at=? WHERE id=? AND state='queued'",
                             (time.time(), jid))
        if j["state"] == "running" and j["sandbox_id"]:
            try:
                self.ctl.destroy(j["sandbox_id"], actor)  # the running execution then ends
            except ControllerError:
                pass
        self.store.audit(actor, "job.cancel", jid, "ok")
        return self.get(jid)

    # ---- budget ------------------------------------------------------------------------------
    def hours_today(self) -> float:
        day0 = time.time() - (time.time() % 86400)
        rows = self.store.q("SELECT started_at, finished_at FROM jobs WHERE started_at IS NOT NULL AND "
                            "(finished_at IS NULL OR finished_at >= ?)", (day0,))
        now = time.time()
        return sum(((r["finished_at"] or now) - max(r["started_at"], day0)) for r in rows) / 3600

    # ---- runner side -----------------------------------------------------------------------
    def recover(self) -> int:
        n = 0
        for r in self.store.q("SELECT * FROM jobs WHERE state='running'"):
            if r["sandbox_id"]:
                try:
                    self.ctl.destroy(r["sandbox_id"], "system")
                except ControllerError:
                    pass
            if r["attempts"] <= r["max_retries"]:
                self.store.x("UPDATE jobs SET state='queued', sandbox_id=NULL, wait_reason='recovered after restart' "
                             "WHERE id=?", (r["id"],))
            else:
                self.store.x("UPDATE jobs SET state='failed', error='interrupted by a restart', finished_at=? "
                             "WHERE id=?", (time.time(), r["id"]))
            n += 1
        return n

    def _claim(self) -> dict | None:
        with self._lock:
            running = self.store.q("SELECT COUNT(*) n FROM jobs WHERE state='running'")[0]["n"]
            if running >= self.st.max_concurrent_jobs:
                return None
            over_budget = self.hours_today() >= self.st.job_hours_budget_daily
            now = time.time()
            for r in self.store.q("SELECT * FROM jobs WHERE state='queued' AND cancel_requested=0 "
                                  "ORDER BY priority DESC, created_at ASC LIMIT 50"):
                if self._not_before.get(r["id"], 0) > now:
                    continue
                if over_budget:
                    self.store.x("UPDATE jobs SET wait_reason='daily job-hours budget reached' WHERE id=?", (r["id"],))
                    return None
                self.store.x("UPDATE jobs SET state='running', attempts=attempts+1, started_at=COALESCE(started_at,?), "
                             "wait_reason=NULL WHERE id=? AND state='queued'", (now, r["id"]))
                return dict(self.store.q("SELECT * FROM jobs WHERE id=?", (r["id"],))[0])
        return None

    def run_once(self) -> bool:
        """Claim and run one job synchronously. Returns False if nothing was runnable."""
        j = self._claim()
        if not j:
            return False
        self._execute(j)
        return True

    def _requeue(self, j: dict, reason: str, delay: float) -> None:
        self._not_before[j["id"]] = time.time() + delay
        self.store.x("UPDATE jobs SET state='queued', sandbox_id=NULL, attempts=attempts-?, wait_reason=? WHERE id=?",
                     (1 if reason.startswith("waiting") else 0, reason, j["id"]))

    def _finish(self, j: dict, state: str, result: dict | None = None, error: str | None = None) -> None:
        self.store.x("UPDATE jobs SET state=?, result=?, error=?, finished_at=? WHERE id=?",
                     (state, json.dumps(result) if result is not None else None, error, time.time(), j["id"]))
        self.store.audit(j["actor"], "job.finish", j["id"], state, {"error": error} if error else None)
        if state == "failed" and getattr(self.ctl, "events", None):
            self.ctl.events.emit("job_failed", "warning", j["id"], error or "job failed")

    def _execute(self, j: dict) -> None:
        spec = JobSpec.model_validate_json(j["spec"])
        sid = None
        try:
            s = self.ctl.create(spec.profile, j["actor"], j["owner"], spec.env, None,
                                isolation=spec.isolation, worker=spec.worker)
            sid = s["id"]
            self.store.x("UPDATE jobs SET sandbox_id=? WHERE id=?", (sid, j["id"]))
            if self.get(j["id"])["cancel_requested"]:
                raise _Cancelled()
            if spec.git_url:
                self.ctl.git_clone(sid, j["actor"], spec.git_url)
            for path, b64 in spec.files.items():
                self.ctl.write_file(sid, path, base64.b64decode(b64), j["actor"])
            res = self.ctl.execute(sid, spec.argv, j["actor"], workdir=spec.workdir, env=spec.env,
                                   timeout_s=spec.timeout_s)
            outputs = {}
            for path in spec.outputs:
                try:
                    outputs[path] = base64.b64encode(self.ctl.read_file(sid, path, j["actor"])).decode()
                except ControllerError as e:
                    outputs[path] = None
                    res.setdefault("output_errors", {})[path] = e.message
            res["outputs"] = outputs
            if self.get(j["id"])["cancel_requested"]:
                raise _Cancelled()
            if res["status"] == "ok":
                self._finish(j, "succeeded", res)
            elif spec.retry_on_failure and j["attempts"] <= j["max_retries"]:
                self._requeue(j, f"retry after exit code {res['exit_code']}", self.st.job_retry_backoff_s)
            else:
                self._finish(j, "failed", res, f"command {res['status']} (exit {res['exit_code']})")
        except _Cancelled:
            self._finish(j, "cancelled")
        except ControllerError as e:
            if self.get(j["id"])["cancel_requested"]:
                self._finish(j, "cancelled")
            elif e.status in (429, 503):           # no capacity right now: wait, do not burn a retry
                self._requeue(j, f"waiting for capacity: {e.message}", self.st.job_retry_backoff_s)
            elif e.status >= 500 and j["attempts"] <= j["max_retries"]:
                self._requeue(j, f"retry after infrastructure error: {e.message}",
                              self.st.job_retry_backoff_s * j["attempts"])
            else:
                self._finish(j, "failed", None, e.message)
        except Exception as e:  # noqa: BLE001  a job must never kill its runner thread
            self._finish(j, "failed", None, f"internal error: {type(e).__name__}: {e}")
        finally:
            if sid:
                try:
                    self.ctl.destroy(sid, "system")
                except ControllerError:
                    pass

    def start(self, interval: float = 1.0) -> None:
        self.recover()

        def loop():
            while not self._stop.is_set():
                try:
                    worked = self.run_once()
                except Exception:  # noqa: BLE001
                    worked = False
                if not worked:
                    self._stop.wait(interval)
        for i in range(max(1, self.st.max_concurrent_jobs)):
            t = threading.Thread(target=loop, daemon=True, name=f"job-runner-{i}")
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()


class _Cancelled(Exception):
    pass
