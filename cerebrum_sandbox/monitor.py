"""Monitoring: deduplicated events (+ optional webhook), the maintenance loop, Prometheus metrics.

Detected: failed sandbox creation, failed/timed-out executions, runtime failures (sandbox lost),
resource exhaustion (host memory/disk, quotas), network policy violations, worker failure,
failed jobs. The maintenance loop also does TTL cleanup, quota enforcement, drift
reconciliation, retention purges and daily metadata backups, so the service can run unattended.
"""
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from .lifecycle import State
from .redact import redact
from .resources import host_resources
from .runtime import RuntimeError_

SEVERITIES = ("info", "warning", "critical")


class Events:
    def __init__(self, store, webhook: str = "", http_factory=None, dedupe_s: int = 600):
        self.store, self.webhook, self.dedupe_s = store, webhook, dedupe_s
        self._http = http_factory or (lambda: __import__("httpx").Client(timeout=10))

    def emit(self, kind: str, severity: str, target: str | None, message: str) -> None:
        message = redact(message)[:1000]
        now = time.time()
        rows = self.store.q("SELECT id FROM events WHERE kind=? AND IFNULL(target,'')=IFNULL(?,'') AND last_ts>? "
                            "ORDER BY id DESC LIMIT 1", (kind, target, now - self.dedupe_s))
        if rows:  # same problem again: count it, do not spam
            self.store.x("UPDATE events SET count=count+1, last_ts=?, message=? WHERE id=?", (now, message, rows[0]["id"]))
            return
        self.store.x("INSERT INTO events(ts,kind,severity,target,message,last_ts) VALUES (?,?,?,?,?,?)",
                     (now, kind, severity, target, message, now))
        if self.webhook and severity in ("warning", "critical"):
            body = {"source": "cerebrum.sandbox", "kind": kind, "severity": severity, "target": target,
                    "message": message, "ts": now}
            threading.Thread(target=self._post, args=(body,), daemon=True).start()

    def _post(self, body: dict) -> None:
        try:
            with self._http() as h:
                h.post(self.webhook, json=body)
        except Exception:  # noqa: BLE001  alerting is best effort
            pass

    def list_events(self, limit: int = 100, severity: str | None = None) -> list[dict]:
        q = "SELECT * FROM events" + (" WHERE severity=?" if severity else "") + " ORDER BY last_ts DESC LIMIT ?"
        return [dict(r) for r in self.store.q(q, (severity, limit) if severity else (limit,))]


class Maintenance:
    def __init__(self, ctl, st, store, events: Events):
        self.ctl, self.st, self.store, self.events = ctl, st, store, events
        self.last_run = time.time()
        self._stop = threading.Event()
        self.last_report: dict = {}

    def reconcile(self) -> int:
        """Running/paused/stopped sandboxes whose runtime lost them -> failed (+ event)."""
        lost = 0
        for s in self.ctl.list_sandboxes():
            if s["state"] not in (State.RUNNING, State.PAUSED, State.STOPPED):
                continue
            try:
                real = self.ctl._rt(s).status(s["id"])
            except RuntimeError_:
                continue  # worker unreachable: reported by the worker check, state kept
            if real == "missing":
                try:
                    self.ctl._set(s["id"], State.FAILED, "runtime lost the sandbox")
                except Exception:  # noqa: BLE001
                    continue
                self.events.emit("sandbox_lost", "critical", s["id"], "the runtime no longer has this sandbox")
                lost += 1
            elif real != s["state"] and real in ("running", "paused", "stopped"):
                self.store.x("UPDATE sandboxes SET state=?, updated_at=? WHERE id=?", (real, time.time(), s["id"]))
        return lost

    def _since(self, table: str, where: str, since: float) -> list:
        return self.store.q(f"SELECT * FROM {table} WHERE ts > ? AND {where}", (since,))

    def run_once(self) -> dict:
        since, now = self.last_run, time.time()
        rep: dict = {}
        rep["expired"] = self.ctl.cleanup_expired()
        rep["quota_stopped"] = self.ctl.enforce_quotas()
        for sid in rep["quota_stopped"]:
            self.events.emit("quota_exceeded", "warning", sid, "workspace over quota; sandbox stopped (data kept)")
        rep["lost"] = self.reconcile()
        for w in self.ctl.refresh_workers():
            if w["state"] != "online":
                self.events.emit("worker_offline", "critical", w["name"], w.get("last_error") or "worker offline")
        host = host_resources(self.st.data_dir, [])
        mem = host["memory"]
        if mem.get("total_mb") and mem.get("available_mb") is not None and mem["available_mb"] < 0.1 * mem["total_mb"]:
            self.events.emit("resource_exhaustion", "critical", "memory",
                             f"host memory low: {mem['available_mb']} MB available of {mem['total_mb']}")
        if host["disk"]["free_mb"] < 0.1 * host["disk"]["total_mb"]:
            self.events.emit("resource_exhaustion", "critical", "disk", f"disk low: {host['disk']['free_mb']} MB free")
        u = self.ctl.usage()
        if u["sandboxes"] >= self.st.max_sandboxes:
            self.events.emit("resource_exhaustion", "warning", "sandboxes", f"sandbox limit reached ({u['sandboxes']})")
        for r in self.store.q("SELECT sandbox_id, COUNT(*) n FROM netlog WHERE ts>? AND decision='denied' "
                              "GROUP BY sandbox_id", (since,)):
            self.events.emit("network_violation", "warning", r["sandbox_id"],
                             f"{r['n']} blocked outbound connection attempt(s)")
        for a in self._since("audit", "action='sandbox.create' AND outcome IN ('failed','denied')", since):
            self.events.emit("sandbox_create_failed", "warning" if a["outcome"] == "failed" else "info",
                             a["target"], a["detail"] or a["outcome"])
        for a in self.store.q("SELECT * FROM executions WHERE created_at>? AND status IN ('timeout','error')", (since,)):
            self.events.emit("execution_" + ("timeout" if a["status"] == "timeout" else "failed"),
                             "info", a["sandbox_id"], f"execution {a['id']} {a['status']} (exit {a['exit_code']})")
        # retention
        self.store.x("DELETE FROM netlog WHERE ts<?", (now - self.st.netlog_retention_days * 86400,))
        self.store.x("DELETE FROM executions WHERE created_at<?", (now - self.st.audit_retention_days * 86400,))
        self.store.x("DELETE FROM events WHERE last_ts<?", (now - self.st.audit_retention_days * 86400,))
        rep["backup"] = self.backup_if_due()
        self.last_run, self.last_report = now, rep
        return rep

    def backup_if_due(self) -> str | None:
        d = self.st.data_dir / "backups"
        name = f"meta-{datetime.now(timezone.utc):%Y%m%d}.db"
        if (d / name).exists():
            return None
        out = self.store.backup(d / name)
        for old in sorted(d.glob("meta-*.db"))[:-self.st.backup_keep]:
            old.unlink(missing_ok=True)
        return str(out)

    def start(self) -> None:
        def loop():
            while not self._stop.wait(self.st.maintenance_interval_s):
                try:
                    self.run_once()
                except Exception as e:  # noqa: BLE001  the loop must survive anything
                    self.events.emit("maintenance_error", "warning", None, f"{type(e).__name__}: {e}")
        threading.Thread(target=loop, daemon=True, name="maintenance").start()

    def stop(self) -> None:
        self._stop.set()


def prometheus(ctl, store, jobs, egress) -> str:
    lines: list[str] = []

    def g(name, help_, samples, typ="gauge"):
        lines.append(f"# HELP {name} {help_}")
        lines.append(f"# TYPE {name} {typ}")
        for labels, v in samples:
            lab = ",".join(f'{k}="{str(val).replace(chr(34), "")}"' for k, val in labels.items())
            lines.append(f"{name}{{{lab}}} {v}" if lab else f"{name} {v}")

    states = {r["state"]: r["n"] for r in store.q("SELECT state, COUNT(*) n FROM sandboxes GROUP BY state")}
    g("csb_sandboxes", "Sandboxes by state", [({"state": s.value}, states.get(s.value, 0)) for s in State])
    ex = store.q("SELECT status, COUNT(*) n FROM executions GROUP BY status")
    g("csb_executions_total", "Executions by result", [({"status": r["status"]}, r["n"]) for r in ex], "counter")
    js = {r["state"]: r["n"] for r in store.q("SELECT state, COUNT(*) n FROM jobs GROUP BY state")}
    g("csb_jobs", "Jobs by state", [({"state": s}, js.get(s, 0))
                                    for s in ("queued", "running", "succeeded", "failed", "cancelled")])
    u = ctl.usage()
    g("csb_reserved_cpu", "CPU reserved by active sandboxes", [({}, u["cpu"])])
    g("csb_reserved_memory_mb", "Memory reserved by active sandboxes", [({}, u["memory_mb"])])
    g("csb_gpus_assigned", "GPUs assigned to sandboxes", [({}, u["gpus_assigned"])])
    ws = ctl.workers()
    g("csb_workers", "Registered workers by state", [({"state": st_}, sum(1 for w in ws if w["state"] == st_))
                                                     for st_ in ("online", "offline")])
    nl = store.q("SELECT decision, COUNT(*) n FROM netlog GROUP BY decision")
    g("csb_egress_connections_total", "Egress proxy connections", [({"decision": r["decision"]}, r["n"]) for r in nl],
      "counter")
    ev = store.q("SELECT severity, SUM(count) n FROM events GROUP BY severity")
    g("csb_events_total", "Monitoring events", [({"severity": r["severity"]}, r["n"]) for r in ev], "counter")
    g("csb_job_hours_today", "Job hours used today", [({}, round(jobs.hours_today(), 4))])
    for r in ctl.runtime_status():
        g("csb_runtime_up", "Runtime health", [({"runtime": r["name"]}, 1 if r.get("ok") else 0)])
    return "\n".join(lines) + "\n"
