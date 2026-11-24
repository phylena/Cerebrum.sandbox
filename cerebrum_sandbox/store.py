"""Persistent metadata (SQLite, WAL). Survives restarts; backed up with `backup()`."""
import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS sandboxes (
  id TEXT PRIMARY KEY, owner TEXT NOT NULL, profile TEXT NOT NULL, profile_json TEXT NOT NULL,
  state TEXT NOT NULL, runtime TEXT NOT NULL, error TEXT, created_at REAL NOT NULL,
  updated_at REAL NOT NULL, expires_at REAL,
  worker TEXT NOT NULL DEFAULT 'local', gpu_indices TEXT NOT NULL DEFAULT '[]');
CREATE TABLE IF NOT EXISTS workers (
  id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, url TEXT NOT NULL, key TEXT NOT NULL,
  state TEXT NOT NULL, caps TEXT NOT NULL, last_seen REAL, last_error TEXT, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS executions (
  id TEXT PRIMARY KEY, sandbox_id TEXT NOT NULL, argv TEXT NOT NULL, status TEXT NOT NULL,
  exit_code INTEGER, stdout TEXT, stderr TEXT, truncated INTEGER, duration_s REAL, created_at REAL NOT NULL);
CREATE INDEX IF NOT EXISTS ex_sb ON executions(sandbox_id, created_at);
CREATE TABLE IF NOT EXISTS profiles (name TEXT PRIMARY KEY, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, owner TEXT, hash TEXT UNIQUE NOT NULL,
  created_at REAL NOT NULL, expires_at REAL, revoked_at REAL);
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, kind TEXT NOT NULL, secret TEXT NOT NULL,
  hosts TEXT NOT NULL, scopes TEXT NOT NULL, max_ttl_s INTEGER NOT NULL, created_at REAL NOT NULL, revoked_at REAL);
CREATE TABLE IF NOT EXISTS leases (
  id TEXT PRIMARY KEY, credential_id TEXT NOT NULL, sandbox_id TEXT NOT NULL, scope TEXT NOT NULL,
  created_at REAL NOT NULL, expires_at REAL NOT NULL, revoked_at REAL, uses INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS git_repos (
  sandbox_id TEXT NOT NULL, path TEXT NOT NULL, url TEXT NOT NULL, branch TEXT, base_sha TEXT NOT NULL,
  created_at REAL NOT NULL, PRIMARY KEY (sandbox_id, path));
CREATE TABLE IF NOT EXISTS netlog (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, sandbox_id TEXT, src TEXT, method TEXT, host TEXT,
  port INTEGER, decision TEXT NOT NULL, reason TEXT, bytes_up INTEGER, bytes_down INTEGER, duration_s REAL);
CREATE INDEX IF NOT EXISTS netlog_sb ON netlog(sandbox_id, ts);
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY, owner TEXT NOT NULL, actor TEXT NOT NULL, spec TEXT NOT NULL, priority INTEGER NOT NULL,
  state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, max_retries INTEGER NOT NULL, sandbox_id TEXT,
  result TEXT, error TEXT, wait_reason TEXT, created_at REAL NOT NULL, started_at REAL, finished_at REAL,
  cancel_requested INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS jobs_q ON jobs(state, priority, created_at);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL,
  target TEXT, message TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 1, last_ts REAL NOT NULL);
CREATE INDEX IF NOT EXISTS events_kind ON events(kind, target, last_ts);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  target TEXT, outcome TEXT NOT NULL, detail TEXT);
"""


class Store:
    def __init__(self, data_dir: Path):
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "sandbox.db"
        self._lock = threading.RLock()
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)
        self._migrate()
        try:
            self.path.chmod(0o600)  # worker keys live in here
        except OSError:
            pass

    def _migrate(self) -> None:
        cols = {r["name"] for r in self.db.execute("PRAGMA table_info(sandboxes)")}
        with self.db:
            if "worker" not in cols:
                self.db.execute("ALTER TABLE sandboxes ADD COLUMN worker TEXT NOT NULL DEFAULT 'local'")
            if "gpu_indices" not in cols:
                self.db.execute("ALTER TABLE sandboxes ADD COLUMN gpu_indices TEXT NOT NULL DEFAULT '[]'")

    def q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.db.execute(sql, args).fetchall()

    def x(self, sql: str, args: tuple = ()) -> None:
        with self._lock, self.db:
            self.db.execute(sql, args)

    def audit(self, actor: str, action: str, target: str | None, outcome: str, detail: dict | None = None) -> None:
        from .redact import redact
        self.x("INSERT INTO audit(ts,actor,action,target,outcome,detail) VALUES (?,?,?,?,?,?)",
               (time.time(), actor, action, target, outcome,
                redact(json.dumps(detail or {}, default=str))[:4000]))

    def purge_audit(self, days: int) -> None:
        self.x("DELETE FROM audit WHERE ts < ?", (time.time() - days * 86400,))

    def backup(self, dest: Path) -> Path:
        """Consistent online copy of all metadata."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            out = sqlite3.connect(dest)
            with out:
                self.db.backup(out)
            out.close()
        return dest
