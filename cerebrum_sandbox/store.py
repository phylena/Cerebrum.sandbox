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
