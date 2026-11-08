"""SQLite storage for the LGTM demo: installations, repos, review runs, their
events (the live agent trace), findings with triage state, webhook deliveries
and settings. One file, ``demo/.data/lgtm.db`` (git-ignored).
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / ".data"
DB_PATH = DATA_DIR / "lgtm.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS installations (
  id INTEGER PRIMARY KEY, account TEXT, account_type TEXT, avatar TEXT,
  repo_selection TEXT, suspended INTEGER DEFAULT 0, created_at TEXT, removed INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS repos (
  id INTEGER PRIMARY KEY, installation_id INTEGER, full_name TEXT UNIQUE, private INTEGER,
  default_branch TEXT, description TEXT, language TEXT, enabled INTEGER DEFAULT 1,
  removed INTEGER DEFAULT 0, added_at TEXT
);
CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY, source TEXT, repo TEXT, repo_id INTEGER, installation_id INTEGER,
  pr_number INTEGER, pr_title TEXT, pr_url TEXT, author TEXT, author_avatar TEXT,
  head_sha TEXT, base_sha TEXT, head_ref TEXT, base_ref TEXT, trigger TEXT,
  status TEXT, conclusion TEXT, verdict TEXT, n_flagged INTEGER DEFAULT 0,
  n_candidates INTEGER DEFAULT 0, severity_max TEXT, stage TEXT,
  check_run_id INTEGER, check_url TEXT, review_id INTEGER, review_url TEXT,
  created_at TEXT, started_at TEXT, finished_at TEXT, latency REAL,
  backend TEXT, model TEXT, error TEXT,
  imported_dataset TEXT, imported_mode TEXT, imported_key TEXT, outcome TEXT, expected TEXT,
  advisory TEXT, merged INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS runs_repo ON runs(repo, created_at);
CREATE INDEX IF NOT EXISTS runs_pr ON runs(repo, pr_number, head_sha);
CREATE TABLE IF NOT EXISTS events (run_id TEXT, seq INTEGER, body TEXT, PRIMARY KEY (run_id, seq));
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, run_id TEXT, source TEXT, repo TEXT, pr_number INTEGER, pr_title TEXT,
  file TEXT, line INTEGER, cwe TEXT, category TEXT, severity TEXT, agent TEXT,
  flagged INTEGER, kev_verdict TEXT, title TEXT, explanation TEXT,
  status TEXT DEFAULT 'open', note TEXT, created_at TEXT, updated_at TEXT
);
CREATE INDEX IF NOT EXISTS findings_status ON findings(status, flagged);
CREATE TABLE IF NOT EXISTS deliveries (
  id TEXT PRIMARY KEY, event TEXT, action TEXT, repo TEXT, received_at TEXT,
  via TEXT, verified INTEGER, outcome TEXT
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS finding_briefs (key TEXT PRIMARY KEY, body TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS suggestions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, repo TEXT, pr_number INTEGER, head_sha TEXT, run_id TEXT, finding_key TEXT,
  path TEXT, start_line INTEGER, end_line INTEGER, replacement TEXT, created_at TEXT
);
"""

DEFAULT_SETTINGS = {
    # Fail the check run (so branch protection can block the merge) at or above this severity.
    "block_on": "high",
    "request_changes": True,     # post the review as "Request changes" when the check fails
    "inline_comments": True,
    "backend": "gpu",            # reviewer: gpu (Qwen on the cluster) or bedrock (Claude)
    "judge": "kev",              # evidence judge: kev (Kev-4B on :8008, this Mac or the GPU job) or claude (stand-in on :8009)
    "poll_seconds": 30,
    "auto_review": True,
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1, "unrated": 0, "": 0, None: 0}


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


class Store:
    def __init__(self, path: Path = DB_PATH):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.executescript(SCHEMA)
            try:   # which judge decided a run (added after the first demos)
                self.db.execute("ALTER TABLE runs ADD COLUMN judge TEXT")
            except sqlite3.OperationalError:
                pass

    # -- generic helpers ---------------------------------------------------
    def q(self, sql: str, args: tuple | list = ()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def one(self, sql: str, args: tuple | list = ()) -> dict | None:
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql: str, args: tuple | list = ()) -> int:
        with self.lock:
            return self.db.execute(sql, args).rowcount

    def upsert(self, table: str, row: dict, key: str = "id") -> None:
        cols = list(row)
        sets = ", ".join(f"{c}=excluded.{c}" for c in cols if c != key)
        sql = (f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))}) "
               f"ON CONFLICT({key}) DO UPDATE SET {sets}")
        self.x(sql, [row[c] for c in cols])

    def update(self, table: str, row_id, **fields) -> None:
        if fields:
            self.x(f"UPDATE {table} SET {', '.join(f'{k}=?' for k in fields)} WHERE id=?",
                   [*fields.values(), row_id])

    # -- settings ------------------------------------------------------------
    def settings(self) -> dict:
        out = dict(DEFAULT_SETTINGS)
        for r in self.q("SELECT key, value FROM settings"):
            out[r["key"]] = json.loads(r["value"])
        return out

    def set_setting(self, key: str, value) -> None:
        if key not in DEFAULT_SETTINGS:
            raise KeyError(key)
        self.upsert("settings", {"key": key, "value": json.dumps(value)}, key="key")

    # -- runs ----------------------------------------------------------------
    def run(self, run_id: str) -> dict | None:
        return self.one("SELECT * FROM runs WHERE id=?", (run_id,))

    def add_event(self, run_id: str, seq: int, event: dict) -> None:
        self.x("INSERT OR REPLACE INTO events (run_id, seq, body) VALUES (?, ?, ?)",
               (run_id, seq, json.dumps(event, default=str)))

    def events(self, run_id: str, start: int = 0) -> list[dict]:
        return [json.loads(r["body"]) for r in
                self.q("SELECT body FROM events WHERE run_id=? AND seq>=? ORDER BY seq", (run_id, start))]

    def pending_for(self, repo: str, pr_number: int, head_sha: str) -> dict | None:
        """A run for this exact commit that is queued, running, done, cancelled or failed, so the webhook and the poller
        do not review it again on their own. Cancelling must stick; a failed review is re-run on purpose (GitHub's
        Re-run button or the dashboard), which goes through ``enqueue(force=True)`` and skips this check."""
        return self.one("SELECT * FROM runs WHERE repo=? AND pr_number=? AND head_sha=? AND source='github' "
                        "AND status IN ('queued','running','completed','cancelled','failed') ORDER BY created_at DESC LIMIT 1",
                        (repo, pr_number, head_sha))
