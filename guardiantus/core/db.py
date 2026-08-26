"""SQLite persistence for events, scan history, detections and quarantine.

A single connection guarded by a lock is plenty for a desktop product and
keeps the code free of session/pooling machinery.  WAL mode lets the
dashboard read while a scan writes.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .. import paths

SCHEMA_VERSION = 1

#: Conservative cap on bound parameters per statement -- see describe_digests.
_MAX_SQL_PARAMS = 500

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        REAL NOT NULL,
    level     TEXT NOT NULL,
    category  TEXT NOT NULL,
    message   TEXT NOT NULL,
    details   TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);

CREATE TABLE IF NOT EXISTS scans (
    scan_id        TEXT PRIMARY KEY,
    scan_type      TEXT NOT NULL,
    state          TEXT NOT NULL,
    started_at     REAL NOT NULL,
    finished_at    REAL,
    files_scanned  INTEGER NOT NULL DEFAULT 0,
    files_skipped  INTEGER NOT NULL DEFAULT 0,
    bytes_scanned  INTEGER NOT NULL DEFAULT 0,
    threats_found  INTEGER NOT NULL DEFAULT 0,
    errors         INTEGER NOT NULL DEFAULT 0,
    targets        TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);

CREATE TABLE IF NOT EXISTS detections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT,
    ts          REAL NOT NULL,
    path        TEXT NOT NULL,
    sha256      TEXT NOT NULL DEFAULT '',
    verdict     TEXT NOT NULL,
    severity    TEXT NOT NULL,
    threat_name TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT '',
    handled     TEXT NOT NULL DEFAULT 'none',
    payload     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_detections_ts ON detections(ts DESC);
CREATE INDEX IF NOT EXISTS idx_detections_scan ON detections(scan_id);

CREATE TABLE IF NOT EXISTS quarantine (
    entry_id       TEXT PRIMARY KEY,
    original_path  TEXT NOT NULL,
    stored_name    TEXT NOT NULL,
    threat_name    TEXT NOT NULL DEFAULT '',
    severity       TEXT NOT NULL DEFAULT 'medium',
    sha256         TEXT NOT NULL DEFAULT '',
    size           INTEGER NOT NULL DEFAULT 0,
    quarantined_at REAL NOT NULL,
    restored       INTEGER NOT NULL DEFAULT 0,
    deleted        INTEGER NOT NULL DEFAULT 0,
    original_mode  INTEGER,
    detections     TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_quarantine_ts ON quarantine(quarantined_at DESC);
"""


class Database:
    """Thin, thread-safe wrapper around the application database."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or paths.database_file()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._closed = False
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(_SCHEMA)
            self._conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._conn.commit()

    # ---------------------------------------------------------------- basics
    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._conn.close()

    @property
    def closed(self) -> bool:
        return self._closed

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur

    def query(self, sql: str, params: Iterable[Any] = ()) -> List[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            return [dict(row) for row in cur.fetchall()]

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> Optional[Dict[str, Any]]:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # ----------------------------------------------------------------- meta
    def get_meta(self, key: str, default: str = "") -> str:
        try:
            row = self.query_one("SELECT value FROM meta WHERE key = ?", (key,))
        except sqlite3.ProgrammingError:
            return default
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        try:
            self.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value))
        except sqlite3.ProgrammingError:
            pass  # see add_event: shutdown races must not raise

    # --------------------------------------------------------------- events
    def add_event(
        self,
        level: str,
        category: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Append to the activity log.

        Logging is best effort: a background scan or scheduled task can still
        be finishing when the application shuts the database, and losing that
        last log line is preferable to crashing the worker thread.
        """
        try:
            cur = self.execute(
                "INSERT INTO events(ts, level, category, message, details) VALUES(?, ?, ?, ?, ?)",
                (time.time(), level, category, message, json.dumps(details or {})),
            )
        except sqlite3.ProgrammingError:
            return 0
        return int(cur.lastrowid or 0)

    def recent_events(self, limit: int = 100, category: str = "") -> List[Dict[str, Any]]:
        if category:
            rows = self.query(
                "SELECT * FROM events WHERE category = ? ORDER BY ts DESC LIMIT ?",
                (category, limit),
            )
        else:
            rows = self.query("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))
        for row in rows:
            row["details"] = _loads(row.get("details"), {})
        return rows

    def prune_events(self, keep: int = 5000) -> int:
        cur = self.execute(
            "DELETE FROM events WHERE id NOT IN "
            "(SELECT id FROM events ORDER BY ts DESC LIMIT ?)",
            (keep,),
        )
        return cur.rowcount or 0

    # ---------------------------------------------------------------- scans
    def upsert_scan(self, progress: Dict[str, Any]) -> None:
        self.execute(
            """
            INSERT INTO scans(scan_id, scan_type, state, started_at, finished_at,
                              files_scanned, files_skipped, bytes_scanned,
                              threats_found, errors, targets)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                state=excluded.state,
                finished_at=excluded.finished_at,
                files_scanned=excluded.files_scanned,
                files_skipped=excluded.files_skipped,
                bytes_scanned=excluded.bytes_scanned,
                threats_found=excluded.threats_found,
                errors=excluded.errors
            """,
            (
                progress["scan_id"],
                progress["scan_type"],
                progress["state"],
                progress["started_at"],
                progress.get("finished_at"),
                progress.get("files_scanned", 0),
                progress.get("files_skipped", 0),
                progress.get("bytes_scanned", 0),
                progress.get("threats_found", 0),
                progress.get("errors", 0),
                json.dumps(progress.get("targets", [])),
            ),
        )

    def recent_scans(self, limit: int = 25) -> List[Dict[str, Any]]:
        rows = self.query("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,))
        for row in rows:
            row["targets"] = _loads(row.get("targets"), [])
        return rows

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        row = self.query_one("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        if row:
            row["targets"] = _loads(row.get("targets"), [])
        return row

    def last_completed_scan(self) -> Optional[Dict[str, Any]]:
        row = self.query_one(
            "SELECT * FROM scans WHERE state = 'completed' ORDER BY finished_at DESC LIMIT 1"
        )
        if row:
            row["targets"] = _loads(row.get("targets"), [])
        return row

    # ----------------------------------------------------------- detections
    def add_detection(self, scan_id: Optional[str], result: Dict[str, Any], handled: str = "none") -> int:
        sources = ",".join(sorted({d.get("source", "") for d in result.get("detections", [])}))
        cur = self.execute(
            """
            INSERT INTO detections(scan_id, ts, path, sha256, verdict, severity,
                                   threat_name, source, handled, payload)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                result.get("scanned_at", time.time()),
                result.get("path", ""),
                result.get("sha256", ""),
                result.get("verdict", "suspicious"),
                result.get("severity", "medium"),
                result.get("name", ""),
                sources,
                handled,
                json.dumps(result),
            ),
        )
        return int(cur.lastrowid or 0)

    def recent_detections(self, limit: int = 100, scan_id: str = "") -> List[Dict[str, Any]]:
        if scan_id:
            rows = self.query(
                "SELECT * FROM detections WHERE scan_id = ? ORDER BY ts DESC LIMIT ?",
                (scan_id, limit),
            )
        else:
            rows = self.query("SELECT * FROM detections ORDER BY ts DESC LIMIT ?", (limit,))
        for row in rows:
            row["payload"] = _loads(row.get("payload"), {})
        return rows

    def count_detections(self, since: float = 0.0) -> int:
        row = self.query_one("SELECT COUNT(*) AS n FROM detections WHERE ts >= ?", (since,))
        return int(row["n"]) if row else 0

    def get_detection(self, detection_id: int) -> Optional[Dict[str, Any]]:
        row = self.query_one("SELECT * FROM detections WHERE id = ?", (detection_id,))
        if row:
            row["payload"] = _loads(row.get("payload"), {})
        return row

    def describe_digests(self, digests: Iterable[str]) -> Dict[str, Dict[str, Any]]:
        """Where each digest was last seen, so an allow-list can name files.

        The allow-list itself only stores hashes; the history is what turns
        one back into "the file you restored from Downloads".
        """
        wanted = [d for d in digests if d]
        if not wanted:
            return {}

        rows: List[Dict[str, Any]] = []
        # Bound the IN clause: SQLite before 3.32 refuses more than 999
        # parameters, and the allow-list is allowed to hold a thousand.
        for start in range(0, len(wanted), _MAX_SQL_PARAMS):
            batch = wanted[start:start + _MAX_SQL_PARAMS]
            placeholders = ",".join("?" for _ in batch)
            rows += self.query(
                f"SELECT sha256, path, ts FROM detections WHERE sha256 IN ({placeholders})",
                batch,
            )
            rows += self.query(
                "SELECT sha256, original_path AS path, quarantined_at AS ts FROM quarantine "
                f"WHERE sha256 IN ({placeholders})",
                batch,
            )
        seen: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            digest = str(row["sha256"]).lower()
            if digest not in seen or float(row["ts"] or 0) > float(seen[digest]["ts"] or 0):
                seen[digest] = {"path": row["path"], "ts": row["ts"]}
        return seen

    def mark_detections_restored(self, path: str) -> None:
        """Stop showing a restored file as a live threat in the detection list."""
        self.execute(
            "UPDATE detections SET handled = 'restored' WHERE path = ? AND handled = 'quarantined'",
            (path,),
        )

    def mark_detection_handled(self, detection_id: int, handled: str) -> None:
        self.execute("UPDATE detections SET handled = ? WHERE id = ?", (handled, detection_id))

    # ----------------------------------------------------------- quarantine
    def add_quarantine(self, entry: Dict[str, Any]) -> None:
        self.execute(
            """
            INSERT OR REPLACE INTO quarantine(entry_id, original_path, stored_name,
                threat_name, severity, sha256, size, quarantined_at, restored,
                deleted, original_mode, detections)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry["entry_id"],
                entry["original_path"],
                entry["stored_name"],
                entry.get("threat_name", ""),
                entry.get("severity", "medium"),
                entry.get("sha256", ""),
                entry.get("size", 0),
                entry.get("quarantined_at", time.time()),
                int(bool(entry.get("restored"))),
                int(bool(entry.get("deleted"))),
                entry.get("original_mode"),
                json.dumps(entry.get("detections", [])),
            ),
        )

    def list_quarantine(self, include_inactive: bool = False) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM quarantine"
        if not include_inactive:
            sql += " WHERE restored = 0 AND deleted = 0"
        sql += " ORDER BY quarantined_at DESC"
        rows = self.query(sql)
        for row in rows:
            row["detections"] = _loads(row.get("detections"), [])
            row["restored"] = bool(row["restored"])
            row["deleted"] = bool(row["deleted"])
        return rows

    def get_quarantine(self, entry_id: str) -> Optional[Dict[str, Any]]:
        row = self.query_one("SELECT * FROM quarantine WHERE entry_id = ?", (entry_id,))
        if row:
            row["detections"] = _loads(row.get("detections"), [])
            row["restored"] = bool(row["restored"])
            row["deleted"] = bool(row["deleted"])
        return row

    def update_quarantine_flags(
        self, entry_id: str, *, restored: bool = False, deleted: bool = False
    ) -> None:
        self.execute(
            "UPDATE quarantine SET restored = ?, deleted = ? WHERE entry_id = ?",
            (int(restored), int(deleted), entry_id),
        )

    # ------------------------------------------------------------ dashboard
    def stats(self) -> Dict[str, Any]:
        day_ago = time.time() - 86400
        week_ago = time.time() - 7 * 86400
        return {
            "total_scans": _scalar(self.query_one("SELECT COUNT(*) AS n FROM scans")),
            "total_detections": _scalar(self.query_one("SELECT COUNT(*) AS n FROM detections")),
            "detections_24h": self.count_detections(day_ago),
            "detections_7d": self.count_detections(week_ago),
            "quarantined": _scalar(
                self.query_one("SELECT COUNT(*) AS n FROM quarantine WHERE restored = 0 AND deleted = 0")
            ),
            "files_scanned_total": _scalar(
                self.query_one("SELECT COALESCE(SUM(files_scanned), 0) AS n FROM scans")
            ),
            "last_scan": self.last_completed_scan(),
        }


def _scalar(row: Optional[Dict[str, Any]]) -> int:
    if not row:
        return 0
    return int(next(iter(row.values())) or 0)


def _loads(raw: Any, fallback: Any) -> Any:
    if not raw:
        return fallback
    try:
        return json.loads(raw)
    except (TypeError, ValueError):
        return fallback


_INSTANCE: Optional[Database] = None
_INSTANCE_LOCK = threading.Lock()


def get_db() -> Database:
    """Process-wide database singleton."""
    global _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is None:
            _INSTANCE = Database()
        return _INSTANCE


def reset_db_cache() -> None:
    global _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is not None:
            try:
                _INSTANCE.close()
            except sqlite3.Error:
                pass
        _INSTANCE = None
