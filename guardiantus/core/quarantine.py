"""The quarantine vault.

Quarantined files are moved out of reach and stored obfuscated so that they
can neither execute nor be re-detected by other on-access scanners while
parked.  The transform is a keyed XOR stream derived from a per-install key --
this is *containment, not cryptography*: the goal is to render the sample
inert and non-executable, and it is reversible by design so a false positive
can be restored byte-for-byte.

Layout::

    <home>/quarantine/<entry-id>.qtn   payload, XOR-obfuscated
    <home>/quarantine/vault.key        random per-install key
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import paths
from .db import Database, get_db
from .models import QuarantineEntry, ScanResult, Severity

KEY_SIZE = 64
MAGIC = b"GQTN\x01"


class QuarantineError(RuntimeError):
    """Raised when a file cannot be quarantined or restored."""


class Quarantine:
    def __init__(self, db: Optional[Database] = None, directory: Optional[Path] = None) -> None:
        self.db = db or get_db()
        self.dir = directory or paths.quarantine_dir()
        self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._key = self._load_or_create_key()

    # ------------------------------------------------------------------ key
    def _load_or_create_key(self) -> bytes:
        key_file = self.dir / "vault.key"
        if key_file.exists():
            data = key_file.read_bytes()
            if len(data) >= KEY_SIZE:
                return data[:KEY_SIZE]
        key = secrets.token_bytes(KEY_SIZE)
        key_file.write_bytes(key)
        try:
            key_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        return key

    def _transform(self, data: bytes) -> bytes:
        key = self._key
        key_len = len(key)
        return bytes(byte ^ key[index % key_len] for index, byte in enumerate(data))

    # ----------------------------------------------------------- operations
    def quarantine_file(self, result: ScanResult) -> QuarantineEntry:
        """Move the file behind ``result.path`` into the vault."""
        source = Path(result.path)
        if not source.is_file():
            raise QuarantineError(f"not a regular file: {source}")

        entry_id = uuid.uuid4().hex
        stored_name = f"{entry_id}.qtn"
        target = self.dir / stored_name

        try:
            original_mode = stat.S_IMODE(source.stat().st_mode)
            payload = source.read_bytes()
        except OSError as exc:
            raise QuarantineError(f"cannot read {source}: {exc}") from exc

        try:
            with open(target, "wb") as handle:
                handle.write(MAGIC)
                handle.write(self._transform(payload))
            try:
                target.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
            source.unlink()
        except OSError as exc:
            target.unlink(missing_ok=True)
            raise QuarantineError(f"cannot quarantine {source}: {exc}") from exc

        entry = QuarantineEntry(
            entry_id=entry_id,
            original_path=str(source),
            threat_name=result.primary_name or "Unknown",
            severity=result.severity,
            sha256=result.sha256,
            size=len(payload),
            quarantined_at=time.time(),
            stored_name=stored_name,
            detections=[d.to_dict() for d in result.detections],
            original_mode=original_mode,
        )
        with self._lock:
            self.db.add_quarantine(entry.to_dict())
            self.db.add_event(
                "warning",
                "quarantine",
                f"Quarantined {source.name}",
                {"path": str(source), "threat": entry.threat_name, "entry_id": entry_id},
            )
        self.enforce_limits()
        return entry

    def restore(self, entry_id: str, destination: Optional[Path] = None) -> Path:
        """Put a quarantined file back, byte-for-byte."""
        record = self.db.get_quarantine(entry_id)
        if not record:
            raise QuarantineError(f"unknown quarantine entry: {entry_id}")
        if record["deleted"]:
            raise QuarantineError("entry was permanently deleted")
        if record["restored"]:
            raise QuarantineError("entry was already restored")

        stored = self.dir / record["stored_name"]
        if not stored.is_file():
            raise QuarantineError("vault payload is missing")

        target = Path(destination) if destination else Path(record["original_path"])
        target.parent.mkdir(parents=True, exist_ok=True)

        blob = stored.read_bytes()
        if blob.startswith(MAGIC):
            blob = blob[len(MAGIC):]
        payload = self._transform(blob)

        try:
            target.write_bytes(payload)
            if record.get("original_mode"):
                target.chmod(int(record["original_mode"]))
        except OSError as exc:
            raise QuarantineError(f"cannot restore to {target}: {exc}") from exc

        stored.unlink(missing_ok=True)
        with self._lock:
            self.db.update_quarantine_flags(entry_id, restored=True, deleted=False)
            self.db.add_event(
                "info",
                "quarantine",
                f"Restored {target.name}",
                {"path": str(target), "entry_id": entry_id},
            )
        return target

    def delete(self, entry_id: str) -> None:
        """Destroy the vault copy for good."""
        record = self.db.get_quarantine(entry_id)
        if not record:
            raise QuarantineError(f"unknown quarantine entry: {entry_id}")
        stored = self.dir / record["stored_name"]
        _shred(stored)
        with self._lock:
            self.db.update_quarantine_flags(entry_id, restored=bool(record["restored"]), deleted=True)
            self.db.add_event(
                "info",
                "quarantine",
                f"Deleted quarantined item {record['original_path']}",
                {"entry_id": entry_id},
            )

    def empty(self) -> int:
        """Delete every active vault entry. Returns the number removed."""
        removed = 0
        for record in self.db.list_quarantine():
            try:
                self.delete(record["entry_id"])
                removed += 1
            except QuarantineError:
                continue
        return removed

    def list_entries(self, include_inactive: bool = False) -> List[Dict[str, Any]]:
        return self.db.list_quarantine(include_inactive=include_inactive)

    def enforce_limits(self, max_entries: int = 1000, retention_days: int = 90) -> int:
        """Trim the vault by age and count. Returns entries dropped."""
        entries = self.db.list_quarantine()
        dropped = 0
        cutoff = time.time() - retention_days * 86400
        for record in entries:
            if record["quarantined_at"] < cutoff:
                try:
                    self.delete(record["entry_id"])
                    dropped += 1
                except QuarantineError:
                    continue
        remaining = self.db.list_quarantine()
        if len(remaining) > max_entries:
            excess = sorted(remaining, key=lambda r: r["quarantined_at"])[: len(remaining) - max_entries]
            for record in excess:
                try:
                    self.delete(record["entry_id"])
                    dropped += 1
                except QuarantineError:
                    continue
        return dropped

    def stats(self) -> Dict[str, Any]:
        entries = self.db.list_quarantine()
        return {
            "count": len(entries),
            "bytes": sum(int(e.get("size", 0)) for e in entries),
            "severities": {
                severity.value: sum(1 for e in entries if e.get("severity") == severity.value)
                for severity in Severity
            },
        }


def _shred(path: Path, passes: int = 1) -> None:
    """Overwrite then unlink, best effort (no guarantees on CoW filesystems)."""
    if not path.is_file():
        return
    try:
        size = path.stat().st_size
        with open(path, "r+b") as handle:
            for _ in range(passes):
                handle.seek(0)
                handle.write(os.urandom(size))
                handle.flush()
                os.fsync(handle.fileno())
    except OSError:
        pass
    try:
        path.unlink()
    except OSError:
        shutil.rmtree(path, ignore_errors=True)


_INSTANCE: Optional[Quarantine] = None
_INSTANCE_LOCK = threading.Lock()


def get_quarantine() -> Quarantine:
    global _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is None:
            _INSTANCE = Quarantine()
        return _INSTANCE


def reset_quarantine_cache() -> None:
    global _INSTANCE
    with _INSTANCE_LOCK:
        _INSTANCE = None
