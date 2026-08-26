"""Persistent configuration.

The configuration is a plain JSON document.  Unknown keys from a newer version
are preserved on save so downgrading does not silently drop settings, and
missing keys fall back to :data:`DEFAULTS`.
"""

from __future__ import annotations

import copy
import json
import os
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

from . import paths

_LOCK = threading.RLock()

#: Cap on the allow-list so it cannot grow without bound.
MAX_TRUSTED_HASHES = 1000

DEFAULTS: Dict[str, Any] = {
    "general": {
        "language": "en",
        "theme": "system",  # light | dark | system
        "first_run_completed": False,
    },
    "scanning": {
        # Files above this size are hashed but not deep-inspected.
        "max_file_size_mb": 512,
        # Archives are unpacked in memory up to this many bytes per member.
        "max_archive_member_mb": 64,
        "max_archive_members": 512,
        "scan_archives": True,
        # Move threats found by a manual/scheduled scan into the vault.
        # An antivirus that finds malware and leaves it in place is not
        # protecting anyone, so this is on by default; the CLI can override it
        # per run with --quarantine / --no-quarantine.
        "auto_quarantine": True,
        "follow_symlinks": False,
        "heuristics_enabled": True,
        "yara_enabled": True,
        "worker_threads": 0,  # 0 => auto (cpu_count, capped)
        "excluded_paths": [],
        "excluded_extensions": [],
        # Minimum score at which a heuristic hit is reported as a detection.
        "heuristic_threshold": 60,
        # Heuristics are guesses. Off by default, only files identified by a
        # signature or a YARA rule are moved into the vault.
        "quarantine_suspicious": False,
        # SHA-256 of files the user restored from quarantine. Never flagged
        # again -- otherwise a restore undoes itself on the next scan.
        "trusted_hashes": [],
    },
    "realtime": {
        "enabled": False,
        "watch_paths": [],  # empty => sensible per-platform defaults
        "action": "quarantine",  # report | quarantine
        "scan_on_create": True,
        "scan_on_modify": True,
        "debounce_seconds": 1.0,
        "poll_interval_seconds": 3.0,  # fallback watcher only
    },
    "quarantine": {
        "enabled": True,
        "max_entries": 1000,
        "retention_days": 90,
    },
    "updates": {
        "signature_url": "",
        "auto_update_signatures": True,
        "check_interval_hours": 6,
        "programs_auto_check": True,
        "programs_auto_install": False,
    },
    "schedule": {
        "quick_scan_cron": "0 12 * * *",
        "full_scan_cron": "0 3 * * 0",
        "quick_scan_enabled": False,
        "full_scan_enabled": False,
    },
    "service": {
        "host": "127.0.0.1",
        "port": 8787,
        "open_browser": True,
    },
}


def default_watch_paths() -> List[str]:
    """Directories worth watching when the user has not picked any."""
    hits: List[Path] = []
    home_dir = Path.home()
    for name in ("Downloads", "Desktop", "Documents"):
        candidate = home_dir / name
        if candidate.is_dir():
            hits.append(candidate)
    if not hits:
        hits.append(home_dir)

    if sys.platform == "win32":
        temp = os.environ.get("TEMP")
        if temp and Path(temp).is_dir():
            hits.append(Path(temp))
    else:
        tmp = Path("/tmp")
        if tmp.is_dir():
            hits.append(tmp)
    return [str(p) for p in hits]


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Config:
    """Thread-safe accessor around the JSON configuration document."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or paths.config_file()
        self._data: Dict[str, Any] = copy.deepcopy(DEFAULTS)
        self.load()

    # ------------------------------------------------------------------ io
    def load(self) -> Dict[str, Any]:
        with _LOCK:
            if self.path.exists():
                try:
                    stored = json.loads(self.path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    stored = {}
                if isinstance(stored, dict):
                    self._data = _deep_merge(DEFAULTS, stored)
            return self._data

    def save(self) -> None:
        with _LOCK:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, indent=2, sort_keys=True), encoding="utf-8")
            tmp.replace(self.path)

    # --------------------------------------------------------------- access
    @property
    def data(self) -> Dict[str, Any]:
        with _LOCK:
            return copy.deepcopy(self._data)

    def get(self, section: str, key: str, default: Any = None) -> Any:
        with _LOCK:
            bucket = self._data.get(section, {})
            if key in bucket:
                return copy.deepcopy(bucket[key])
            fallback = DEFAULTS.get(section, {}).get(key, default)
            return copy.deepcopy(fallback)

    def set(self, section: str, key: str, value: Any) -> None:
        with _LOCK:
            self._data.setdefault(section, {})[key] = value
        self.save()

    def update(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        """Merge a (possibly partial) configuration document and persist it."""
        with _LOCK:
            self._data = _deep_merge(self._data, patch)
        self.save()
        return self.data

    # ------------------------------------------------------------- helpers
    def watch_paths(self) -> List[str]:
        configured = self.get("realtime", "watch_paths") or []
        return list(configured) if configured else default_watch_paths()

    def excluded_paths(self) -> List[Path]:
        out: List[Path] = []
        for raw in self.get("scanning", "excluded_paths") or []:
            try:
                out.append(Path(raw).expanduser().resolve())
            except OSError:
                continue
        return out

    def trusted_hashes(self) -> Set[str]:
        """Digests the user has explicitly allowed."""
        return {
            str(digest).lower()
            for digest in (self.get("scanning", "trusted_hashes") or [])
            if digest
        }

    def trust_hash(self, digest: str) -> None:
        """Remember that the user considers this exact file harmless."""
        if not digest:
            return
        with _LOCK:
            bucket = self._data.setdefault("scanning", {})
            current = [str(h).lower() for h in bucket.get("trusted_hashes") or []]
            digest = digest.lower()
            if digest in current:
                return
            current.append(digest)
            bucket["trusted_hashes"] = current[-MAX_TRUSTED_HASHES:]
        self.save()

    def revoke_hash(self, digest: str) -> bool:
        """Take a digest off the allow-list. Returns whether it was on it."""
        digest = str(digest).lower()
        with _LOCK:
            bucket = self._data.setdefault("scanning", {})
            current = [str(h).lower() for h in bucket.get("trusted_hashes") or []]
            if digest not in current:
                return False
            bucket["trusted_hashes"] = [h for h in current if h != digest]
        self.save()
        return True

    def excluded_extensions(self) -> Iterable[str]:
        return {
            ext.lower() if ext.startswith(".") else f".{ext.lower()}"
            for ext in (self.get("scanning", "excluded_extensions") or [])
        }


_INSTANCE: Config | None = None


def get_config() -> Config:
    """Process-wide configuration singleton."""
    global _INSTANCE
    with _LOCK:
        if _INSTANCE is None:
            _INSTANCE = Config()
        return _INSTANCE


def reset_config_cache() -> None:
    """Drop the singleton -- used by the test-suite between temp homes."""
    global _INSTANCE
    with _LOCK:
        _INSTANCE = None
