"""Real-time (on-access) protection.

Two backends:

``watchdog``
    Event-driven via inotify / FSEvents / ReadDirectoryChangesW.  Used when
    the optional ``watchdog`` package is installed.

``poll``
    A stdlib fallback that walks the watched trees on an interval and reacts
    to new or modified files.  Slower to notice a change, but it keeps
    real-time protection working on a bare Python install.

Both feed the same debounced work queue, so the handling logic -- scan,
report, optionally quarantine -- exists only once.
"""

from __future__ import annotations

import os
import queue
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..config import Config, get_config
from .db import Database, get_db
from .models import ScanResult, Verdict
from .quarantine import Quarantine, QuarantineError, get_quarantine
from .scanner import FileScanner

try:  # pragma: no cover - depends on the host environment
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer

    HAVE_WATCHDOG = True
except ImportError:  # pragma: no cover
    FileSystemEvent = object  # type: ignore[assignment,misc]
    FileSystemEventHandler = object  # type: ignore[assignment,misc]
    Observer = None  # type: ignore[assignment]
    HAVE_WATCHDOG = False


#: Files that are almost certainly still being written; skip them this round.
_TRANSIENT_SUFFIXES = (".part", ".crdownload", ".tmp", ".download", ".partial", "~")


class _WatchdogHandler(FileSystemEventHandler):  # pragma: no cover - needs watchdog
    def __init__(self, enqueue: Callable[[str], None], on_create: bool, on_modify: bool) -> None:
        super().__init__()
        self._enqueue = enqueue
        self._on_create = on_create
        self._on_modify = on_modify

    def on_created(self, event: FileSystemEvent) -> None:
        if self._on_create and not event.is_directory:
            self._enqueue(event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if self._on_modify and not event.is_directory:
            self._enqueue(event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:
        destination = getattr(event, "dest_path", "")
        if self._on_create and destination and not event.is_directory:
            self._enqueue(destination)


class RealtimeProtection:
    """Watches configured directories and reacts to file changes."""

    def __init__(
        self,
        config: Optional[Config] = None,
        scanner: Optional[FileScanner] = None,
        db: Optional[Database] = None,
        quarantine: Optional[Quarantine] = None,
        on_detection: Optional[Callable[[ScanResult], None]] = None,
    ) -> None:
        self.config = config or get_config()
        self.scanner = scanner or FileScanner(config=self.config)
        self.db = db or get_db()
        self.quarantine = quarantine or get_quarantine()
        self.on_detection = on_detection

        self._queue: queue.Queue[str] = queue.Queue(maxsize=10000)
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._worker: Optional[threading.Thread] = None
        self._poller: Optional[threading.Thread] = None
        self._observer: Any = None
        self._seen: Dict[str, float] = {}
        self._started_at: float = 0.0
        self._watched: List[str] = []

        self.events_handled = 0
        self.threats_blocked = 0
        self.last_event: Dict[str, Any] = {}

    # ------------------------------------------------------------ lifecycle
    @property
    def running(self) -> bool:
        return self._worker is not None and self._worker.is_alive() and not self._stop.is_set()

    @property
    def backend(self) -> str:
        if self._observer is not None:
            return "watchdog"
        return "poll" if self._poller is not None else "stopped"

    def start(self, watch_paths: Optional[List[str]] = None) -> Dict[str, Any]:
        with self._lock:
            if self.running:
                return self.status()

            self._stop.clear()
            self._started_at = time.time()
            raw = watch_paths if watch_paths is not None else self.config.watch_paths()
            self._watched = [str(Path(p).expanduser()) for p in raw if Path(p).expanduser().is_dir()]
            if not self._watched:
                raise RuntimeError("no valid directories to watch")

            self._worker = threading.Thread(target=self._consume, name="gav-realtime", daemon=True)
            self._worker.start()

            if HAVE_WATCHDOG and Observer is not None:
                self._start_watchdog()
            else:
                self._start_poller()

            self.db.add_event(
                "info",
                "realtime",
                f"Real-time protection enabled ({self.backend})",
                {"paths": self._watched, "backend": self.backend},
            )
            return self.status()

    def _start_watchdog(self) -> None:  # pragma: no cover - needs watchdog
        handler = _WatchdogHandler(
            self._enqueue,
            bool(self.config.get("realtime", "scan_on_create", True)),
            bool(self.config.get("realtime", "scan_on_modify", True)),
        )
        observer = Observer()
        for path in self._watched:
            try:
                observer.schedule(handler, path, recursive=True)
            except OSError as exc:
                self.db.add_event("error", "realtime", f"Cannot watch {path}: {exc}", {"path": path})
        observer.daemon = True
        observer.start()
        self._observer = observer

    def _start_poller(self) -> None:
        self._poller = threading.Thread(target=self._poll_loop, name="gav-realtime-poll", daemon=True)
        self._poller.start()

    def stop(self) -> Dict[str, Any]:
        with self._lock:
            self._stop.set()
            if self._observer is not None:
                try:
                    self._observer.stop()
                    self._observer.join(timeout=5)
                except RuntimeError:
                    pass
                self._observer = None
            if self._poller is not None:
                self._poller.join(timeout=5)
                self._poller = None
            if self._worker is not None:
                # Unblock the consumer's get().
                try:
                    self._queue.put_nowait("")
                except queue.Full:
                    pass
                self._worker.join(timeout=5)
                self._worker = None
            self.db.add_event("info", "realtime", "Real-time protection disabled", {})
            return self.status()

    def status(self) -> Dict[str, Any]:
        return {
            "running": self.running,
            "backend": self.backend,
            "watch_paths": list(self._watched),
            "queued": self._queue.qsize(),
            "events_handled": self.events_handled,
            "threats_blocked": self.threats_blocked,
            "started_at": self._started_at if self.running else None,
            "uptime": round(time.time() - self._started_at, 1) if self.running else 0,
            "action": self.config.get("realtime", "action", "quarantine"),
            "watchdog_available": HAVE_WATCHDOG,
            "last_event": dict(self.last_event),
        }

    # --------------------------------------------------------------- queue
    def _enqueue(self, path: str) -> None:
        if not path or path.endswith(_TRANSIENT_SUFFIXES):
            return
        debounce = float(self.config.get("realtime", "debounce_seconds", 1.0))
        now = time.time()
        with self._lock:
            last = self._seen.get(path, 0.0)
            if now - last < debounce:
                return
            self._seen[path] = now
            if len(self._seen) > 20000:
                cutoff = now - max(debounce * 10, 60)
                self._seen = {k: v for k, v in self._seen.items() if v >= cutoff}
        try:
            self._queue.put_nowait(path)
        except queue.Full:
            pass

    def _consume(self) -> None:
        while not self._stop.is_set():
            try:
                path = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if not path:
                continue
            try:
                self._handle(Path(path))
            except Exception as exc:  # pragma: no cover - never kill the watcher
                self.db.add_event("error", "realtime", f"Handler error: {exc}", {"path": path})
            finally:
                self._queue.task_done()

    def _handle(self, path: Path) -> None:
        if not path.is_file():
            return
        # Give whatever is writing the file a moment to finish.
        try:
            size_before = path.stat().st_size
            time.sleep(0.05)
            if path.stat().st_size != size_before:
                self._enqueue(str(path))
                return
        except OSError:
            return

        result = self.scanner.scan_file(path)
        self.events_handled += 1
        self.last_event = {
            "path": str(path),
            "verdict": result.verdict.value,
            "at": time.time(),
        }
        if result.verdict is Verdict.SKIPPED:
            return
        if not result.is_threat:
            return

        handled = "reported"
        action = self.config.get("realtime", "action", "quarantine")
        if action == "quarantine" and self.config.get("quarantine", "enabled", True):
            try:
                entry = self.quarantine.quarantine_file(result)
                result.quarantined = True
                result.quarantine_id = entry.entry_id
                handled = "quarantined"
            except QuarantineError as exc:
                self.db.add_event(
                    "error", "quarantine", f"Could not quarantine {path}: {exc}", {"path": str(path)}
                )

        self.threats_blocked += 1
        self.db.add_detection(None, result.to_dict(), handled=handled)
        self.db.add_event(
            "warning",
            "detection",
            f"Real-time block: {result.primary_name or 'threat'} in {path.name}",
            {
                "path": str(path),
                "severity": result.severity.value,
                "handled": handled,
                "source": "realtime",
            },
        )
        if self.on_detection:
            try:
                self.on_detection(result)
            except Exception:  # pragma: no cover
                pass

    # -------------------------------------------------------- poll backend
    def _poll_loop(self) -> None:
        interval = float(self.config.get("realtime", "poll_interval_seconds", 3.0))
        known: Dict[str, float] = {}
        first_pass = True
        while not self._stop.is_set():
            current: Dict[str, float] = {}
            for root in self._watched:
                for directory, dirnames, filenames in os.walk(root, onerror=lambda _: None):
                    dirnames[:] = [d for d in dirnames if not d.startswith(".git")]
                    for filename in filenames:
                        candidate = os.path.join(directory, filename)
                        try:
                            current[candidate] = os.path.getmtime(candidate)
                        except OSError:
                            continue
                if self._stop.is_set():
                    return
            if not first_pass:
                for candidate, mtime in current.items():
                    previous = known.get(candidate)
                    if previous is None or mtime > previous:
                        self._enqueue(candidate)
            known = current
            first_pass = False
            self._stop.wait(interval)

    # ------------------------------------------------------------ scanning
    def scan_now(self, path: str) -> None:
        """Force a file through the real-time pipeline (used by tests/CLI)."""
        self._handle(Path(path))


_INSTANCE: Optional[RealtimeProtection] = None
_INSTANCE_LOCK = threading.Lock()


def get_realtime() -> RealtimeProtection:
    global _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is None:
            _INSTANCE = RealtimeProtection()
        return _INSTANCE


def reset_realtime_cache() -> None:
    global _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is not None and _INSTANCE.running:
            _INSTANCE.stop()
        _INSTANCE = None
