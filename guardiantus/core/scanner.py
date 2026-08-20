"""Scan orchestration: file inspection, directory walking and scan jobs."""

from __future__ import annotations

import os
import sys
import threading
import time
import uuid
import zipfile
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from .. import paths
from ..config import Config, get_config
from . import heuristics
from .db import Database, get_db
from .hashing import hash_file
from .models import (
    Detection,
    DetectionSource,
    ScanProgress,
    ScanResult,
    ScanState,
    ScanType,
    Severity,
    Verdict,
)
from .quarantine import Quarantine, QuarantineError, get_quarantine
from .signatures import SignatureDatabase, get_signatures
from .yara_engine import YaraEngine, get_yara

#: How much of a file is read into memory for content analysis.
DEEP_READ_BYTES = 4 * 1024 * 1024

#: Directories never worth walking during a full scan.
SKIP_DIRECTORIES = {
    "/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker/overlay2",
    "/System/Volumes", "/private/var/vm",
}
SKIP_DIR_NAMES = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".tox"}


def quick_scan_targets() -> List[Path]:
    """High-risk locations covered by a quick scan."""
    home = Path.home()
    candidates: List[Path] = []
    for name in ("Downloads", "Desktop", "Documents", "AppData/Local/Temp"):
        candidate = home / name
        if candidate.is_dir():
            candidates.append(candidate)

    if sys.platform == "win32":
        for env in ("TEMP", "APPDATA", "LOCALAPPDATA"):
            value = os.environ.get(env)
            if value and Path(value).is_dir():
                candidates.append(Path(value))
    else:
        for extra in ("/tmp", "/var/tmp", str(home / ".local" / "bin"), str(home / ".config" / "autostart")):
            if Path(extra).is_dir():
                candidates.append(Path(extra))

    seen: List[Path] = []
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved not in seen:
            seen.append(resolved)
    return seen or [home]


def full_scan_targets() -> List[Path]:
    """Roots covered by a full system scan."""
    if sys.platform == "win32":
        drives: List[Path] = []
        for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = Path(f"{letter}:\\")
            if drive.exists():
                drives.append(drive)
        return drives or [Path.home()]
    return [Path("/")]


class FileScanner:
    """Stateless inspector: given a path or a buffer, produce a verdict."""

    def __init__(
        self,
        config: Optional[Config] = None,
        signatures: Optional[SignatureDatabase] = None,
        yara: Optional[YaraEngine] = None,
    ) -> None:
        self.config = config or get_config()
        self.signatures = signatures or get_signatures()
        self.yara = yara or get_yara()

    # ------------------------------------------------------------- policies
    def _max_file_size(self) -> int:
        return int(self.config.get("scanning", "max_file_size_mb", 512)) * 1024 * 1024

    def is_excluded(self, path: Path) -> bool:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path

        if resolved.suffix.lower() in self.config.excluded_extensions():
            return True
        for excluded in self.config.excluded_paths():
            if resolved == excluded or excluded in resolved.parents:
                return True
        # Never scan our own vault -- the payloads there are already contained.
        try:
            vault = paths.quarantine_dir().resolve()
            if resolved == vault or vault in resolved.parents:
                return True
        except OSError:
            pass
        return False

    # ---------------------------------------------------------------- entry
    def scan_file(self, path: Path | str, deep: bool = True) -> ScanResult:
        """Inspect one file on disk."""
        started = time.perf_counter()
        path = Path(path)

        try:
            if path.is_symlink() and not self.config.get("scanning", "follow_symlinks", False):
                return ScanResult(
                    path=str(path),
                    verdict=Verdict.SKIPPED,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    error="symlink",
                )
            if not path.is_file():
                return ScanResult(
                    path=str(path),
                    verdict=Verdict.SKIPPED,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    error="not a regular file",
                )
            if self.is_excluded(path):
                return ScanResult(
                    path=str(path),
                    verdict=Verdict.SKIPPED,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    error="excluded",
                )
            size = path.stat().st_size
        except OSError as exc:
            return ScanResult(
                path=str(path),
                verdict=Verdict.ERROR,
                duration_ms=(time.perf_counter() - started) * 1000,
                error=str(exc),
            )

        if size == 0:
            return ScanResult(
                path=str(path),
                verdict=Verdict.CLEAN,
                size=0,
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        oversized = size > self._max_file_size()
        try:
            digests = hash_file(path, max_bytes=None if not oversized else DEEP_READ_BYTES)
        except OSError as exc:
            return ScanResult(
                path=str(path),
                verdict=Verdict.ERROR,
                size=size,
                duration_ms=(time.perf_counter() - started) * 1000,
                error=str(exc),
            )

        detections: List[Detection] = self.signatures.match_hashes(digests)

        data = b""
        if deep and not oversized:
            try:
                with open(path, "rb") as handle:
                    data = handle.read(DEEP_READ_BYTES)
            except OSError as exc:
                return ScanResult(
                    path=str(path),
                    verdict=Verdict.ERROR,
                    sha256=digests.get("sha256", ""),
                    size=size,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    error=str(exc),
                )
            detections.extend(self._inspect_buffer(data, path, size))
            if self.config.get("scanning", "scan_archives", True) and zipfile.is_zipfile(path):
                detections.extend(self._scan_archive(path))

        detections = self._dedupe(detections)
        verdict = self._verdict_for(detections)
        return ScanResult(
            path=str(path),
            verdict=verdict,
            detections=detections,
            sha256=digests.get("sha256", ""),
            size=size,
            duration_ms=(time.perf_counter() - started) * 1000,
            error="oversized: hashed only" if oversized else "",
        )

    def scan_bytes(self, data: bytes, name: str = "<buffer>") -> ScanResult:
        """Inspect an in-memory buffer (used for archive members)."""
        started = time.perf_counter()
        from .hashing import hash_bytes

        digests = hash_bytes(data)
        detections = self.signatures.match_hashes(digests)
        detections.extend(self._inspect_buffer(data, Path(name), len(data)))
        detections = self._dedupe(detections)
        return ScanResult(
            path=name,
            verdict=self._verdict_for(detections),
            detections=detections,
            sha256=digests.get("sha256", ""),
            size=len(data),
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    # ------------------------------------------------------------ internals
    def _inspect_buffer(self, data: bytes, path: Path, size: int) -> List[Detection]:
        detections = self.signatures.match_patterns(data)
        if self.config.get("scanning", "yara_enabled", True):
            detections.extend(self.yara.scan(data))
        if self.config.get("scanning", "heuristics_enabled", True):
            threshold = int(self.config.get("scanning", "heuristic_threshold", 60))
            detections.extend(heuristics.analyse(data, path=path, file_size=size, threshold=threshold))
        return detections

    def _scan_archive(self, path: Path) -> List[Detection]:
        """Inspect archive members without unpacking to disk."""
        max_member = int(self.config.get("scanning", "max_archive_member_mb", 64)) * 1024 * 1024
        max_members = int(self.config.get("scanning", "max_archive_members", 512))
        detections: List[Detection] = []
        try:
            with zipfile.ZipFile(path) as archive:
                for index, info in enumerate(archive.infolist()):
                    if index >= max_members:
                        break
                    if info.is_dir() or info.file_size == 0:
                        continue
                    if info.file_size > max_member:
                        continue
                    # Guard against zip bombs: refuse absurd compression ratios.
                    if info.compress_size and info.file_size / max(info.compress_size, 1) > 1000:
                        detections.append(
                            Detection(
                                name="Archive.ZipBomb.Suspected",
                                source=DetectionSource.ARCHIVE,
                                severity=Severity.MEDIUM,
                                description="Archive member expands at an implausible ratio",
                                score=60,
                                evidence={
                                    "member": info.filename,
                                    "ratio": round(info.file_size / max(info.compress_size, 1)),
                                },
                            )
                        )
                        continue
                    if _is_path_traversal(info.filename):
                        detections.append(
                            Detection(
                                name="Archive.PathTraversal",
                                source=DetectionSource.ARCHIVE,
                                severity=Severity.HIGH,
                                description="Archive member escapes the extraction directory",
                                score=75,
                                evidence={"member": info.filename},
                            )
                        )
                    try:
                        with archive.open(info) as member:
                            payload = member.read(max_member)
                    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
                        continue
                    inner = self.scan_bytes(payload, name=f"{path}!{info.filename}")
                    for detection in inner.detections:
                        detection.evidence["archive_member"] = info.filename
                        detection.evidence["archive"] = str(path)
                        detections.append(detection)
        except (zipfile.BadZipFile, OSError, RuntimeError):
            return detections
        return detections

    @staticmethod
    def _dedupe(detections: Sequence[Detection]) -> List[Detection]:
        """Collapse repeats of the same finding.

        The same threat legitimately fires more than once -- an entry carrying
        both an MD5 and a SHA-256, or an uncompressed archive whose member text
        also matches in the container's own bytes. The user wants one line per
        distinct finding, so keep the highest-scoring instance of each
        ``(name, source)`` pair.
        """
        best: Dict[Tuple[str, str], Detection] = {}
        for detection in detections:
            key = (detection.name, detection.source.value)
            current = best.get(key)
            if current is None or detection.score > current.score:
                best[key] = detection
        return sorted(best.values(), key=lambda d: -d.score)

    @staticmethod
    def _verdict_for(detections: Sequence[Detection]) -> Verdict:
        if not detections:
            return Verdict.CLEAN
        if any(d.source in (DetectionSource.SIGNATURE, DetectionSource.YARA) for d in detections):
            return Verdict.MALICIOUS
        if any(d.severity is Severity.CRITICAL for d in detections):
            return Verdict.MALICIOUS
        return Verdict.SUSPICIOUS


def _is_path_traversal(name: str) -> bool:
    normalised = name.replace("\\", "/")
    if normalised.startswith("/") or ".." in Path(normalised).parts:
        return True
    return len(normalised) > 2 and normalised[1] == ":"


def iter_files(
    targets: Iterable[Path],
    follow_symlinks: bool = False,
    skip_dirs: Optional[Iterable[str]] = None,
) -> Iterator[Path]:
    """Yield every regular file below ``targets``, pruning noisy directories."""
    skip = set(SKIP_DIRECTORIES) | set(skip_dirs or ())
    for target in targets:
        target = Path(target)
        if target.is_file():
            yield target
            continue
        if not target.is_dir():
            continue
        for root, dirnames, filenames in os.walk(target, followlinks=follow_symlinks, onerror=lambda _: None):
            root_path = Path(root)
            dirnames[:] = [
                d
                for d in dirnames
                if d not in SKIP_DIR_NAMES and str(root_path / d) not in skip
            ]
            for filename in filenames:
                candidate = root_path / filename
                if candidate.is_symlink() and not follow_symlinks:
                    continue
                yield candidate


def count_files(targets: Iterable[Path], limit: int = 250_000, follow_symlinks: bool = False) -> int:
    """Cheap pre-pass so the UI can show a real progress bar."""
    total = 0
    for _ in iter_files(targets, follow_symlinks=follow_symlinks):
        total += 1
        if total >= limit:
            break
    return total


class ScanJob:
    """A cancellable, pausable scan running on a worker thread."""

    def __init__(
        self,
        targets: Sequence[Path],
        scan_type: ScanType,
        scanner: Optional[FileScanner] = None,
        config: Optional[Config] = None,
        db: Optional[Database] = None,
        quarantine: Optional[Quarantine] = None,
        auto_quarantine: bool = False,
        on_result: Optional[Callable[[ScanResult], None]] = None,
        on_progress: Optional[Callable[[ScanProgress], None]] = None,
    ) -> None:
        self.config = config or get_config()
        self.scanner = scanner or FileScanner(config=self.config)
        self.db = db or get_db()
        self.quarantine = quarantine or get_quarantine()
        self.auto_quarantine = auto_quarantine
        self.on_result = on_result
        self.on_progress = on_progress

        self.scan_id = uuid.uuid4().hex[:12]
        self.targets = [Path(t) for t in targets]
        self.progress = ScanProgress(
            scan_id=self.scan_id,
            scan_type=scan_type,
            targets=[str(t) for t in self.targets],
        )
        self.results: List[ScanResult] = []
        self.threats: List[ScanResult] = []

        self._cancel = threading.Event()
        self._pause = threading.Event()
        self._pause.set()  # set == running
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None

    # ----------------------------------------------------------- lifecycle
    def start(self) -> ScanJob:
        self._thread = threading.Thread(target=self.run, name=f"scan-{self.scan_id}", daemon=True)
        self._thread.start()
        return self

    def join(self, timeout: Optional[float] = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def cancel(self) -> None:
        self._cancel.set()
        self._pause.set()

    def pause(self) -> None:
        if self.progress.state is ScanState.RUNNING:
            self._pause.clear()
            self.progress.state = ScanState.PAUSED

    def resume(self) -> None:
        if self.progress.state is ScanState.PAUSED:
            self.progress.state = ScanState.RUNNING
            self._pause.set()

    @property
    def is_running(self) -> bool:
        return self.progress.state in (ScanState.RUNNING, ScanState.PAUSED, ScanState.PENDING)

    # ---------------------------------------------------------------- work
    def run(self) -> ScanProgress:
        self.progress.state = ScanState.RUNNING
        self.progress.started_at = time.time()
        self.db.upsert_scan(self.progress.to_dict())
        self.db.add_event(
            "info",
            "scan",
            f"{self.progress.scan_type.value.title()} scan started",
            {"scan_id": self.scan_id, "targets": self.progress.targets},
        )

        follow_symlinks = bool(self.config.get("scanning", "follow_symlinks", False))
        try:
            if self.progress.scan_type is not ScanType.FILE:
                self.progress.total_estimate = count_files(self.targets, follow_symlinks=follow_symlinks)
            else:
                self.progress.total_estimate = len(self.targets)
            self._emit_progress()

            workers = self._worker_count()
            files = iter_files(self.targets, follow_symlinks=follow_symlinks)
            if workers <= 1:
                for path in files:
                    if not self._step(path):
                        break
            else:
                self._run_parallel(files, workers)

            if self._cancel.is_set():
                self.progress.state = ScanState.CANCELLED
                self.progress.message = "Scan cancelled"
            else:
                self.progress.state = ScanState.COMPLETED
                self.progress.message = (
                    f"{self.progress.threats_found} threat(s) found"
                    if self.progress.threats_found
                    else "No threats found"
                )
        except Exception as exc:  # pragma: no cover - defensive
            self.progress.state = ScanState.FAILED
            self.progress.message = str(exc)
            self.db.add_event("error", "scan", f"Scan failed: {exc}", {"scan_id": self.scan_id})
        finally:
            self.progress.finished_at = time.time()
            self.progress.current_path = ""
            self.db.upsert_scan(self.progress.to_dict())
            self.db.add_event(
                "warning" if self.progress.threats_found else "info",
                "scan",
                f"{self.progress.scan_type.value.title()} scan {self.progress.state.value}: "
                f"{self.progress.files_scanned} files, {self.progress.threats_found} threat(s)",
                {
                    "scan_id": self.scan_id,
                    "threats": self.progress.threats_found,
                    "elapsed": round(self.progress.elapsed, 2),
                },
            )
            self._emit_progress()
        return self.progress

    def _run_parallel(self, files: Iterator[Path], workers: int) -> None:
        """Scan with a bounded pool.

        ``Executor.map`` would materialise a future per file up front, which
        on a full-disk scan means millions of pending objects.  Keeping only
        ``workers * 4`` in flight caps memory regardless of scan size.
        """
        in_flight: set = set()
        window = workers * 4
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="gav") as pool:
            for path in files:
                if self._cancel.is_set():
                    break
                in_flight.add(pool.submit(self._step, path))
                if len(in_flight) >= window:
                    done, in_flight = wait(in_flight, return_when=FIRST_COMPLETED)
                    for future in done:
                        future.result()
            for future in as_completed(in_flight):
                future.result()

    def _worker_count(self) -> int:
        configured = int(self.config.get("scanning", "worker_threads", 0))
        if configured > 0:
            return min(configured, 32)
        return max(2, min(8, (os.cpu_count() or 2)))

    def _step(self, path: Path) -> bool:
        """Scan one file. Returns ``False`` when the job should stop."""
        if self._cancel.is_set():
            return False
        self._pause.wait()
        if self._cancel.is_set():
            return False

        with self._lock:
            self.progress.current_path = str(path)

        result = self.scanner.scan_file(path)
        self._record(result)
        return not self._cancel.is_set()

    def _record(self, result: ScanResult) -> None:
        with self._lock:
            self.results.append(result)
            if result.verdict is Verdict.SKIPPED:
                self.progress.files_skipped += 1
            elif result.verdict is Verdict.ERROR:
                self.progress.errors += 1
            else:
                self.progress.files_scanned += 1
                self.progress.bytes_scanned += result.size

            if result.is_threat:
                self.progress.threats_found += 1
                self.threats.append(result)

        if result.is_threat:
            self._handle_threat(result)

        if self.on_result:
            try:
                self.on_result(result)
            except Exception:  # pragma: no cover - callback must not kill a scan
                pass

        total_seen = self.progress.files_scanned + self.progress.files_skipped
        if total_seen % 200 == 0:
            self.db.upsert_scan(self.progress.to_dict())
            self._emit_progress()

    def _handle_threat(self, result: ScanResult) -> None:
        handled = "reported"
        if self.auto_quarantine and self.config.get("quarantine", "enabled", True):
            try:
                entry = self.quarantine.quarantine_file(result)
                result.quarantined = True
                result.quarantine_id = entry.entry_id
                handled = "quarantined"
            except QuarantineError as exc:
                self.db.add_event(
                    "error",
                    "quarantine",
                    f"Could not quarantine {result.path}: {exc}",
                    {"path": result.path},
                )
        self.db.add_detection(self.scan_id, result.to_dict(), handled=handled)
        self.db.add_event(
            "warning",
            "detection",
            f"{result.primary_name or 'Threat'} detected in {Path(result.path).name}",
            {
                "path": result.path,
                "verdict": result.verdict.value,
                "severity": result.severity.value,
                "handled": handled,
            },
        )

    def _emit_progress(self) -> None:
        if self.on_progress:
            try:
                self.on_progress(self.progress)
            except Exception:  # pragma: no cover
                pass

    # -------------------------------------------------------------- summary
    def summary(self) -> Dict[str, Any]:
        return {
            **self.progress.to_dict(),
            "threats": [t.to_dict() for t in self.threats],
        }


class ScanManager:
    """Tracks the scans of the current process for the API and the CLI."""

    def __init__(self) -> None:
        self._jobs: Dict[str, ScanJob] = {}
        self._lock = threading.RLock()

    def start(
        self,
        scan_type: ScanType,
        targets: Optional[Sequence[Path]] = None,
        auto_quarantine: Optional[bool] = None,
        **kwargs: Any,
    ) -> ScanJob:
        config = get_config()
        if targets:
            resolved = [Path(t).expanduser() for t in targets]
        elif scan_type is ScanType.QUICK:
            resolved = quick_scan_targets()
        elif scan_type is ScanType.FULL:
            resolved = full_scan_targets()
        else:
            raise ValueError("custom and file scans require explicit targets")

        if auto_quarantine is None:
            auto_quarantine = bool(config.get("scanning", "auto_quarantine", True))

        job = ScanJob(
            targets=resolved,
            scan_type=scan_type,
            config=config,
            auto_quarantine=bool(auto_quarantine),
            **kwargs,
        )
        with self._lock:
            self._prune()
            self._jobs[job.scan_id] = job
        job.start()
        return job

    def get(self, scan_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._jobs.get(scan_id)

    def active(self) -> List[ScanJob]:
        with self._lock:
            return [job for job in self._jobs.values() if job.is_running]

    def all(self) -> List[ScanJob]:
        with self._lock:
            return list(self._jobs.values())

    def cancel(self, scan_id: str) -> bool:
        job = self.get(scan_id)
        if not job:
            return False
        job.cancel()
        return True

    def cancel_all(self) -> int:
        jobs = self.active()
        for job in jobs:
            job.cancel()
        return len(jobs)

    def _prune(self, keep: int = 20) -> None:
        finished = [job for job in self._jobs.values() if not job.is_running]
        if len(finished) <= keep:
            return
        for job in sorted(finished, key=lambda j: j.progress.started_at)[: len(finished) - keep]:
            self._jobs.pop(job.scan_id, None)


_MANAGER: Optional[ScanManager] = None
_MANAGER_LOCK = threading.Lock()


def get_scan_manager() -> ScanManager:
    global _MANAGER
    with _MANAGER_LOCK:
        if _MANAGER is None:
            _MANAGER = ScanManager()
        return _MANAGER


def scan_paths(targets: Sequence[Path], auto_quarantine: bool = False) -> ScanJob:
    """Convenience helper: run a blocking custom scan."""
    job = ScanJob(
        targets=targets,
        scan_type=ScanType.CUSTOM,
        auto_quarantine=auto_quarantine,
    )
    job.run()
    return job
