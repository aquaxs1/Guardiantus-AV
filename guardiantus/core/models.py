"""Value objects shared by the engine, the CLI and the HTTP API."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Verdict(str, Enum):
    """Outcome of inspecting a single file."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    SKIPPED = "skipped"
    ERROR = "error"

    @property
    def is_threat(self) -> bool:
        return self in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanType(str, Enum):
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"
    FILE = "file"
    REALTIME = "realtime"


class ScanState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class DetectionSource(str, Enum):
    SIGNATURE = "signature"
    HEURISTIC = "heuristic"
    YARA = "yara"
    ARCHIVE = "archive"


@dataclass
class Detection:
    """A single reason why a file is considered dangerous."""

    name: str
    source: DetectionSource
    severity: Severity
    description: str = ""
    score: int = 0
    #: ``"low"`` for rules that describe a plausible threat rather than
    #: identify one.  Some behaviour is simply indistinguishable from the
    #: outside -- a browser reading its own password store looks exactly like
    #: a stealer reading it -- so those rules report without the file being
    #: treated as confirmed malware and moved to the vault.
    confidence: str = "high"
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["source"] = self.source.value
        payload["severity"] = self.severity.value
        return payload


@dataclass
class ScanResult:
    """Result of inspecting one path."""

    path: str
    verdict: Verdict
    detections: List[Detection] = field(default_factory=list)
    sha256: str = ""
    size: int = 0
    duration_ms: float = 0.0
    error: str = ""
    quarantined: bool = False
    quarantine_id: Optional[str] = None
    scanned_at: float = field(default_factory=time.time)

    @property
    def is_threat(self) -> bool:
        return self.verdict.is_threat

    @property
    def severity(self) -> Severity:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        worst = Severity.INFO
        for det in self.detections:
            if order.index(det.severity) > order.index(worst):
                worst = det.severity
        return worst

    @property
    def primary_name(self) -> str:
        """Name shown to the user.

        Signature and YARA hits identify a concrete family, so they outrank a
        heuristic hit even when the heuristic scored higher.
        """
        if not self.detections:
            return ""
        priority = {
            DetectionSource.SIGNATURE: 3,
            DetectionSource.YARA: 2,
            DetectionSource.ARCHIVE: 1,
            DetectionSource.HEURISTIC: 0,
        }
        return max(self.detections, key=lambda d: (priority.get(d.source, 0), d.score)).name

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "verdict": self.verdict.value,
            "detections": [d.to_dict() for d in self.detections],
            "sha256": self.sha256,
            "size": self.size,
            "duration_ms": round(self.duration_ms, 3),
            "error": self.error,
            "quarantined": self.quarantined,
            "quarantine_id": self.quarantine_id,
            "scanned_at": self.scanned_at,
            "severity": self.severity.value,
            "name": self.primary_name,
        }


@dataclass
class ScanProgress:
    """Live progress snapshot of a running scan."""

    scan_id: str
    scan_type: ScanType
    state: ScanState = ScanState.PENDING
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    threats_found: int = 0
    errors: int = 0
    total_estimate: int = 0
    current_path: str = ""
    targets: List[str] = field(default_factory=list)
    message: str = ""

    @property
    def elapsed(self) -> float:
        end = self.finished_at if self.finished_at is not None else time.time()
        return max(0.0, end - self.started_at)

    @property
    def percent(self) -> float:
        if self.state is ScanState.COMPLETED:
            return 100.0
        if self.total_estimate <= 0:
            return 0.0
        done = self.files_scanned + self.files_skipped
        return min(99.9, round(done / self.total_estimate * 100, 1))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "scan_type": self.scan_type.value,
            "state": self.state.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "elapsed": round(self.elapsed, 2),
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "bytes_scanned": self.bytes_scanned,
            "threats_found": self.threats_found,
            "errors": self.errors,
            "total_estimate": self.total_estimate,
            "percent": self.percent,
            "current_path": self.current_path,
            "targets": list(self.targets),
            "message": self.message,
        }


@dataclass
class QuarantineEntry:
    """Metadata for a neutralised file kept in the vault."""

    entry_id: str
    original_path: str
    threat_name: str
    severity: Severity
    sha256: str
    size: int
    quarantined_at: float
    stored_name: str
    restored: bool = False
    deleted: bool = False
    detections: List[Dict[str, Any]] = field(default_factory=list)
    original_mode: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        return payload


@dataclass
class ProgramInfo:
    """An installed third-party program and its update status."""

    name: str
    current_version: str
    available_version: str = ""
    manager: str = ""
    package_id: str = ""
    publisher: str = ""

    @property
    def update_available(self) -> bool:
        return bool(self.available_version) and self.available_version != self.current_version

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["update_available"] = self.update_available
        return payload
