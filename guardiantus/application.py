"""The application facade.

One object that owns every subsystem, so the CLI and the HTTP API share
exactly the same behaviour and there is a single place where protection
status is computed.
"""

from __future__ import annotations

import platform
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import __version__, paths
from .config import Config, get_config
from .core.db import Database, get_db
from .core.models import ScanType
from .core.quarantine import Quarantine, get_quarantine
from .core.realtime import RealtimeProtection, get_realtime
from .core.scanner import FileScanner, ScanJob, ScanManager, get_scan_manager
from .core.scheduler import CronError, Scheduler, get_scheduler
from .core.signatures import SignatureDatabase, get_signatures
from .core.yara_engine import YaraEngine, get_yara
from .updater.programs import ProgramUpdater, get_program_updater
from .updater.signatures_update import SignatureUpdater, UpdateError


class Application:
    """Owns configuration, engine, protection state and scheduled work."""

    def __init__(self) -> None:
        self.config: Config = get_config()
        self.db: Database = get_db()
        self.signatures: SignatureDatabase = get_signatures()
        self.yara: YaraEngine = get_yara()
        self.scanner: FileScanner = FileScanner(
            config=self.config, signatures=self.signatures, yara=self.yara
        )
        self.quarantine: Quarantine = get_quarantine()
        self.realtime: RealtimeProtection = get_realtime()
        self.scans: ScanManager = get_scan_manager()
        self.scheduler: Scheduler = get_scheduler()
        self.signature_updater = SignatureUpdater(config=self.config, db=self.db)
        self.programs: ProgramUpdater = get_program_updater()
        self.started_at = time.time()
        self._lock = threading.RLock()

    # ------------------------------------------------------------- start-up
    def start_background_services(self) -> Dict[str, Any]:
        """Bring up real-time protection and the scheduler per configuration."""
        started: Dict[str, Any] = {"realtime": False, "scheduler": False}

        if self.config.get("realtime", "enabled", False):
            try:
                self.realtime.start()
                started["realtime"] = True
            except RuntimeError as exc:
                self.db.add_event("error", "realtime", f"Could not start protection: {exc}", {})

        self._register_tasks()
        self.scheduler.start()
        started["scheduler"] = True
        return started

    def shutdown(self) -> None:
        if self.realtime.running:
            self.realtime.stop()
        if self.scheduler.running:
            self.scheduler.stop()
        self.scans.cancel_all()

    def _register_tasks(self) -> None:
        schedule = self.config.data.get("schedule", {})
        updates = self.config.data.get("updates", {})

        registrations = [
            (
                "quick-scan",
                schedule.get("quick_scan_cron", "0 12 * * *"),
                lambda: self.start_scan("quick").scan_id,
                bool(schedule.get("quick_scan_enabled", False)),
                "Scheduled quick scan of high-risk locations",
            ),
            (
                "full-scan",
                schedule.get("full_scan_cron", "0 3 * * 0"),
                lambda: self.start_scan("full").scan_id,
                bool(schedule.get("full_scan_enabled", False)),
                "Scheduled full system scan",
            ),
            (
                "signature-update",
                f"0 */{max(1, int(updates.get('check_interval_hours', 6)))} * * *",
                lambda: self.update_signatures().get("message", ""),
                bool(updates.get("auto_update_signatures", True)),
                "Signature database refresh",
            ),
            (
                "program-update-check",
                "30 9 * * *",
                lambda: f"{self.check_programs()['updates_available']} update(s) available",
                bool(updates.get("programs_auto_check", True)),
                "Third-party program update check",
            ),
        ]

        for name, cron, action, enabled, description in registrations:
            try:
                self.scheduler.register(name, cron, action, enabled=enabled, description=description)
            except CronError as exc:
                self.db.add_event("error", "scheduler", f"Bad cron for '{name}': {exc}", {"cron": cron})

    # --------------------------------------------------------------- status
    def protection_status(self) -> Dict[str, Any]:
        """Aggregate health used by the dashboard's status card."""
        issues: List[Dict[str, str]] = []

        if not self.realtime.running:
            issues.append(
                {
                    "id": "realtime-off",
                    "severity": "high",
                    "title": "Real-time protection is off",
                    "action": "enable_realtime",
                }
            )

        signature_status = self.signature_updater.status()
        if signature_status.get("stale"):
            issues.append(
                {
                    "id": "signatures-stale",
                    "severity": "medium",
                    "title": "Signature database is more than 7 days old",
                    "action": "update_signatures",
                }
            )
        if self.signatures.count == 0:
            issues.append(
                {
                    "id": "signatures-empty",
                    "severity": "high",
                    "title": "No signatures loaded",
                    "action": "update_signatures",
                }
            )

        last_scan = self.db.last_completed_scan()
        if not last_scan:
            issues.append(
                {
                    "id": "never-scanned",
                    "severity": "medium",
                    "title": "This device has never been scanned",
                    "action": "quick_scan",
                }
            )
        elif last_scan.get("finished_at") and time.time() - float(last_scan["finished_at"]) > 7 * 86400:
            issues.append(
                {
                    "id": "scan-stale",
                    "severity": "low",
                    "title": "Last scan was more than a week ago",
                    "action": "quick_scan",
                }
            )

        active_quarantine = len(self.quarantine.list_entries())
        if active_quarantine:
            issues.append(
                {
                    "id": "quarantine-pending",
                    "severity": "low",
                    "title": f"{active_quarantine} item(s) waiting in quarantine",
                    "action": "review_quarantine",
                }
            )

        severity_rank = {"high": 3, "medium": 2, "low": 1}
        worst = max((severity_rank.get(i["severity"], 0) for i in issues), default=0)
        state = {3: "at_risk", 2: "attention", 1: "attention", 0: "protected"}[worst]

        return {
            "state": state,
            "headline": {
                "protected": "You are protected",
                "attention": "Attention needed",
                "at_risk": "Your device is at risk",
            }[state],
            "issues": issues,
            "realtime": self.realtime.status(),
            "signatures": signature_status,
            "scans_active": len(self.scans.active()),
            "quarantine": self.quarantine.stats(),
            "last_scan": last_scan,
        }

    def system_info(self) -> Dict[str, Any]:
        return {
            "app": "Guardiantus AV",
            "version": __version__,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "hostname": platform.node(),
            "machine": platform.machine(),
            "data_dir": str(paths.home()),
            "uptime": round(time.time() - self.started_at, 1),
            "engine": {
                "signatures": self.signatures.info(),
                "yara": self.yara.info(),
            },
        }

    # ---------------------------------------------------------------- scans
    def start_scan(
        self,
        scan_type: str,
        targets: Optional[Sequence[str]] = None,
        auto_quarantine: Optional[bool] = None,
    ) -> ScanJob:
        try:
            kind = ScanType(scan_type)
        except ValueError as exc:
            raise ValueError(f"unknown scan type: {scan_type}") from exc

        resolved: Optional[List[Path]] = None
        if targets:
            resolved = []
            for raw in targets:
                candidate = Path(raw).expanduser()
                if not candidate.exists():
                    raise FileNotFoundError(f"no such path: {raw}")
                resolved.append(candidate)
        elif kind in (ScanType.CUSTOM, ScanType.FILE):
            raise ValueError(f"{kind.value} scans require at least one target")

        return self.scans.start(kind, targets=resolved, auto_quarantine=auto_quarantine)

    def scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        job = self.scans.get(scan_id)
        if job:
            return job.summary()
        record = self.db.get_scan(scan_id)
        if not record:
            return None
        record["threats"] = [d["payload"] for d in self.db.recent_detections(500, scan_id=scan_id)]
        return record

    def cancel_scan(self, scan_id: str) -> bool:
        return self.scans.cancel(scan_id)

    def scan_history(self, limit: int = 25) -> List[Dict[str, Any]]:
        return self.db.recent_scans(limit)

    # ----------------------------------------------------------- protection
    def enable_realtime(self) -> Dict[str, Any]:
        status = self.realtime.start()
        self.config.set("realtime", "enabled", True)
        return status

    def disable_realtime(self) -> Dict[str, Any]:
        status = self.realtime.stop()
        self.config.set("realtime", "enabled", False)
        return status

    def toggle_realtime(self, enabled: bool) -> Dict[str, Any]:
        return self.enable_realtime() if enabled else self.disable_realtime()

    # --------------------------------------------------------------- update
    def update_signatures(self, force: bool = False) -> Dict[str, Any]:
        try:
            return self.signature_updater.update(force=force)
        except UpdateError as exc:
            self.db.add_event("error", "update", f"Signature update failed: {exc}", {})
            return {"ok": False, "installed": 0, "message": str(exc)}

    def check_signature_updates(self) -> Dict[str, Any]:
        try:
            return self.signature_updater.check()
        except UpdateError as exc:
            return {"configured": True, "updates_available": 0, "sets": [], "message": str(exc)}

    def check_programs(self, use_cache: bool = False) -> Dict[str, Any]:
        return self.programs.check(use_cache=use_cache)

    def upgrade_program(self, manager: str, package_id: str) -> Dict[str, Any]:
        return self.programs.upgrade(manager, package_id)

    def upgrade_all_programs(self, manager: str) -> Dict[str, Any]:
        return self.programs.upgrade_all(manager)

    # --------------------------------------------------------------- events
    def events(self, limit: int = 100, category: str = "") -> List[Dict[str, Any]]:
        return self.db.recent_events(limit=limit, category=category)

    def detections(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self.db.recent_detections(limit=limit)

    def stats(self) -> Dict[str, Any]:
        return self.db.stats()

    # -------------------------------------------------------------- config
    def update_config(self, patch: Dict[str, Any]) -> Dict[str, Any]:
        """Apply a configuration patch and re-sync anything it affects."""
        data = self.config.update(patch)

        if "scanning" in patch:
            self.signatures.load()
        if "realtime" in patch and self.realtime.running:
            # Restart so new watch paths take effect immediately.
            self.realtime.stop()
            try:
                self.realtime.start()
            except RuntimeError as exc:
                self.db.add_event("error", "realtime", f"Restart failed: {exc}", {})
        if "schedule" in patch or "updates" in patch:
            for name in ("quick-scan", "full-scan", "signature-update", "program-update-check"):
                self.scheduler.unregister(name)
            self._register_tasks()
        return data


_INSTANCE: Optional[Application] = None
_INSTANCE_LOCK = threading.Lock()


def get_app() -> Application:
    """Process-wide application singleton."""
    global _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is None:
            _INSTANCE = Application()
        return _INSTANCE


def reset_app_cache() -> None:
    global _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is not None:
            _INSTANCE.shutdown()
        _INSTANCE = None
