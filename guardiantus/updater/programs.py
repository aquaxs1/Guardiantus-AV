"""Third-party program inventory and updates.

Out-of-date software is the most common way a machine gets compromised, so
Guardiantus treats "are your programs patched?" as a first-class security
check alongside malware scanning.

Each supported package manager is wrapped in a :class:`PackageManager`
implementation that knows three things: whether it is present, how to list
outdated packages, and how to upgrade one.  Managers that are not installed
simply report ``available == False`` and are skipped.

Upgrades are never run implicitly: :meth:`ProgramUpdater.upgrade` has to be
called explicitly, and the ``programs_auto_install`` setting defaults to off.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

from ..config import Config, get_config
from ..core.db import Database, get_db
from ..core.models import ProgramInfo

LIST_TIMEOUT = 120
UPGRADE_TIMEOUT = 1800


def _run(command: List[str], timeout: int = LIST_TIMEOUT) -> subprocess.CompletedProcess:
    """Run a command without a shell, capturing output."""
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


class PackageManager:
    """Base class for a package-manager integration."""

    name = "base"
    #: Human readable description shown in the UI.
    label = "Package manager"
    #: Command whose presence on PATH indicates the manager is usable.
    binary = ""
    #: True when upgrading needs administrative rights.
    needs_privileges = False

    @property
    def available(self) -> bool:
        return bool(self.binary) and shutil.which(self.binary) is not None

    def outdated(self) -> List[ProgramInfo]:  # pragma: no cover - overridden
        raise NotImplementedError

    def upgrade(self, package_id: str) -> subprocess.CompletedProcess:  # pragma: no cover - overridden
        raise NotImplementedError

    def upgrade_all(self) -> subprocess.CompletedProcess:  # pragma: no cover - overridden
        raise NotImplementedError


class AptManager(PackageManager):
    name = "apt"
    label = "APT (Debian/Ubuntu)"
    binary = "apt"
    needs_privileges = True

    _LINE = re.compile(
        r"^(?P<name>[^/]+)/\S+\s+(?P<available>\S+)\s+\S+\s+\[upgradable from:\s*(?P<current>[^\]]+)\]"
    )

    def outdated(self) -> List[ProgramInfo]:
        result = _run(["apt", "list", "--upgradable"])
        programs: List[ProgramInfo] = []
        for line in result.stdout.splitlines():
            match = self._LINE.match(line.strip())
            if not match:
                continue
            programs.append(
                ProgramInfo(
                    name=match.group("name"),
                    current_version=match.group("current").strip(),
                    available_version=match.group("available"),
                    manager=self.name,
                    package_id=match.group("name"),
                )
            )
        return programs

    def upgrade(self, package_id: str) -> subprocess.CompletedProcess:
        return _run(
            ["apt-get", "install", "--only-upgrade", "-y", package_id],
            timeout=UPGRADE_TIMEOUT,
        )

    def upgrade_all(self) -> subprocess.CompletedProcess:
        return _run(["apt-get", "upgrade", "-y"], timeout=UPGRADE_TIMEOUT)


class DnfManager(PackageManager):
    name = "dnf"
    label = "DNF (Fedora/RHEL)"
    binary = "dnf"
    needs_privileges = True

    def outdated(self) -> List[ProgramInfo]:
        result = _run(["dnf", "--quiet", "check-update"])
        programs: List[ProgramInfo] = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) != 3 or line.startswith(("Last metadata", "Obsoleting")):
                continue
            name, version, _repo = parts
            programs.append(
                ProgramInfo(
                    name=name.split(".")[0],
                    current_version="",
                    available_version=version,
                    manager=self.name,
                    package_id=name,
                )
            )
        return programs

    def upgrade(self, package_id: str) -> subprocess.CompletedProcess:
        return _run(["dnf", "upgrade", "-y", package_id], timeout=UPGRADE_TIMEOUT)

    def upgrade_all(self) -> subprocess.CompletedProcess:
        return _run(["dnf", "upgrade", "-y"], timeout=UPGRADE_TIMEOUT)


class PacmanManager(PackageManager):
    name = "pacman"
    label = "Pacman (Arch)"
    binary = "pacman"
    needs_privileges = True

    def outdated(self) -> List[ProgramInfo]:
        result = _run(["pacman", "-Qu"])
        programs: List[ProgramInfo] = []
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[2] != "->":
                continue
            programs.append(
                ProgramInfo(
                    name=parts[0],
                    current_version=parts[1],
                    available_version=parts[3],
                    manager=self.name,
                    package_id=parts[0],
                )
            )
        return programs

    def upgrade(self, package_id: str) -> subprocess.CompletedProcess:
        return _run(["pacman", "-S", "--noconfirm", package_id], timeout=UPGRADE_TIMEOUT)

    def upgrade_all(self) -> subprocess.CompletedProcess:
        return _run(["pacman", "-Syu", "--noconfirm"], timeout=UPGRADE_TIMEOUT)


class FlatpakManager(PackageManager):
    name = "flatpak"
    label = "Flatpak"
    binary = "flatpak"

    def outdated(self) -> List[ProgramInfo]:
        result = _run(["flatpak", "remote-ls", "--updates", "--columns=application,version"])
        programs: List[ProgramInfo] = []
        for line in result.stdout.splitlines():
            parts = line.split("\t") if "\t" in line else line.split()
            if not parts or parts[0].lower() in ("application", "application id"):
                continue
            programs.append(
                ProgramInfo(
                    name=parts[0],
                    current_version="",
                    available_version=parts[1] if len(parts) > 1 else "newer",
                    manager=self.name,
                    package_id=parts[0],
                )
            )
        return programs

    def upgrade(self, package_id: str) -> subprocess.CompletedProcess:
        return _run(["flatpak", "update", "-y", package_id], timeout=UPGRADE_TIMEOUT)

    def upgrade_all(self) -> subprocess.CompletedProcess:
        return _run(["flatpak", "update", "-y"], timeout=UPGRADE_TIMEOUT)


class SnapManager(PackageManager):
    name = "snap"
    label = "Snap"
    binary = "snap"
    needs_privileges = True

    def outdated(self) -> List[ProgramInfo]:
        result = _run(["snap", "refresh", "--list"])
        programs: List[ProgramInfo] = []
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 2:
                continue
            programs.append(
                ProgramInfo(
                    name=parts[0],
                    current_version="",
                    available_version=parts[1],
                    manager=self.name,
                    package_id=parts[0],
                    publisher=parts[2] if len(parts) > 2 else "",
                )
            )
        return programs

    def upgrade(self, package_id: str) -> subprocess.CompletedProcess:
        return _run(["snap", "refresh", package_id], timeout=UPGRADE_TIMEOUT)

    def upgrade_all(self) -> subprocess.CompletedProcess:
        return _run(["snap", "refresh"], timeout=UPGRADE_TIMEOUT)


class BrewManager(PackageManager):
    name = "brew"
    label = "Homebrew"
    binary = "brew"

    def outdated(self) -> List[ProgramInfo]:
        result = _run(["brew", "outdated", "--json=v2"])
        programs: List[ProgramInfo] = []
        try:
            document = json.loads(result.stdout or "{}")
        except json.JSONDecodeError:
            return programs
        for formula in document.get("formulae", []) or []:
            versions = formula.get("installed_versions") or [""]
            programs.append(
                ProgramInfo(
                    name=formula.get("name", ""),
                    current_version=versions[-1],
                    available_version=formula.get("current_version", ""),
                    manager=self.name,
                    package_id=formula.get("name", ""),
                )
            )
        for cask in document.get("casks", []) or []:
            programs.append(
                ProgramInfo(
                    name=cask.get("name", ""),
                    current_version=(cask.get("installed_versions") or [""])[-1]
                    if isinstance(cask.get("installed_versions"), list)
                    else str(cask.get("installed_versions", "")),
                    available_version=cask.get("current_version", ""),
                    manager=self.name,
                    package_id=cask.get("name", ""),
                )
            )
        return programs

    def upgrade(self, package_id: str) -> subprocess.CompletedProcess:
        return _run(["brew", "upgrade", package_id], timeout=UPGRADE_TIMEOUT)

    def upgrade_all(self) -> subprocess.CompletedProcess:
        return _run(["brew", "upgrade"], timeout=UPGRADE_TIMEOUT)


class WingetManager(PackageManager):
    name = "winget"
    label = "Windows Package Manager"
    binary = "winget"

    def outdated(self) -> List[ProgramInfo]:
        result = _run(
            ["winget", "upgrade", "--include-unknown", "--accept-source-agreements"]
        )
        return _parse_winget_table(result.stdout, self.name)

    def upgrade(self, package_id: str) -> subprocess.CompletedProcess:
        return _run(
            [
                "winget", "upgrade", "--id", package_id, "--silent",
                "--accept-package-agreements", "--accept-source-agreements",
            ],
            timeout=UPGRADE_TIMEOUT,
        )

    def upgrade_all(self) -> subprocess.CompletedProcess:
        return _run(
            [
                "winget", "upgrade", "--all", "--silent",
                "--accept-package-agreements", "--accept-source-agreements",
            ],
            timeout=UPGRADE_TIMEOUT,
        )


class ChocolateyManager(PackageManager):
    name = "choco"
    label = "Chocolatey"
    binary = "choco"
    needs_privileges = True

    def outdated(self) -> List[ProgramInfo]:
        result = _run(["choco", "outdated", "--limit-output"])
        programs: List[ProgramInfo] = []
        for line in result.stdout.splitlines():
            parts = line.split("|")
            if len(parts) < 3:
                continue
            programs.append(
                ProgramInfo(
                    name=parts[0],
                    current_version=parts[1],
                    available_version=parts[2],
                    manager=self.name,
                    package_id=parts[0],
                )
            )
        return programs

    def upgrade(self, package_id: str) -> subprocess.CompletedProcess:
        return _run(["choco", "upgrade", package_id, "-y"], timeout=UPGRADE_TIMEOUT)

    def upgrade_all(self) -> subprocess.CompletedProcess:
        return _run(["choco", "upgrade", "all", "-y"], timeout=UPGRADE_TIMEOUT)


class PipManager(PackageManager):
    name = "pip"
    label = "Python packages (pip)"
    binary = sys.executable or "python3"

    @property
    def available(self) -> bool:
        return bool(sys.executable)

    def outdated(self) -> List[ProgramInfo]:
        result = _run([sys.executable, "-m", "pip", "list", "--outdated", "--format=json"])
        programs: List[ProgramInfo] = []
        try:
            document = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            return programs
        for package in document:
            programs.append(
                ProgramInfo(
                    name=package.get("name", ""),
                    current_version=package.get("version", ""),
                    available_version=package.get("latest_version", ""),
                    manager=self.name,
                    package_id=package.get("name", ""),
                )
            )
        return programs

    def upgrade(self, package_id: str) -> subprocess.CompletedProcess:
        return _run(
            [sys.executable, "-m", "pip", "install", "--upgrade", package_id],
            timeout=UPGRADE_TIMEOUT,
        )

    def upgrade_all(self) -> subprocess.CompletedProcess:
        # Deliberately unsupported: mass-upgrading pip packages routinely
        # breaks environments. Upgrade individual packages instead.
        raise NotImplementedError("pip does not support a safe bulk upgrade")


_WINGET_HEADER = re.compile(r"^Name\s+Id\s+Version\s+Available", re.I)


def _parse_winget_table(output: str, manager: str) -> List[ProgramInfo]:
    """winget prints a fixed-width table; derive the columns from the header."""
    lines = output.splitlines()
    header_index = next((i for i, line in enumerate(lines) if _WINGET_HEADER.match(line.strip())), -1)
    if header_index < 0:
        return []
    header = lines[header_index]
    columns = []
    for label in ("Name", "Id", "Version", "Available", "Source"):
        index = header.find(label)
        if index >= 0:
            columns.append((label, index))
    columns.sort(key=lambda c: c[1])

    programs: List[ProgramInfo] = []
    for line in lines[header_index + 1:]:
        if not line.strip() or set(line.strip()) <= {"-"}:
            continue
        fields: Dict[str, str] = {}
        for position, (label, start) in enumerate(columns):
            end = columns[position + 1][1] if position + 1 < len(columns) else len(line)
            fields[label] = line[start:end].strip()
        if not fields.get("Id") or not fields.get("Available"):
            continue
        programs.append(
            ProgramInfo(
                name=fields.get("Name", fields["Id"]),
                current_version=fields.get("Version", ""),
                available_version=fields.get("Available", ""),
                manager=manager,
                package_id=fields["Id"],
                publisher=fields.get("Source", ""),
            )
        )
    return programs


def platform_managers() -> List[PackageManager]:
    """Managers worth probing on the current platform."""
    if sys.platform == "win32":
        candidates: List[PackageManager] = [WingetManager(), ChocolateyManager()]
    elif sys.platform == "darwin":
        candidates = [BrewManager()]
    else:
        candidates = [AptManager(), DnfManager(), PacmanManager(), FlatpakManager(), SnapManager()]
    candidates.append(PipManager())
    return candidates


class ProgramUpdater:
    """Aggregates every available package manager into one view."""

    def __init__(self, config: Optional[Config] = None, db: Optional[Database] = None) -> None:
        self._config = config
        self._db = db
        self._managers = {m.name: m for m in platform_managers()}
        self._cache: Optional[Dict[str, Any]] = None

    # This object outlives individual database handles (it is a singleton, and
    # the handle is recycled between test runs and on reconfiguration), so both
    # dependencies are resolved on each use rather than captured once.
    @property
    def config(self) -> Config:
        return self._config or get_config()

    @property
    def db(self) -> Database:
        return self._db if self._db is not None and not self._db.closed else get_db()

    # ------------------------------------------------------------ inventory
    def managers(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": manager.name,
                "label": manager.label,
                "available": manager.available,
                "needs_privileges": manager.needs_privileges,
            }
            for manager in self._managers.values()
        ]

    def check(self, use_cache: bool = False, max_age: float = 900.0) -> Dict[str, Any]:
        """Ask every available manager which of its packages are outdated."""
        if use_cache and self._cache and (time.time() - self._cache["checked_at"]) < max_age:
            return self._cache

        programs: List[Dict[str, Any]] = []
        errors: List[Dict[str, str]] = []
        probed: List[str] = []

        for manager in self._managers.values():
            if not manager.available:
                continue
            probed.append(manager.name)
            try:
                for program in manager.outdated():
                    if program.name:
                        programs.append(program.to_dict())
            except subprocess.TimeoutExpired:
                errors.append({"manager": manager.name, "error": "timed out"})
            except (OSError, subprocess.SubprocessError) as exc:
                errors.append({"manager": manager.name, "error": str(exc)})

        programs.sort(key=lambda p: (p.get("manager", ""), p.get("name", "").lower()))
        payload = {
            "checked_at": time.time(),
            "managers_probed": probed,
            "updates_available": len(programs),
            "programs": programs,
            "errors": errors,
        }
        self._cache = payload
        self.db.set_meta("programs_last_check", str(payload["checked_at"]))
        self.db.add_event(
            "warning" if programs else "info",
            "update",
            f"{len(programs)} program update(s) available"
            if programs
            else "All programs are up to date",
            {"managers": probed, "count": len(programs)},
        )
        return payload

    # -------------------------------------------------------------- actions
    def upgrade(self, manager_name: str, package_id: str) -> Dict[str, Any]:
        """Upgrade a single package. Requires an explicit call -- never implicit."""
        manager = self._managers.get(manager_name)
        if manager is None:
            return {"ok": False, "error": f"unknown package manager: {manager_name}"}
        if not manager.available:
            return {"ok": False, "error": f"{manager.label} is not installed"}
        if not package_id or not _safe_package_id(package_id):
            return {"ok": False, "error": f"invalid package id: {package_id!r}"}

        try:
            completed = manager.upgrade(package_id)
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "upgrade timed out"}
        except (OSError, subprocess.SubprocessError, NotImplementedError) as exc:
            return {"ok": False, "error": str(exc)}

        ok = completed.returncode == 0
        self._cache = None
        self.db.add_event(
            "info" if ok else "error",
            "update",
            f"{'Upgraded' if ok else 'Failed to upgrade'} {package_id} via {manager.label}",
            {"manager": manager_name, "package": package_id, "returncode": completed.returncode},
        )
        return {
            "ok": ok,
            "manager": manager_name,
            "package": package_id,
            "returncode": completed.returncode,
            "stdout": (completed.stdout or "")[-4000:],
            "stderr": (completed.stderr or "")[-4000:],
            "hint": "Administrative rights may be required"
            if not ok and manager.needs_privileges
            else "",
        }

    def upgrade_all(self, manager_name: str) -> Dict[str, Any]:
        manager = self._managers.get(manager_name)
        if manager is None:
            return {"ok": False, "error": f"unknown package manager: {manager_name}"}
        if not manager.available:
            return {"ok": False, "error": f"{manager.label} is not installed"}
        try:
            completed = manager.upgrade_all()
        except NotImplementedError as exc:
            return {"ok": False, "error": str(exc)}
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "upgrade timed out"}
        except (OSError, subprocess.SubprocessError) as exc:
            return {"ok": False, "error": str(exc)}

        ok = completed.returncode == 0
        self._cache = None
        self.db.add_event(
            "info" if ok else "error",
            "update",
            f"Bulk upgrade via {manager.label} {'succeeded' if ok else 'failed'}",
            {"manager": manager_name, "returncode": completed.returncode},
        )
        return {
            "ok": ok,
            "manager": manager_name,
            "returncode": completed.returncode,
            "stdout": (completed.stdout or "")[-8000:],
            "stderr": (completed.stderr or "")[-8000:],
        }

    def status(self) -> Dict[str, Any]:
        last = float(self.db.get_meta("programs_last_check", "0") or 0)
        cached = self._cache or {}
        return {
            "last_check": last or None,
            "updates_available": cached.get("updates_available", 0),
            "managers": self.managers(),
            "auto_check": self.config.get("updates", "programs_auto_check", True),
            "auto_install": self.config.get("updates", "programs_auto_install", False),
        }


def _safe_package_id(package_id: str) -> bool:
    """Reject anything that is not a plausible package identifier."""
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+:@/-]{0,127}", package_id))


_INSTANCE: Optional[ProgramUpdater] = None


def get_program_updater() -> ProgramUpdater:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = ProgramUpdater()
    return _INSTANCE
