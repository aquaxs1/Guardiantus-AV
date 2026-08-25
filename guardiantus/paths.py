"""Filesystem locations used across the suite.

Everything Guardiantus writes lives under a single data directory so that a
full uninstall is a single ``rm -rf``.  The location follows platform
conventions and can be overridden with ``GUARDIANTUS_HOME`` (handy for tests
and for portable installs on a USB stick).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List


def _package_root() -> Path:
    """Where ``guardiantus``'s own files live.

    Under a normal install this is simply the directory containing this file.
    Under a PyInstaller build, the package is not present on disk as loose
    files at all -- modules are loaded from an embedded archive, so
    ``__file__`` resolves to a path that does not exist. Data files (the UI
    and the bundled signatures/rules) are instead unpacked next to the
    executable, so bundled resources must be found there.
    """
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", None)
        if base is None:
            base = Path(sys.executable).resolve().parent
        return Path(base) / "guardiantus"
    return Path(__file__).resolve().parent


PACKAGE_ROOT = _package_root()
PROJECT_ROOT = PACKAGE_ROOT.parent

#: Signature sets and YARA rules shipped with the application.
BUNDLED_SIGNATURES = PACKAGE_ROOT / "data" / "signatures"
BUNDLED_RULES = PACKAGE_ROOT / "data" / "rules"

UI_STATIC = PACKAGE_ROOT / "ui" / "static"
UI_TEMPLATES = PACKAGE_ROOT / "ui" / "templates"


def self_paths() -> List[Path]:
    """Directories that belong to Guardiantus itself.

    Scanning our own files is worse than pointless: the signature database
    contains malware strings and the YARA rules contain the very patterns they
    look for, so a scan of the install directory reliably "detects" the
    scanner.  Under a frozen build those files live in a throwaway
    ``_MEIxxxxxx`` directory next to the unpacked runtime DLLs, which is inside
    the user's temp folder -- squarely in the path of a quick scan.
    """
    candidates = [PACKAGE_ROOT, _default_home()]
    if getattr(sys, "frozen", False):
        unpacked = getattr(sys, "_MEIPASS", None)
        if unpacked:
            candidates.append(Path(unpacked))
        try:
            candidates.append(Path(sys.executable).parent)
        except (OSError, ValueError):
            pass

    resolved: List[Path] = []
    for candidate in candidates:
        try:
            path = Path(candidate).resolve()
        except OSError:
            continue
        if path not in resolved:
            resolved.append(path)
    return resolved


def _default_home() -> Path:
    override = os.environ.get("GUARDIANTUS_HOME")
    if override:
        return Path(override).expanduser()

    if sys.platform == "win32":
        base = os.environ.get("PROGRAMDATA") or os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "Guardiantus"
        return Path.home() / "Guardiantus"

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Guardiantus"

    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "guardiantus"
    return Path.home() / ".local" / "share" / "guardiantus"


def home() -> Path:
    """Root data directory, created on demand."""
    path = _default_home()
    path.mkdir(parents=True, exist_ok=True)
    return path


def config_file() -> Path:
    return home() / "config.json"


def database_file() -> Path:
    return home() / "guardiantus.db"


def quarantine_dir() -> Path:
    path = home() / "quarantine"
    path.mkdir(parents=True, exist_ok=True)
    return path


def signatures_dir() -> Path:
    """Where downloaded/merged signature sets are cached."""
    path = home() / "signatures"
    path.mkdir(parents=True, exist_ok=True)
    return path


def rules_dir() -> Path:
    """Where user supplied YARA rules are stored."""
    path = home() / "rules"
    path.mkdir(parents=True, exist_ok=True)
    return path


def log_file() -> Path:
    path = home() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path / "guardiantus.log"


def runtime_file(name: str) -> Path:
    path = home() / "run"
    path.mkdir(parents=True, exist_ok=True)
    return path / name
