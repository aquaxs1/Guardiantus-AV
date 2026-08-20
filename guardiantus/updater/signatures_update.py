"""Signature database updates.

A feed is a JSON manifest listing the signature sets it offers::

    {
      "version": "2026.08.20",
      "sets": [
        {"name": "base", "url": "https://.../base.json", "sha256": "..."}
      ]
    }

Sets are downloaded to a temporary file, verified against the manifest digest
when one is given, validated as parseable signature sets, and only then moved
into place.  A failed download therefore never corrupts a working install.
"""

from __future__ import annotations

import json
import ssl
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from .. import __version__, paths
from ..config import Config, get_config
from ..core.db import Database, get_db
from ..core.hashing import sha256_file
from ..core.signatures import get_signatures

USER_AGENT = f"GuardiantusAV/{__version__}"
DOWNLOAD_TIMEOUT = 30
MAX_SET_BYTES = 64 * 1024 * 1024


class UpdateError(RuntimeError):
    """Raised when a signature update cannot be completed."""


def _open(url: str, timeout: int = DOWNLOAD_TIMEOUT):
    scheme = urlparse(url).scheme
    if scheme not in ("https", "http", "file"):
        raise UpdateError(f"unsupported URL scheme: {scheme!r}")
    if scheme == "http":
        # Allowed for self-hosted mirrors on a trusted LAN, but flagged.
        pass
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    context = ssl.create_default_context() if scheme == "https" else None
    try:
        return urllib.request.urlopen(request, timeout=timeout, context=context)
    except urllib.error.URLError as exc:
        raise UpdateError(f"cannot reach {url}: {exc.reason}") from exc
    except OSError as exc:
        raise UpdateError(f"cannot reach {url}: {exc}") from exc


class SignatureUpdater:
    def __init__(self, config: Optional[Config] = None, db: Optional[Database] = None) -> None:
        self.config = config or get_config()
        self.db = db or get_db()

    # ------------------------------------------------------------- metadata
    def status(self) -> Dict[str, Any]:
        signatures = get_signatures()
        last_check = float(self.db.get_meta("signatures_last_check", "0") or 0)
        last_update = float(self.db.get_meta("signatures_last_update", "0") or 0)
        info = signatures.info()
        return {
            **info,
            "feed_url": self.config.get("updates", "signature_url", ""),
            "auto_update": self.config.get("updates", "auto_update_signatures", True),
            "last_check": last_check or None,
            "last_update": last_update or None,
            "stale": bool(last_update) and (time.time() - last_update) > 7 * 86400,
        }

    # -------------------------------------------------------------- updates
    def check(self) -> Dict[str, Any]:
        """Fetch the manifest and report which sets differ from local copies."""
        feed = str(self.config.get("updates", "signature_url", "") or "").strip()
        self.db.set_meta("signatures_last_check", str(time.time()))
        if not feed:
            return {"configured": False, "updates_available": 0, "sets": [], "message": "No feed configured"}

        manifest = self._fetch_manifest(feed)
        pending: List[Dict[str, Any]] = []
        for entry in manifest.get("sets", []) or []:
            name = entry.get("name")
            url = entry.get("url")
            if not name or not url:
                continue
            local = paths.signatures_dir() / f"{name}.json"
            local_digest = sha256_file(local) if local.is_file() else ""
            remote_digest = str(entry.get("sha256", "")).lower()
            if not remote_digest or local_digest != remote_digest:
                pending.append(
                    {
                        "name": name,
                        "url": urljoin(feed, url),
                        "sha256": remote_digest,
                        "local_sha256": local_digest,
                        "installed": bool(local_digest),
                    }
                )
        return {
            "configured": True,
            "feed_version": manifest.get("version", ""),
            "updates_available": len(pending),
            "sets": pending,
            "message": f"{len(pending)} set(s) to update" if pending else "Signatures are up to date",
        }

    def update(self, force: bool = False) -> Dict[str, Any]:
        """Download and install every pending signature set."""
        check = self.check()
        if not check.get("configured"):
            return {**check, "installed": 0}

        targets = check["sets"]
        if force:
            feed = str(self.config.get("updates", "signature_url", ""))
            manifest = self._fetch_manifest(feed)
            targets = [
                {
                    "name": e["name"],
                    "url": urljoin(feed, e["url"]),
                    "sha256": str(e.get("sha256", "")).lower(),
                }
                for e in manifest.get("sets", [])
                if e.get("name") and e.get("url")
            ]

        installed: List[str] = []
        failures: List[Dict[str, str]] = []
        for entry in targets:
            try:
                self._install_set(entry["name"], entry["url"], entry.get("sha256", ""))
                installed.append(entry["name"])
            except UpdateError as exc:
                failures.append({"name": entry["name"], "error": str(exc)})

        if installed:
            count = get_signatures().load()
            self.db.set_meta("signatures_last_update", str(time.time()))
            self.db.add_event(
                "info",
                "update",
                f"Installed {len(installed)} signature set(s); {count} signatures active",
                {"sets": installed},
            )
        for failure in failures:
            self.db.add_event(
                "error", "update", f"Signature set '{failure['name']}' failed: {failure['error']}", failure
            )

        return {
            "configured": True,
            "installed": len(installed),
            "sets": installed,
            "failures": failures,
            "signature_count": get_signatures().count,
            "message": f"Installed {len(installed)} set(s)" if installed else "Nothing to install",
        }

    # ------------------------------------------------------------ internals
    def _fetch_manifest(self, feed: str) -> Dict[str, Any]:
        with _open(feed) as response:
            raw = response.read(4 * 1024 * 1024)
        try:
            manifest = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpdateError(f"malformed manifest at {feed}: {exc}") from exc
        if not isinstance(manifest, dict):
            raise UpdateError("manifest must be a JSON object")
        return manifest

    def _install_set(self, name: str, url: str, expected_sha256: str = "") -> Path:
        safe_name = "".join(c for c in name if c.isalnum() or c in "-_")
        if not safe_name:
            raise UpdateError(f"invalid set name: {name!r}")

        target_dir = paths.signatures_dir()
        with tempfile.NamedTemporaryFile(dir=str(target_dir), delete=False, suffix=".part") as handle:
            temp_path = Path(handle.name)
            try:
                with _open(url) as response:
                    written = 0
                    while True:
                        chunk = response.read(1024 * 256)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > MAX_SET_BYTES:
                            raise UpdateError(f"set '{name}' exceeds {MAX_SET_BYTES} bytes")
                        handle.write(chunk)
            except UpdateError:
                temp_path.unlink(missing_ok=True)
                raise

        try:
            if expected_sha256:
                actual = sha256_file(temp_path)
                if actual != expected_sha256:
                    raise UpdateError(f"digest mismatch for '{name}' (expected {expected_sha256[:12]}…)")

            document = json.loads(temp_path.read_text(encoding="utf-8"))
            if not isinstance(document, dict) or not (document.get("hashes") or document.get("patterns")):
                raise UpdateError(f"set '{name}' contains no signatures")
        except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
            temp_path.unlink(missing_ok=True)
            raise UpdateError(f"set '{name}' is not a valid signature set: {exc}") from exc
        except UpdateError:
            temp_path.unlink(missing_ok=True)
            raise

        final = target_dir / f"{safe_name}.json"
        temp_path.replace(final)
        return final


def update_signatures(force: bool = False) -> Dict[str, Any]:
    return SignatureUpdater().update(force=force)


def check_signatures() -> Dict[str, Any]:
    return SignatureUpdater().check()
