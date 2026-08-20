"""Signature database: exact hashes plus byte-pattern signatures.

Two complementary detection classes live here:

*Hash signatures* -- MD5/SHA-1/SHA-256 of known-bad files.  Cheap, zero false
positives, but only catch the exact byte sequence.

*Pattern signatures* -- a hex or ASCII fragment that must appear in the file,
optionally restricted to files whose content starts with a given magic value.
These survive trivial repacking and cover whole families.

The on-disk format is JSON so users can inspect and extend it by hand::

    {
      "name": "guardiantus-base",
      "version": "2026.08.20",
      "hashes": [
        {"sha256": "...", "name": "Trojan.Generic.A", "severity": "high"}
      ],
      "patterns": [
        {"name": "EICAR-Test-File", "hex": "58354f2150", "severity": "low",
         "description": "Industry standard AV test string"}
      ]
    }
"""

from __future__ import annotations

import binascii
import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .. import paths
from .models import Detection, DetectionSource, Severity

_SEVERITY_SCORE = {
    Severity.INFO: 10,
    Severity.LOW: 40,
    Severity.MEDIUM: 65,
    Severity.HIGH: 85,
    Severity.CRITICAL: 100,
}


def _severity(raw: Any, default: Severity = Severity.HIGH) -> Severity:
    try:
        return Severity(str(raw).lower())
    except ValueError:
        return default


class HashSignature:
    __slots__ = ("digest", "algorithm", "name", "severity", "description")

    def __init__(
        self, digest: str, algorithm: str, name: str, severity: Severity, description: str = ""
    ) -> None:
        self.digest = digest.lower()
        self.algorithm = algorithm
        self.name = name
        self.severity = severity
        self.description = description

    def to_detection(self) -> Detection:
        return Detection(
            name=self.name,
            source=DetectionSource.SIGNATURE,
            severity=self.severity,
            description=self.description or f"Matched known {self.algorithm} signature",
            score=_SEVERITY_SCORE[self.severity],
            evidence={"algorithm": self.algorithm, "digest": self.digest},
        )


class PatternSignature:
    __slots__ = ("pattern", "name", "severity", "description", "magic", "max_offset")

    def __init__(
        self,
        pattern: bytes,
        name: str,
        severity: Severity,
        description: str = "",
        magic: Optional[bytes] = None,
        max_offset: Optional[int] = None,
    ) -> None:
        self.pattern = pattern
        self.name = name
        self.severity = severity
        self.description = description
        self.magic = magic
        self.max_offset = max_offset

    def matches(self, data: bytes) -> int:
        """Return the match offset, or ``-1`` when the signature does not fire."""
        if not self.pattern:
            return -1
        if self.magic and not data.startswith(self.magic):
            return -1
        window = data if self.max_offset is None else data[: self.max_offset + len(self.pattern)]
        return window.find(self.pattern)

    def to_detection(self, offset: int) -> Detection:
        return Detection(
            name=self.name,
            source=DetectionSource.SIGNATURE,
            severity=self.severity,
            description=self.description or "Matched malicious byte pattern",
            score=_SEVERITY_SCORE[self.severity],
            evidence={"offset": offset, "pattern_length": len(self.pattern)},
        )


class SignatureDatabase:
    """Loads every signature set found in the bundled and user directories."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_md5: Dict[str, HashSignature] = {}
        self._by_sha1: Dict[str, HashSignature] = {}
        self._by_sha256: Dict[str, HashSignature] = {}
        self._patterns: List[PatternSignature] = []
        self._sets: List[Dict[str, Any]] = []
        self._loaded_at: float = 0.0

    # ---------------------------------------------------------------- state
    @property
    def hash_count(self) -> int:
        with self._lock:
            return len(self._by_md5) + len(self._by_sha1) + len(self._by_sha256)

    @property
    def pattern_count(self) -> int:
        with self._lock:
            return len(self._patterns)

    @property
    def count(self) -> int:
        return self.hash_count + self.pattern_count

    def info(self) -> Dict[str, Any]:
        with self._lock:
            versions = [s.get("version", "") for s in self._sets if s.get("version")]
            return {
                "sets": list(self._sets),
                "hash_signatures": self.hash_count,
                "pattern_signatures": self.pattern_count,
                "total": self.count,
                "loaded_at": self._loaded_at,
                "version": max(versions) if versions else "unknown",
            }

    # ----------------------------------------------------------------- load
    def load(self, extra_dirs: Optional[Sequence[Path]] = None) -> int:
        """(Re)load every ``*.json`` signature set. Returns the signature count."""
        directories = [paths.BUNDLED_SIGNATURES, paths.signatures_dir()]
        directories.extend(extra_dirs or [])

        with self._lock:
            self._by_md5.clear()
            self._by_sha1.clear()
            self._by_sha256.clear()
            self._patterns.clear()
            self._sets.clear()

            seen: set = set()
            for directory in directories:
                if not directory or not Path(directory).is_dir():
                    continue
                for file in sorted(Path(directory).glob("*.json")):
                    resolved = file.resolve()
                    if resolved in seen:
                        continue
                    seen.add(resolved)
                    try:
                        self._load_file(file)
                    except (OSError, json.JSONDecodeError, ValueError):
                        # A broken set must never take down the whole engine.
                        continue
            self._loaded_at = time.time()
            return self.count

    def _load_file(self, file: Path) -> None:
        document = json.loads(file.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise ValueError("signature set must be a JSON object")

        for entry in document.get("hashes", []) or []:
            name = entry.get("name") or "Malware.Unknown"
            severity = _severity(entry.get("severity"), Severity.HIGH)
            description = entry.get("description", "")
            for algorithm, bucket in (
                ("md5", self._by_md5),
                ("sha1", self._by_sha1),
                ("sha256", self._by_sha256),
            ):
                digest = entry.get(algorithm)
                if digest:
                    bucket[str(digest).lower()] = HashSignature(
                        str(digest), algorithm, name, severity, description
                    )

        for entry in document.get("patterns", []) or []:
            pattern = _decode_pattern(entry)
            if not pattern:
                continue
            magic_raw = entry.get("magic_hex") or entry.get("magic")
            magic = None
            if magic_raw:
                try:
                    magic = (
                        binascii.unhexlify(str(magic_raw).replace(" ", ""))
                        if entry.get("magic_hex")
                        else str(magic_raw).encode("utf-8")
                    )
                except (binascii.Error, ValueError):
                    magic = None
            self._patterns.append(
                PatternSignature(
                    pattern=pattern,
                    name=entry.get("name") or "Malware.Pattern",
                    severity=_severity(entry.get("severity"), Severity.HIGH),
                    description=entry.get("description", ""),
                    magic=magic,
                    max_offset=entry.get("max_offset"),
                )
            )

        self._sets.append(
            {
                "name": document.get("name", file.stem),
                "version": document.get("version", ""),
                "source": str(file),
                "hashes": len(document.get("hashes", []) or []),
                "patterns": len(document.get("patterns", []) or []),
            }
        )

    # ----------------------------------------------------------------- scan
    def match_hashes(self, digests: Dict[str, str]) -> List[Detection]:
        out: List[Detection] = []
        with self._lock:
            for algorithm, bucket in (
                ("sha256", self._by_sha256),
                ("sha1", self._by_sha1),
                ("md5", self._by_md5),
            ):
                digest = (digests.get(algorithm) or "").lower()
                if digest and digest in bucket:
                    out.append(bucket[digest].to_detection())
        return out

    def match_patterns(self, data: bytes) -> List[Detection]:
        out: List[Detection] = []
        with self._lock:
            patterns = list(self._patterns)
        for signature in patterns:
            offset = signature.matches(data)
            if offset >= 0:
                out.append(signature.to_detection(offset))
        return out

    def match(self, digests: Dict[str, str], data: bytes) -> List[Detection]:
        return self.match_hashes(digests) + self.match_patterns(data)

    # -------------------------------------------------------------- editing
    def add_hash(
        self,
        digest: str,
        name: str,
        algorithm: str = "sha256",
        severity: Severity = Severity.HIGH,
        set_name: str = "custom",
    ) -> None:
        """Append a hash to a user-owned signature set and reload."""
        target = paths.signatures_dir() / f"{set_name}.json"
        if target.exists():
            document = json.loads(target.read_text(encoding="utf-8"))
        else:
            document = {"name": set_name, "version": time.strftime("%Y.%m.%d"), "hashes": [], "patterns": []}
        document.setdefault("hashes", []).append(
            {algorithm: digest.lower(), "name": name, "severity": severity.value}
        )
        document["version"] = time.strftime("%Y.%m.%d")
        target.write_text(json.dumps(document, indent=2), encoding="utf-8")
        self.load()


_INSTANCE: Optional[SignatureDatabase] = None
_INSTANCE_LOCK = threading.Lock()


def _decode_pattern(entry: Dict[str, Any]) -> bytes:
    if entry.get("hex"):
        try:
            return binascii.unhexlify(str(entry["hex"]).replace(" ", ""))
        except (binascii.Error, ValueError):
            return b""
    if entry.get("ascii"):
        return str(entry["ascii"]).encode("utf-8", errors="ignore")
    return b""


def get_signatures() -> SignatureDatabase:
    """Process-wide signature database, loaded on first use."""
    global _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is None:
            _INSTANCE = SignatureDatabase()
            _INSTANCE.load()
        return _INSTANCE


def reload_signatures(extra_dirs: Optional[Iterable[Path]] = None) -> int:
    return get_signatures().load(list(extra_dirs) if extra_dirs else None)


def reset_signature_cache() -> None:
    global _INSTANCE
    with _INSTANCE_LOCK:
        _INSTANCE = None
