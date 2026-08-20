"""Hashing helpers used for signature matching and integrity checks."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, Optional, Union

CHUNK_SIZE = 1024 * 1024  # 1 MiB


def hash_bytes(data: bytes, algorithms: tuple = ("md5", "sha1", "sha256")) -> Dict[str, str]:
    """Return several digests of ``data`` in one pass."""
    digests = {name: hashlib.new(name) for name in algorithms}
    for digest in digests.values():
        digest.update(data)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def hash_file(
    path: Union[str, Path],
    algorithms: tuple = ("md5", "sha1", "sha256"),
    max_bytes: Optional[int] = None,
) -> Dict[str, str]:
    """Stream ``path`` and return the requested digests.

    ``max_bytes`` caps how much of the file is read, which keeps huge files
    from stalling a scan.  Callers that rely on a full-file digest must leave
    it at ``None``.
    """
    digests = {name: hashlib.new(name) for name in algorithms}
    read = 0
    with open(path, "rb") as handle:
        while True:
            budget = CHUNK_SIZE
            if max_bytes is not None:
                remaining = max_bytes - read
                if remaining <= 0:
                    break
                budget = min(CHUNK_SIZE, remaining)
            chunk = handle.read(budget)
            if not chunk:
                break
            read += len(chunk)
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def sha256_file(path: Union[str, Path]) -> str:
    return hash_file(path, algorithms=("sha256",))["sha256"]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
