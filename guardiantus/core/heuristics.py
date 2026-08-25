"""Heuristic analysis for files no signature covers.

Every rule contributes a score, and the scores are summed and compared against
the configured threshold.  Nothing here is conclusive on its own, so a
heuristic-only hit is reported as *suspicious* rather than *malicious* unless
the score is overwhelming.

Findings come in two flavours, and the distinction is what keeps the noise
down:

*primary*
    A construct that is specific to malicious software: an encoded PowerShell
    command, a reverse shell, ``vssadmin delete shadows``, an executable
    wearing a ``.pdf`` name.

*supporting*
    A property that malware often has but ordinary files have too: high
    entropy, an embedded base64 blob, hardcoded URLs, an import of
    ``VirtualAllocEx``.  Minecraft asset bundles, launcher logs and Windows
    API-set DLLs all trip several of these, and adding them up used to be
    enough to cross the threshold on their own.

A file is only reported when **at least one primary finding** is present.
Supporting findings then push the score up (or fail to), but they can never
raise an alarm by themselves.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .models import Detection, DetectionSource, Severity

#: Extensions that get script-level inspection.
SCRIPT_EXTENSIONS = {
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".hta", ".sh", ".bash", ".py", ".pl", ".php", ".rb", ".lua",
}

#: Extensions commonly used to disguise executables.
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".sys", ".ocx", ".msi",
}

DOCUMENT_EXTENSIONS = {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf", ".pdf"}

#: Windows ships hundreds of forwarder DLLs whose whole job is to re-export
#: kernel functions.  Their export tables name every process and memory API
#: there is, which is not a hint about anything.
SYSTEM_LIBRARY_PREFIXES = (
    "api-ms-win-", "ext-ms-win-", "ucrtbase", "vcruntime", "msvcp", "msvcr",
    "kernel32", "kernelbase", "ntdll", "advapi32", "combase", "python3",
    "libcrypto", "libssl",
)


@dataclass
class Finding:
    """One heuristic observation about a file."""

    label: str
    score: int
    severity: Severity
    #: ``True`` for constructs specific to malicious software.  Only a primary
    #: finding can raise an alarm; the rest merely add weight to one.
    primary: bool = False
    evidence: Dict[str, Any] = field(default_factory=dict)


#: Suspicious constructs found in scripts. (regex, label, score, primary)
SCRIPT_PATTERNS: List[Tuple[re.Pattern, str, int, bool]] = [
    (re.compile(rb"(?i)frombase64string\s*\(", re.S), "PowerShell base64 payload decode", 25, False),
    (re.compile(rb"(?i)-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{40,}", re.S),
     "PowerShell encoded command", 40, True),
    (re.compile(rb"(?i)invoke-expression|(?<![\w-])iex(?![\w-])", re.S),
     "Dynamic code execution (IEX)", 25, False),
    (re.compile(rb"(?i)downloadstring\s*\(|downloadfile\s*\(", re.S), "Remote payload download", 30, False),
    (re.compile(rb"(?i)new-object\s+system\.net\.webclient", re.S), "WebClient dropper pattern", 25, False),
    (re.compile(rb"(?i)\bhidden\b.{0,40}\b(?:windowstyle|bypass)\b", re.S),
     "Hidden execution window", 20, False),
    (re.compile(rb"(?i)-(?:exec(?:utionpolicy)?)\s+bypass", re.S), "ExecutionPolicy bypass", 30, True),
    (re.compile(rb"(?i)\beval\s*\(\s*(?:atob|base64_decode|gzinflate)", re.S),
     "Obfuscated eval chain", 40, True),
    (re.compile(rb"(?i)\bshell_exec\s*\(|\bpassthru\s*\(|\bsystem\s*\(\s*\$_", re.S),
     "PHP command execution", 35, True),
    (re.compile(rb"(?i)wscript\.shell", re.S), "WScript.Shell automation", 20, False),
    (re.compile(rb"(?i)vbscript\.encode|\bexecute\s*\(\s*chr\s*\(", re.S), "Encoded VBScript", 30, True),
    (re.compile(rb"(?i)reg(?:\.exe)?\s+add\s+.{0,80}\\currentversion\\run", re.S),
     "Run-key persistence", 35, True),
    (re.compile(rb"(?i)schtasks\s+/create", re.S), "Scheduled-task persistence", 25, False),
    (re.compile(rb"(?i)vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog", re.S),
     "Shadow-copy deletion (ransomware)", 60, True),
    (re.compile(rb"(?i)bcdedit\s+.{0,40}recoveryenabled\s+no", re.S),
     "Recovery disabled (ransomware)", 55, True),
    (re.compile(rb"(?i)cipher\s+/w:", re.S), "Free-space wiping", 25, False),
    (re.compile(rb"(?i)rm\s+-rf\s+(?:/|/\*|\$HOME)", re.S), "Destructive recursive delete", 45, True),
    (re.compile(rb"(?i)(?:curl|wget)\s+[^|\n]{0,120}\|\s*(?:ba)?sh", re.S),
     "Pipe-to-shell installer", 40, True),
    (re.compile(rb"(?i)chattr\s+\+i|history\s+-c\b", re.S), "Anti-forensics", 20, False),
    (re.compile(rb"(?i)nc(?:\.exe)?\s+-(?:l|e)\s", re.S), "Netcat listener/reverse shell", 35, True),
    (re.compile(rb"(?i)/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+", re.S), "Raw TCP reverse shell", 45, True),
    (re.compile(rb"(?i)socket\s*\(.{0,60}connect\s*\(.{0,60}dup2\s*\(", re.S),
     "Reverse-shell socket chain", 45, True),
    (re.compile(rb"(?i)crontab\s+-\s*$|>>\s*/etc/cron", re.S), "Cron persistence", 25, False),
    (re.compile(rb"(?i)mimikatz|sekurlsa::|lsadump::", re.S), "Credential-dumping tooling", 70, True),
    (re.compile(rb"(?i)\bkeylog|GetAsyncKeyState|SetWindowsHookEx", re.S), "Keylogging API usage", 40, True),
]

#: Labels that fetch something from the network, and labels that run whatever
#: they are handed.  Either alone is ordinary; together they are a dropper.
_DOWNLOAD_LABELS = {"Remote payload download", "WebClient dropper pattern"}
_EXECUTE_LABELS = {"Dynamic code execution (IEX)", "Obfuscated eval chain", "WScript.Shell automation"}

#: Windows API imports that, combined, indicate process injection.
INJECTION_APIS = [
    b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
    b"NtUnmapViewOfSection", b"SetThreadContext", b"QueueUserAPC",
    b"RtlCreateUserThread", b"NtWriteVirtualMemory",
]

PACKER_MARKERS = [
    (b"UPX!", "UPX"), (b"UPX0", "UPX"), (b"ASPack", "ASPack"), (b".aspack", "ASPack"),
    (b"MPRESS1", "MPRESS"), (b"PECompact", "PECompact"), (b"Themida", "Themida"),
    (b"VMProtect", "VMProtect"), (b".petite", "Petite"), (b"FSG!", "FSG"),
]

RANSOM_NOTE_HINTS = [
    b"your files have been encrypted", b"all your files are encrypted",
    b"to decrypt your files", b"bitcoin wallet", b"tor browser",
    b"recover your data", b"decryption key",
]

_IPV4 = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL = re.compile(rb"(?i)\bhttps?://[a-z0-9.\-]{4,}", re.S)
_ONION = re.compile(rb"(?i)\b[a-z2-7]{16,56}\.onion\b")
#: Only very long unbroken base64 runs are interesting.  Config files, skin
#: caches and web assets routinely carry a few hundred characters of it.
_LONG_B64 = re.compile(rb"[A-Za-z0-9+/]{1500,}={0,2}")


def shannon_entropy(data: bytes) -> float:
    """Entropy in bits/byte. 0 = uniform, 8 = perfectly random."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:8192]
    if b"\x00" in sample:
        return True
    printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
    return printable / len(sample) < 0.75


def detect_file_type(data: bytes, path: Optional[Path] = None) -> str:
    """Cheap magic-byte based type detection."""
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "macho"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"\xd0\xcf\x11\xe0"):
        return "ole"
    if data.startswith(b"Rar!"):
        return "rar"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"#!"):
        return "script"
    if path and path.suffix.lower() in SCRIPT_EXTENSIONS:
        return "script"
    return "binary" if looks_binary(data) else "text"


def _has_double_extension(path: Path) -> Optional[str]:
    """``invoice.pdf.exe`` style names."""
    parts = path.name.lower().split(".")
    if len(parts) < 3:
        return None
    inner = f".{parts[-2]}"
    outer = f".{parts[-1]}"
    decoys = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".mp4", ".zip"}
    if inner in decoys and outer in EXECUTABLE_EXTENSIONS | {".js", ".vbs", ".scr", ".bat", ".cmd"}:
        return f"{inner}{outer}"
    return None


#: U+202E RIGHT-TO-LEFT OVERRIDE and U+202B RIGHT-TO-LEFT EMBEDDING.
_RTL_MARKS = ("‮", "‫", "⁧")


def _has_rtl_override(path: Path) -> bool:
    """Right-to-left override hides the real extension in file managers."""
    return any(mark in path.name for mark in _RTL_MARKS)


def _is_system_library(path: Optional[Path]) -> bool:
    """Is this one of the OS/runtime libraries that re-export everything?"""
    if path is None:
        return False
    name = path.name.lower()
    return name.startswith(SYSTEM_LIBRARY_PREFIXES)


def is_os_runtime_library(path: Optional[Path], data: bytes) -> bool:
    """An OS/runtime library whose contents are an export table, nothing more.

    Both halves matter.  The name alone would let malware opt out of every
    behavioural rule by calling itself ``api-ms-win-core-memory-l1-1-0.dll``;
    requiring an actual PE that also carries its own api-set name means the
    file has to *be* the forwarder it claims to be.
    """
    if path is None or not _is_system_library(path) or not data.startswith(b"MZ"):
        return False
    stem = path.stem.lower().encode("ascii", "ignore")
    # The export directory of a forwarder carries the module's own name.
    return bool(stem) and stem in data.lower()


def _pe_analysis(data: bytes, path: Optional[Path] = None) -> List[Finding]:
    """Structural checks against a PE image. All of them are supporting."""
    findings: List[Finding] = []
    if len(data) < 0x40:
        return findings
    try:
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    except (ValueError, IndexError):
        return findings
    if pe_offset <= 0 or pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        findings.append(Finding("Corrupted or forged PE header", 25, Severity.MEDIUM))
        return findings

    coff = pe_offset + 4
    try:
        number_of_sections = int.from_bytes(data[coff + 2:coff + 4], "little")
    except (ValueError, IndexError):
        return findings

    if number_of_sections == 0 or number_of_sections > 32:
        findings.append(
            Finding("Unusual PE section count", 25, Severity.MEDIUM,
                    evidence={"sections": number_of_sections})
        )

    found_packers = [label for marker, label in PACKER_MARKERS if marker in data[:8192]]
    if found_packers:
        findings.append(
            Finding(f"Packed executable ({found_packers[0]})", 30, Severity.MEDIUM,
                    evidence={"packer": found_packers[0]})
        )

    # A DLL that re-exports the Win32 API is not injecting into anything, and
    # two matching strings prove nothing -- plenty of debuggers, installers and
    # anti-cheat shims import them.  Three or more, in something that is not a
    # system library, is worth counting towards a verdict someone else raised.
    if not _is_system_library(path):
        present = [api.decode() for api in INJECTION_APIS if api in data]
        if len(present) >= 3:
            findings.append(
                Finding("Process-injection API combination", min(30, 10 * len(present)),
                        Severity.MEDIUM, evidence={"apis": present})
            )
    return findings


def _script_patterns(data: bytes) -> List[Finding]:
    """Match the attacker-construct patterns. Runs on scripts and plain text."""
    findings: List[Finding] = []
    labels = set()
    for pattern, label, score, primary in SCRIPT_PATTERNS:
        match = pattern.search(data)
        if match:
            severity = Severity.HIGH if score >= 40 else Severity.MEDIUM
            findings.append(Finding(label, score, severity, primary, {"offset": match.start()}))
            labels.add(label)

    # Fetching a payload is ordinary and running a string is ordinary; a script
    # that does both in one breath is a download cradle.
    if labels & _DOWNLOAD_LABELS and labels & _EXECUTE_LABELS:
        findings.append(Finding("Download-and-execute chain", 45, Severity.HIGH, True))

    if _ONION.search(data):
        findings.append(Finding("Tor hidden-service address", 35, Severity.HIGH, True))
    return findings


def _script_statistics(data: bytes) -> List[Finding]:
    """Shape-of-the-file signals. Scripts only -- data files trip all of them."""
    findings: List[Finding] = []

    blobs = _LONG_B64.findall(data)
    if blobs:
        longest = max(len(b) for b in blobs)
        findings.append(
            Finding("Large embedded base64 blob", 20, Severity.LOW, evidence={"length": longest})
        )

    urls = set(_URL.findall(data))
    if len(urls) > 12:
        findings.append(Finding("Many hardcoded URLs", 10, Severity.LOW, evidence={"count": len(urls)}))

    ips = {ip for ip in _IPV4.findall(data) if not ip.startswith((b"0.", b"127.", b"255."))}
    if len(ips) >= 3:
        findings.append(
            Finding("Multiple hardcoded IP addresses", 10, Severity.LOW, evidence={"count": len(ips)})
        )
    return findings


def analyse(
    data: bytes,
    path: Optional[Path] = None,
    file_size: Optional[int] = None,
    threshold: int = 60,
) -> List[Detection]:
    """Run every heuristic rule and fold the hits into a detection."""
    if not data:
        return []

    path = Path(path) if path is not None else None
    size = file_size if file_size is not None else len(data)
    file_type = detect_file_type(data, path)
    suffix = path.suffix.lower() if path is not None else ""
    is_script = file_type == "script" or suffix in SCRIPT_EXTENSIONS
    findings: List[Finding] = []

    # --- naming tricks -------------------------------------------------
    if path is not None:
        double = _has_double_extension(path)
        if double:
            findings.append(
                Finding("Double extension disguise", 45, Severity.HIGH, True, {"extension": double})
            )
        if _has_rtl_override(path):
            findings.append(
                Finding("Right-to-left override in filename", 60, Severity.HIGH, True,
                        {"filename": path.name})
            )
        if suffix in DOCUMENT_EXTENSIONS and file_type in ("pe", "elf", "macho"):
            findings.append(
                Finding("Executable masquerading as a document", 65, Severity.CRITICAL, True,
                        {"claimed": suffix})
            )
        if suffix in {".jpg", ".png", ".gif", ".mp3", ".mp4"} and file_type in ("pe", "elf"):
            findings.append(
                Finding("Executable masquerading as media", 60, Severity.HIGH, True, {"claimed": suffix})
            )

    # --- entropy -------------------------------------------------------
    # Compressed archives, media and minified assets are all high-entropy, so
    # this only ever counts as corroboration.
    entropy = shannon_entropy(data[:1024 * 256])
    if file_type in ("pe", "elf", "macho") and entropy > 7.2:
        findings.append(
            Finding("High-entropy executable (packed/encrypted)", 30, Severity.MEDIUM,
                    evidence={"entropy": round(entropy, 2)})
        )
    elif is_script and entropy > 6.2 and size > 2048:
        findings.append(
            Finding("Obfuscated script content", 20, Severity.MEDIUM,
                    evidence={"entropy": round(entropy, 2)})
        )

    # --- structural ----------------------------------------------------
    if file_type == "pe":
        findings.extend(_pe_analysis(data, path))
    if file_type in ("script", "text", "ole") or is_script:
        findings.extend(_script_patterns(data))
    if is_script:
        findings.extend(_script_statistics(data))

    has_vba = b"vbaProject" in data or b"macros/vbaProject" in data
    if file_type in ("ole", "zip") and has_vba:
        findings.append(Finding("Embedded VBA macro project", 35, Severity.MEDIUM))
    if b"Auto_Open" in data or b"AutoOpen" in data or b"Document_Open" in data:
        findings.append(Finding("Auto-executing office macro", 45, Severity.HIGH, True))
    if file_type == "pdf" and (b"/JavaScript" in data or b"/JS" in data) and b"/OpenAction" in data:
        findings.append(Finding("PDF with auto-run JavaScript", 40, Severity.HIGH, True))

    lowered = data[:200_000].lower()
    note_hits = [hint.decode() for hint in RANSOM_NOTE_HINTS if hint in lowered]
    if len(note_hits) >= 2:
        findings.append(
            Finding("Ransom-note text", 70, Severity.CRITICAL, True, {"phrases": note_hits[:3]})
        )

    # --- tiny droppers -------------------------------------------------
    if file_type in ("pe", "elf") and size < 8192:
        findings.append(Finding("Unusually small executable", 15, Severity.LOW, evidence={"size": size}))

    # A pile of circumstantial observations is not a detection.  Without one
    # construct that is specific to malware, stay quiet however high the total.
    primary = [f for f in findings if f.primary]
    if not primary:
        return []

    total = sum(f.score for f in findings)
    if total < threshold:
        return []

    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    # Both the name and the severity come from the primary findings, so the
    # user never sees an alarm titled after a supporting observation.
    label = max(primary, key=lambda f: f.score).label
    severity = max((f.severity for f in primary), key=lambda s: order.index(s))
    ranked = sorted(findings, key=lambda f: -f.score)

    return [
        Detection(
            name=f"Heuristic.{_slug(label)}",
            source=DetectionSource.HEURISTIC,
            severity=severity,
            description="; ".join(f.label for f in ranked[:5]),
            score=min(100, total),
            evidence={
                "file_type": file_type,
                "entropy": round(entropy, 2),
                "total_score": total,
                "threshold": threshold,
                "rules": [
                    {
                        "rule": f.label,
                        "score": f.score,
                        "severity": f.severity.value,
                        "primary": f.primary,
                        **f.evidence,
                    }
                    for f in ranked
                ],
            },
        )
    ]


def _slug(label: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "", label.title())
    return cleaned[:40] or "Generic"
