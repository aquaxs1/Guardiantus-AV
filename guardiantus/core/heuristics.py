"""Heuristic analysis for files no signature covers.

Each rule contributes a score; the scores are summed and compared against the
configured threshold.  Nothing here is conclusive on its own -- packed files
and obfuscated scripts have legitimate uses -- so a heuristic-only hit is
reported as *suspicious* rather than *malicious* unless the score is
overwhelming.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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

#: Suspicious constructs found in scripts. (regex, label, score)
SCRIPT_PATTERNS: List[Tuple[re.Pattern, str, int]] = [
    (re.compile(rb"(?i)frombase64string\s*\(", re.S), "PowerShell base64 payload decode", 25),
    (re.compile(rb"(?i)-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{40,}", re.S),
     "PowerShell encoded command", 40),
    (re.compile(rb"(?i)invoke-expression|(?<![\w-])iex(?![\w-])", re.S), "Dynamic code execution (IEX)", 25),
    (re.compile(rb"(?i)downloadstring\s*\(|downloadfile\s*\(", re.S), "Remote payload download", 30),
    (re.compile(rb"(?i)new-object\s+system\.net\.webclient", re.S), "WebClient dropper pattern", 25),
    (re.compile(rb"(?i)\bhidden\b.{0,40}\b(?:windowstyle|bypass)\b", re.S), "Hidden execution window", 20),
    (re.compile(rb"(?i)-(?:exec(?:utionpolicy)?)\s+bypass", re.S), "ExecutionPolicy bypass", 30),
    (re.compile(rb"(?i)\beval\s*\(\s*(?:atob|base64_decode|gzinflate)", re.S), "Obfuscated eval chain", 40),
    (re.compile(rb"(?i)\bshell_exec\s*\(|\bpassthru\s*\(|\bsystem\s*\(\s*\$_", re.S),
     "PHP command execution", 35),
    (re.compile(rb"(?i)wscript\.shell", re.S), "WScript.Shell automation", 20),
    (re.compile(rb"(?i)vbscript\.encode|\bexecute\s*\(\s*chr\s*\(", re.S), "Encoded VBScript", 30),
    (re.compile(rb"(?i)reg(?:\.exe)?\s+add\s+.{0,80}\\currentversion\\run", re.S),
     "Run-key persistence", 35),
    (re.compile(rb"(?i)schtasks\s+/create", re.S), "Scheduled-task persistence", 25),
    (re.compile(rb"(?i)vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog", re.S),
     "Shadow-copy deletion (ransomware)", 60),
    (re.compile(rb"(?i)bcdedit\s+.{0,40}recoveryenabled\s+no", re.S), "Recovery disabled (ransomware)", 55),
    (re.compile(rb"(?i)cipher\s+/w:", re.S), "Free-space wiping", 25),
    (re.compile(rb"(?i)rm\s+-rf\s+(?:/|/\*|\$HOME)", re.S), "Destructive recursive delete", 45),
    (re.compile(rb"(?i)(?:curl|wget)\s+[^|\n]{0,120}\|\s*(?:ba)?sh", re.S), "Pipe-to-shell installer", 40),
    (re.compile(rb"(?i)chattr\s+\+i|history\s+-c\b", re.S), "Anti-forensics", 20),
    (re.compile(rb"(?i)nc(?:\.exe)?\s+-(?:l|e)\s", re.S), "Netcat listener/reverse shell", 35),
    (re.compile(rb"(?i)/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+", re.S), "Raw TCP reverse shell", 45),
    (re.compile(rb"(?i)socket\s*\(.{0,60}connect\s*\(.{0,60}dup2\s*\(", re.S),
     "Reverse-shell socket chain", 45),
    (re.compile(rb"(?i)crontab\s+-\s*$|>>\s*/etc/cron", re.S), "Cron persistence", 25),
    (re.compile(rb"(?i)mimikatz|sekurlsa::|lsadump::", re.S), "Credential-dumping tooling", 70),
    (re.compile(rb"(?i)\bkeylog|GetAsyncKeyState|SetWindowsHookEx", re.S), "Keylogging API usage", 40),
]

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
_LONG_B64 = re.compile(rb"[A-Za-z0-9+/]{200,}={0,2}")


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


def _pe_analysis(data: bytes) -> List[Tuple[str, int, Severity, Dict]]:
    """Structural checks against a PE image."""
    findings: List[Tuple[str, int, Severity, Dict]] = []
    if len(data) < 0x40:
        return findings
    try:
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    except (ValueError, IndexError):
        return findings
    if pe_offset <= 0 or pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        findings.append(("Corrupted or forged PE header", 25, Severity.MEDIUM, {}))
        return findings

    coff = pe_offset + 4
    try:
        number_of_sections = int.from_bytes(data[coff + 2:coff + 4], "little")
        characteristics = int.from_bytes(data[coff + 18:coff + 20], "little")
    except (ValueError, IndexError):
        return findings

    if number_of_sections == 0 or number_of_sections > 32:
        findings.append(
            ("Unusual PE section count", 25, Severity.MEDIUM, {"sections": number_of_sections})
        )
    # 0x2000 = DLL
    if characteristics & 0x2000 and b".dll" not in data[:512].lower():
        findings.append(("DLL characteristics on non-DLL image", 10, Severity.LOW, {}))

    found_packers = [label for marker, label in PACKER_MARKERS if marker in data[:8192]]
    if found_packers:
        findings.append(
            (f"Packed executable ({found_packers[0]})", 30, Severity.MEDIUM, {"packer": found_packers[0]})
        )

    present = [api.decode() for api in INJECTION_APIS if api in data]
    if len(present) >= 2:
        findings.append(
            (
                "Process-injection API combination",
                20 + 15 * min(len(present), 4),
                Severity.HIGH,
                {"apis": present},
            )
        )
    return findings


def _script_analysis(data: bytes) -> List[Tuple[str, int, Severity, Dict]]:
    findings: List[Tuple[str, int, Severity, Dict]] = []
    for pattern, label, score in SCRIPT_PATTERNS:
        match = pattern.search(data)
        if match:
            severity = Severity.HIGH if score >= 40 else Severity.MEDIUM
            findings.append((label, score, severity, {"offset": match.start()}))

    blobs = _LONG_B64.findall(data)
    if blobs:
        longest = max(len(b) for b in blobs)
        findings.append(
            (
                "Large embedded base64 blob",
                min(35, 10 + longest // 400),
                Severity.MEDIUM,
                {"length": longest},
            )
        )

    onion = _ONION.search(data)
    if onion:
        findings.append(("Tor hidden-service address", 35, Severity.HIGH, {}))

    urls = set(_URL.findall(data))
    if len(urls) > 12:
        findings.append(("Many hardcoded URLs", 15, Severity.LOW, {"count": len(urls)}))

    ips = {ip for ip in _IPV4.findall(data) if not ip.startswith((b"0.", b"127.", b"255."))}
    if len(ips) >= 3:
        findings.append(("Multiple hardcoded IP addresses", 20, Severity.MEDIUM, {"count": len(ips)}))
    return findings


def analyse(
    data: bytes,
    path: Optional[Path] = None,
    file_size: Optional[int] = None,
    threshold: int = 60,
) -> List[Detection]:
    """Run every heuristic rule and fold the hits into detections."""
    if not data:
        return []

    path = Path(path) if path is not None else None
    size = file_size if file_size is not None else len(data)
    file_type = detect_file_type(data, path)
    findings: List[Tuple[str, int, Severity, Dict]] = []

    # --- naming tricks -------------------------------------------------
    if path is not None:
        double = _has_double_extension(path)
        if double:
            findings.append(
                ("Double extension disguise", 45, Severity.HIGH, {"extension": double})
            )
        if _has_rtl_override(path):
            findings.append(
                ("Right-to-left override in filename", 60, Severity.HIGH, {"filename": path.name})
            )
        suffix = path.suffix.lower()
        if suffix in DOCUMENT_EXTENSIONS and file_type in ("pe", "elf", "macho"):
            findings.append(
                ("Executable masquerading as a document", 65, Severity.CRITICAL, {"claimed": suffix})
            )
        if suffix in {".jpg", ".png", ".gif", ".mp3", ".mp4"} and file_type in ("pe", "elf"):
            findings.append(
                ("Executable masquerading as media", 60, Severity.HIGH, {"claimed": suffix})
            )

    # --- entropy -------------------------------------------------------
    entropy = shannon_entropy(data[:1024 * 256])
    if file_type in ("pe", "elf", "macho") and entropy > 7.2:
        findings.append(
            (
                "High-entropy executable (packed/encrypted)",
                30,
                Severity.MEDIUM,
                {"entropy": round(entropy, 2)},
            )
        )
    elif file_type in ("script", "text") and entropy > 5.6 and size > 2048:
        findings.append(
            ("Obfuscated script content", 30, Severity.MEDIUM, {"entropy": round(entropy, 2)})
        )

    # --- structural ----------------------------------------------------
    if file_type == "pe":
        findings.extend(_pe_analysis(data))
    if file_type in ("script", "text", "ole") or (path and path.suffix.lower() in SCRIPT_EXTENSIONS):
        findings.extend(_script_analysis(data))
    has_vba = b"vbaProject" in data or b"macros/vbaProject" in data
    if file_type in ("ole", "zip") and has_vba:
        findings.append(("Embedded VBA macro project", 35, Severity.MEDIUM, {}))
    if b"Auto_Open" in data or b"AutoOpen" in data or b"Document_Open" in data:
        findings.append(("Auto-executing office macro", 45, Severity.HIGH, {}))
    if file_type == "pdf" and (b"/JavaScript" in data or b"/JS" in data) and b"/OpenAction" in data:
        findings.append(("PDF with auto-run JavaScript", 40, Severity.HIGH, {}))

    lowered = data[:200_000].lower()
    note_hits = [hint.decode() for hint in RANSOM_NOTE_HINTS if hint in lowered]
    if len(note_hits) >= 2:
        findings.append(("Ransom-note text", 70, Severity.CRITICAL, {"phrases": note_hits[:3]}))

    # --- tiny droppers -------------------------------------------------
    if file_type in ("pe", "elf") and size < 8192:
        findings.append(("Unusually small executable", 15, Severity.LOW, {"size": size}))

    if not findings:
        return []

    total = sum(score for _, score, _, _ in findings)
    if total < threshold:
        return []

    worst = max(findings, key=lambda f: f[1])
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    severity = max((f[2] for f in findings), key=lambda s: order.index(s))
    label = worst[0]

    return [
        Detection(
            name=f"Heuristic.{_slug(label)}",
            source=DetectionSource.HEURISTIC,
            severity=severity,
            description="; ".join(f[0] for f in sorted(findings, key=lambda f: -f[1])[:5]),
            score=min(100, total),
            evidence={
                "file_type": file_type,
                "entropy": round(entropy, 2),
                "total_score": total,
                "threshold": threshold,
                "rules": [
                    {"rule": name, "score": score, "severity": sev.value, **extra}
                    for name, score, sev, extra in sorted(findings, key=lambda f: -f[1])
                ],
            },
        )
    ]


def _slug(label: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "", label.title())
    return cleaned[:40] or "Generic"
