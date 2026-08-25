"""Detection engine: signatures, heuristics, YARA and the file scanner."""

from __future__ import annotations

import zipfile

import pytest

from guardiantus.core import heuristics
from guardiantus.core.hashing import hash_bytes, hash_file, sha256_bytes
from guardiantus.core.models import DetectionSource, Severity, Verdict
from guardiantus.core.signatures import get_signatures
from guardiantus.core.yara_engine import _eval_boolean, _parse_rules, get_yara

# ------------------------------------------------------------------ hashing


def test_hash_file_matches_hash_bytes(tmp_path):
    payload = b"guardiantus" * 1000
    target = tmp_path / "blob.bin"
    target.write_bytes(payload)
    assert hash_file(target) == hash_bytes(payload)


def test_hash_file_respects_max_bytes(tmp_path):
    target = tmp_path / "big.bin"
    target.write_bytes(b"A" * 5000)
    assert hash_file(target, max_bytes=1000)["sha256"] == sha256_bytes(b"A" * 1000)


# --------------------------------------------------------------- signatures


def test_bundled_signatures_load():
    signatures = get_signatures()
    assert signatures.count > 0
    assert signatures.pattern_count > 0
    assert signatures.info()["version"]


def test_eicar_is_detected_by_pattern(scanner, samples):
    result = scanner.scan_file(samples / "eicar.com")
    assert result.verdict is Verdict.MALICIOUS
    assert result.primary_name == "EICAR-Test-File"
    assert any(d.source is DetectionSource.SIGNATURE for d in result.detections)


def test_hash_signature_matches(scanner, samples):
    result = scanner.scan_file(samples / "probe.txt")
    assert result.is_threat
    assert result.primary_name == "Guardiantus.SelfTest.HashProbe"


def test_clean_file_is_clean(scanner, samples):
    result = scanner.scan_file(samples / "clean.txt")
    assert result.verdict is Verdict.CLEAN
    assert result.detections == []


def test_custom_hash_can_be_added(scanner, tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"a locally known bad file")
    digest = hash_file(target)["sha256"]

    assert scanner.scan_file(target).verdict is Verdict.CLEAN
    get_signatures().add_hash(digest, "Local.Test.Sample", severity=Severity.HIGH)
    result = scanner.scan_file(target)
    assert result.verdict is Verdict.MALICIOUS
    assert result.primary_name == "Local.Test.Sample"


def test_detections_are_deduplicated(scanner, samples):
    """An entry carrying both md5 and sha256 must report one finding, not two."""
    result = scanner.scan_file(samples / "probe.txt")
    names = [(d.name, d.source) for d in result.detections]
    assert len(names) == len(set(names))


# --------------------------------------------------------------- heuristics


def test_entropy_bounds():
    assert heuristics.shannon_entropy(b"") == 0.0
    assert heuristics.shannon_entropy(b"A" * 1000) == pytest.approx(0.0)
    assert heuristics.shannon_entropy(bytes(range(256)) * 4) == pytest.approx(8.0, abs=0.01)


def test_file_type_detection():
    assert heuristics.detect_file_type(b"MZ\x90\x00") == "pe"
    assert heuristics.detect_file_type(b"\x7fELF\x02") == "elf"
    assert heuristics.detect_file_type(b"PK\x03\x04") == "zip"
    assert heuristics.detect_file_type(b"%PDF-1.7") == "pdf"
    assert heuristics.detect_file_type(b"#!/bin/sh\n") == "script"
    assert heuristics.detect_file_type(b"plain english text") == "text"


def test_double_extension_is_flagged(tmp_path):
    target = tmp_path / "invoice.pdf.exe"
    target.write_bytes(b"MZ" + b"\x00" * 4096)
    detections = heuristics.analyse(target.read_bytes(), path=target, threshold=40)
    assert detections
    assert "Double extension" in detections[0].description


def test_executable_masquerading_as_document(tmp_path):
    target = tmp_path / "report.doc"
    target.write_bytes(b"MZ" + b"\x00" * 8192)
    detections = heuristics.analyse(target.read_bytes(), path=target, threshold=60)
    assert detections
    assert detections[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_powershell_cradle_scores_high(samples):
    data = (samples / "cradle.ps1").read_bytes()
    detections = heuristics.analyse(data, path=samples / "cradle.ps1", threshold=60)
    assert detections
    assert detections[0].score >= 60


def test_ordinary_text_is_not_flagged(tmp_path):
    target = tmp_path / "diary.txt"
    target.write_text("Today I went for a walk and bought bread. " * 40)
    assert heuristics.analyse(target.read_bytes(), path=target, threshold=60) == []


def test_heuristics_respect_threshold(samples):
    data = (samples / "cradle.ps1").read_bytes()
    assert heuristics.analyse(data, path=samples / "cradle.ps1", threshold=10_000) == []


# ------------------------------------------------------- heuristics: quiet

def test_supporting_findings_alone_never_raise_an_alarm(tmp_path):
    """Circumstantial signals must not add up to a detection on their own.

    This file trips high entropy, an embedded base64 blob, a pile of URLs and
    a pile of IP addresses -- and is a perfectly ordinary launcher log.
    """
    target = tmp_path / "launcher.ps1"
    target.write_text(
        "\n".join(
            f"[{i:05d}] fetching https://libraries.example.net/pkg-{i}/lib-{i}.jar "
            f"sha1={i:040x} from 13.107.{i % 255}.{(i * 7) % 255}"
            for i in range(2000)
        )
        + "\n# cache: " + "QUJDRGVmZ2hpams" * 400 + "\n"
    )
    assert heuristics.analyse(target.read_bytes(), path=target, threshold=60) == []


def test_launcher_log_is_not_obfuscated_script_content(scanner, tmp_path):
    target = tmp_path / "launcher_log2.txt"
    target.write_text(
        "\n".join(
            f"[{i:05d}] INFO downloading https://example.invalid/asset{i}.bin "
            f"from 93.184.{i % 255}.{(i * 3) % 255} hash={i:064x}"
            for i in range(4000)
        )
    )
    assert scanner.scan_file(target).verdict is Verdict.CLEAN


def test_json_full_of_base64_is_clean(scanner, tmp_path):
    """Skin caches, key stores and web assets embed base64 as a matter of course."""
    import base64
    import json

    target = tmp_path / "launcher_custom_skins.json"
    target.write_text(json.dumps({
        f"skin{i}": base64.b64encode(bytes(range(256)) * 4).decode() for i in range(20)
    }))
    assert scanner.scan_file(target).verdict is Verdict.CLEAN


def test_two_injection_apis_are_not_enough(tmp_path):
    target = tmp_path / "installer.exe"
    target.write_bytes(_pe_image(b"VirtualAllocEx\x00WriteProcessMemory\x00"))
    assert heuristics.analyse(target.read_bytes(), path=target, threshold=60) == []


def test_api_set_forwarder_is_judged_on_signatures_only(scanner, tmp_path):
    """A genuine Windows forwarder DLL lists every process API by design."""
    name = "api-ms-win-core-processthreads-l1-1-0.dll"
    target = tmp_path / name
    target.write_bytes(_pe_image(
        name.encode() + b"\x00VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"
    ))
    assert scanner.scan_file(target).verdict is Verdict.CLEAN


def test_impostor_cannot_hide_behind_a_system_name(scanner, tmp_path):
    """Borrowing the name without being the forwarder buys nothing."""
    target = tmp_path / "api-ms-win-core-memory-l1-1-0.dll"
    target.write_bytes(_pe_image(
        b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"
    ))
    assert scanner.scan_file(target).verdict is Verdict.MALICIOUS


def _pe_image(payload: bytes) -> bytes:
    """A minimal, structurally valid PE carrying ``payload`` as string data."""
    header = bytearray(b"MZ" + b"\x00" * 0x3E)
    header[0x3C:0x40] = (0x80).to_bytes(4, "little")
    header += b"\x00" * (0x80 - len(header))
    header += b"PE\x00\x00" + (2).to_bytes(2, "little") + (4).to_bytes(2, "little")
    header += b"\x00" * 20
    return bytes(header) + payload + b"\x00" * 20_000


def test_the_scanner_does_not_detect_itself(scanner):
    """Our own rules and signature database are lists of malware strings."""
    from guardiantus import paths

    for own in (paths.BUNDLED_RULES / "guardiantus_base.yar",
                paths.BUNDLED_SIGNATURES / "base.json"):
        result = scanner.scan_file(own)
        assert result.verdict is Verdict.SKIPPED, f"{own.name} was scanned"
        assert result.error == "excluded"


def test_the_data_directory_is_never_scanned(scanner, isolated_home):
    planted = isolated_home / "logs" / "note.txt"
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_text("all your files are encrypted; to decrypt your files send bitcoin")
    assert scanner.scan_file(planted).verdict is Verdict.SKIPPED


def test_a_trusted_hash_is_never_flagged_again(scanner, samples):
    from guardiantus.core.hashing import hash_file

    target = samples / "eicar.com"
    assert scanner.scan_file(target).verdict is Verdict.MALICIOUS

    scanner.config.trust_hash(hash_file(target)["sha256"])
    result = scanner.scan_file(target)
    assert result.verdict is Verdict.CLEAN
    assert result.error == "allowed by user"


# --------------------------------------------------------------------- yara


def test_bundled_rules_parse():
    yara = get_yara()
    assert yara.rule_count > 0
    assert not yara.info()["errors"]


def test_yara_reverse_shell_rule(scanner, samples):
    result = scanner.scan_file(samples / "shell.sh")
    assert result.verdict is Verdict.MALICIOUS
    assert any(d.source is DetectionSource.YARA for d in result.detections)


def test_yara_ransom_note_rule(scanner, samples):
    result = scanner.scan_file(samples / "ransom_note.txt")
    assert result.is_threat
    assert "Ransom" in result.primary_name


def test_fallback_boolean_evaluator():
    hits = {"$a": 0, "$b": 5}
    assert _eval_boolean("$a and $b", hits) is True
    assert _eval_boolean("$a and $c", hits) is False
    assert _eval_boolean("$a or $c", hits) is True
    assert _eval_boolean("$a and (not $c or $b)", hits) is True
    assert _eval_boolean("not $a", hits) is False
    # Unsupported syntax must fail closed, never open.
    assert _eval_boolean("filesize < 100", hits) is False
    assert _eval_boolean("$a and", hits) is False


def test_fallback_rule_parser_handles_counts():
    source = """
    rule Demo {
        meta:
            severity = "high"
        strings:
            $a = "alpha"
            $b = "beta"
            $c = "gamma"
        condition:
            2 of them
    }
    """
    rules = _parse_rules(source)
    assert len(rules) == 1
    assert rules[0].evaluate(b"alpha and beta") is not None
    assert rules[0].evaluate(b"alpha only") is None


def test_fallback_rule_parser_handles_hex_and_nocase():
    source = """
    rule Hexy {
        strings:
            $mz = { 4d 5a 90 00 }
            $s = "Suspicious" nocase
        condition:
            $mz and $s
    }
    """
    rules = _parse_rules(source)
    assert rules[0].evaluate(b"\x4d\x5a\x90\x00 with sUsPiCiOuS content") is not None
    assert rules[0].evaluate(b"\x4d\x5a\x90\x00 clean") is None


# ------------------------------------------------------------------ archive


def test_archive_member_is_scanned(scanner, samples, tmp_path):
    archive = tmp_path / "bundle.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("docs/readme.txt", "nothing to see")
        handle.writestr("payload/run.sh", (samples / "shell.sh").read_text())
    result = scanner.scan_file(archive)
    assert result.is_threat
    assert any("archive_member" in d.evidence for d in result.detections)


def test_archive_path_traversal_is_flagged(scanner, tmp_path):
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../../etc/passwd", "root:x:0:0")
    result = scanner.scan_file(archive)
    assert any(d.name == "Archive.PathTraversal" for d in result.detections)


def test_clean_archive_stays_clean(scanner, tmp_path):
    archive = tmp_path / "clean.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("a.txt", "hello")
        handle.writestr("b.txt", "world")
    assert scanner.scan_file(archive).verdict is Verdict.CLEAN


# ------------------------------------------------------------------- policy


def test_missing_file_reports_skipped(scanner, tmp_path):
    result = scanner.scan_file(tmp_path / "nope.bin")
    assert result.verdict is Verdict.SKIPPED


def test_empty_file_is_clean(scanner, tmp_path):
    target = tmp_path / "empty.bin"
    target.touch()
    assert scanner.scan_file(target).verdict is Verdict.CLEAN


def test_excluded_extension_is_skipped(scanner, samples):
    scanner.config.set("scanning", "excluded_extensions", [".com"])
    result = scanner.scan_file(samples / "eicar.com")
    assert result.verdict is Verdict.SKIPPED
    assert result.error == "excluded"


def test_excluded_path_is_skipped(scanner, samples):
    scanner.config.set("scanning", "excluded_paths", [str(samples)])
    assert scanner.scan_file(samples / "eicar.com").verdict is Verdict.SKIPPED


def test_symlinks_are_skipped_by_default(scanner, samples, tmp_path):
    link = tmp_path / "link.com"
    try:
        link.symlink_to(samples / "eicar.com")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")
    assert scanner.scan_file(link).verdict is Verdict.SKIPPED


def test_oversized_file_is_hashed_only(scanner, tmp_path):
    scanner.config.set("scanning", "max_file_size_mb", 0)
    target = tmp_path / "large.bin"
    target.write_bytes(b"x" * 4096)
    result = scanner.scan_file(target)
    assert "oversized" in result.error
    assert result.sha256
