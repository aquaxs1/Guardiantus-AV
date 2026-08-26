"""Configuration, scheduler, updater, HTTP API and CLI."""

from __future__ import annotations

import json
import pathlib
import time
import urllib.error
import urllib.request
from datetime import datetime

import pytest

from guardiantus.core.scheduler import CronError, Scheduler, cron_matches, next_run, parse_cron
from guardiantus.service import api
from guardiantus.service.server import DashboardServer, _safe_static_path
from guardiantus.updater.programs import _parse_winget_table, _safe_package_id
from guardiantus.updater.signatures_update import SignatureUpdater, UpdateError

# ------------------------------------------------------------------ config


def test_config_defaults_and_persistence(isolated_home):
    from guardiantus.config import Config

    config = Config()
    assert config.get("scanning", "heuristics_enabled") is True

    config.set("scanning", "heuristic_threshold", 42)
    assert Config().get("scanning", "heuristic_threshold") == 42


def test_config_deep_merge(isolated_home):
    from guardiantus.config import Config

    config = Config()
    config.update({"scanning": {"worker_threads": 4}})
    assert config.get("scanning", "worker_threads") == 4
    # Untouched keys in the same section survive the merge.
    assert config.get("scanning", "heuristics_enabled") is True


def test_config_survives_corruption(isolated_home):
    from guardiantus.config import Config

    config = Config()
    config.path.write_text("{not json at all")
    assert Config().get("scanning", "max_file_size_mb") == 512


# --------------------------------------------------------------- scheduler


def test_parse_cron_expands_fields():
    minutes, hours, days, months, weekdays = parse_cron("*/15 9-17 * * 1-5")
    assert minutes == {0, 15, 30, 45}
    assert hours == set(range(9, 18))
    assert days == set(range(1, 32))
    assert months == set(range(1, 13))
    assert weekdays == {1, 2, 3, 4, 5}


@pytest.mark.parametrize("expression", ["", "* * *", "60 * * * *", "* 25 * * *", "a * * * *", "*/0 * * * *"])
def test_parse_cron_rejects_bad_input(expression):
    with pytest.raises(CronError):
        parse_cron(expression)


def test_cron_matches_specific_time():
    assert cron_matches("30 3 * * *", datetime(2026, 8, 20, 3, 30))
    assert not cron_matches("30 3 * * *", datetime(2026, 8, 20, 3, 31))
    # 2026-08-23 is a Sunday; cron weekday 0.
    assert cron_matches("0 3 * * 0", datetime(2026, 8, 23, 3, 0))


def test_next_run_is_in_the_future():
    upcoming = next_run("0 3 * * *", after=datetime(2026, 8, 20, 4, 0))
    assert upcoming == datetime(2026, 8, 21, 3, 0)


def test_scheduler_fires_due_tasks(isolated_home):
    calls = []
    scheduler = Scheduler()
    scheduler.register("noon", "0 12 * * *", lambda: calls.append(1))

    assert scheduler.tick(datetime(2026, 8, 20, 11, 59)) == []
    assert scheduler.tick(datetime(2026, 8, 20, 12, 0)) == ["noon"]
    # The same minute must not fire twice.
    assert scheduler.tick(datetime(2026, 8, 20, 12, 0)) == []

    for _ in range(50):
        if calls:
            break
        time.sleep(0.05)
    assert calls == [1]


def test_scheduler_skips_disabled_tasks(isolated_home):
    scheduler = Scheduler()
    scheduler.register("off", "* * * * *", lambda: None, enabled=False)
    assert scheduler.tick(datetime(2026, 8, 20, 12, 0)) == []
    scheduler.set_enabled("off", True)
    assert scheduler.tick(datetime(2026, 8, 20, 12, 0)) == ["off"]


def test_scheduler_rejects_bad_cron(isolated_home):
    scheduler = Scheduler()
    with pytest.raises(CronError):
        scheduler.register("bad", "not a cron", lambda: None)


# ----------------------------------------------------------------- updater


def test_signature_update_without_feed(app):
    result = app.check_signature_updates()
    assert result["configured"] is False
    assert result["updates_available"] == 0


def test_signature_update_from_local_feed(app, tmp_path):
    """A file:// feed exercises the whole download-verify-install path."""
    from guardiantus.core.hashing import sha256_file

    set_file = tmp_path / "extra.json"
    set_file.write_text(json.dumps({
        "name": "extra",
        "version": "2026.09.01",
        "patterns": [{"name": "Test.Feed.Marker", "ascii": "FEED-MARKER-XYZ", "severity": "high"}],
    }))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "version": "2026.09.01",
        "sets": [{"name": "extra", "url": set_file.as_uri(), "sha256": sha256_file(set_file)}],
    }))

    app.config.set("updates", "signature_url", manifest.as_uri())
    before = app.signatures.count

    check = app.check_signature_updates()
    assert check["updates_available"] == 1

    result = app.update_signatures()
    assert result["installed"] == 1
    assert app.signatures.count > before

    probe = tmp_path / "probe.txt"
    probe.write_text("harmless text containing FEED-MARKER-XYZ inside")
    assert app.scanner.scan_file(probe).is_threat

    # A second check has nothing left to do.
    assert app.check_signature_updates()["updates_available"] == 0


def test_signature_update_rejects_digest_mismatch(app, tmp_path):
    set_file = tmp_path / "bad.json"
    set_file.write_text(json.dumps({"name": "bad", "patterns": [{"name": "X", "ascii": "Y"}]}))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "sets": [{"name": "bad", "url": set_file.as_uri(), "sha256": "00" * 32}],
    }))
    app.config.set("updates", "signature_url", manifest.as_uri())

    result = app.update_signatures()
    assert result["installed"] == 0
    assert result["failures"]
    assert "digest mismatch" in result["failures"][0]["error"]


def test_signature_updater_rejects_odd_scheme(app):
    app.config.set("updates", "signature_url", "ftp://example.invalid/manifest.json")
    with pytest.raises(UpdateError):
        SignatureUpdater(config=app.config, db=app.db).check()


def test_winget_table_parser():
    output = (
        "Name                Id                   Version      Available    Source\n"
        "-------------------------------------------------------------------------\n"
        "Mozilla Firefox     Mozilla.Firefox      120.0        121.0        winget\n"
        "7-Zip               7zip.7zip            22.01        23.01        winget\n"
    )
    programs = _parse_winget_table(output, "winget")
    assert [p.name for p in programs] == ["Mozilla Firefox", "7-Zip"]
    assert programs[0].package_id == "Mozilla.Firefox"
    assert programs[0].available_version == "121.0"
    assert programs[0].update_available


@pytest.mark.parametrize("package", ["firefox", "Mozilla.Firefox", "python3-pip", "org.gnome.Calc"])
def test_safe_package_ids_accepted(package):
    assert _safe_package_id(package)


@pytest.mark.parametrize("package", ["", "; rm -rf /", "$(whoami)", "a b", "--flag", "`id`"])
def test_unsafe_package_ids_rejected(package):
    assert not _safe_package_id(package)


def test_program_upgrade_rejects_unknown_manager(app):
    result = app.upgrade_program("definitely-not-a-manager", "firefox")
    assert result["ok"] is False


def test_program_check_reports_managers(app):
    report = app.check_programs()
    assert "programs" in report
    assert isinstance(report["updates_available"], int)


# --------------------------------------------------------------- api layer


def test_route_resolution():
    handler, params = api.resolve("GET", "/api/scans/abc123")
    assert handler is not None
    assert params == {"scan_id": "abc123"}


def test_unknown_route_resolves_to_nothing():
    handler, _ = api.resolve("GET", "/api/nope")
    assert handler is None


def test_wrong_method_yields_405(app):
    handler, _ = api.resolve("PATCH", "/api/status")
    status, payload = handler(app, api.Request(method="PATCH", path="/api/status"))
    assert status == 405
    assert "allowed" in payload


def test_status_handler(app):
    status, payload = api.get_status(app, api.Request(method="GET", path="/api/status"))
    assert status == 200
    assert payload["protection"]["state"] in ("protected", "attention", "at_risk")
    assert payload["system"]["app"] == "Guardiantus AV"


# ------------------------------------------------- acting on a detection


def _reported_detection(app, tmp_path):
    """Scan a heuristic-only threat and return the detection it reported."""
    target = tmp_path / "READ_ME.txt"
    target.write_text(
        "All your files are encrypted. Send bitcoin to our wallet.\n"
        "Your decryption key is safe with us.\n"
    )
    app.start_scan("custom", targets=[str(tmp_path)], auto_quarantine=True).join(timeout=60)
    reported = [d for d in app.detections() if d["handled"] == "reported"]
    assert reported, "a suspicion should be reported rather than moved"
    return target, reported[0]


def _act(app, detection_id, action):
    return api.act_on_detection(
        app,
        api.Request(
            method="POST",
            path="",
            params={"detection_id": str(detection_id), "action": action},
        ),
    )


def test_a_reported_detection_can_be_quarantined_after_the_fact(app, tmp_path):
    target, detection = _reported_detection(app, tmp_path)
    assert target.exists()

    status, payload = _act(app, detection["id"], "quarantine")
    assert status == 200 and payload["quarantined"]
    assert not target.exists()
    assert len(app.quarantine.list_entries()) == 1


def test_a_reported_detection_can_be_allowed(app, tmp_path):
    target, detection = _reported_detection(app, tmp_path)

    status, payload = _act(app, detection["id"], "allow")
    assert status == 200 and payload["allowed"]
    assert target.exists()

    job = app.start_scan("custom", targets=[str(tmp_path)])
    job.join(timeout=60)
    assert job.progress.threats_found == 0, "an allowed file must stop being flagged"


def test_the_dashboard_asks_about_files_left_in_place(app, tmp_path):
    """Reporting instead of quarantining only works if the user is told."""
    before = {issue["id"] for issue in app.protection_status()["issues"]}
    assert "detections-unresolved" not in before

    _, detection = _reported_detection(app, tmp_path)
    issues = {i["id"]: i for i in app.protection_status()["issues"]}
    assert "detections-unresolved" in issues
    assert issues["detections-unresolved"]["action"] == "review_detections"

    _act(app, detection["id"], "allow")
    after = {issue["id"] for issue in app.protection_status()["issues"]}
    assert "detections-unresolved" not in after, "deciding must clear the prompt"


def test_quarantining_an_allowed_file_keeps_its_name(app, tmp_path):
    """The allow-list short-circuits the re-scan, so the name has to survive."""
    _, detection = _reported_detection(app, tmp_path)
    _act(app, detection["id"], "allow")
    app.db.mark_detection_handled(detection["id"], "reported")

    _act(app, detection["id"], "quarantine")
    entry = app.quarantine.list_entries()[0]
    assert entry["threat_name"] == detection["threat_name"]
    assert entry["threat_name"] != "Unknown"


def test_acting_on_a_detection_reports_real_problems(app, tmp_path):
    _, detection = _reported_detection(app, tmp_path)

    assert _act(app, 999_999, "allow")[0] == 404
    assert _act(app, detection["id"], "frobnicate")[0] == 400
    assert _act(app, "not-a-number", "allow")[0] == 400


def test_allowlist_names_the_file_and_can_be_revoked(app, tmp_path):
    target, detection = _reported_detection(app, tmp_path)
    _act(app, detection["id"], "allow")

    status, payload = api.get_allowlist(app, api.Request(method="GET", path="/api/allowlist"))
    assert status == 200
    entry = payload["entries"][0]
    assert entry["path"] == str(target), "the allow-list must name the file, not just a digest"

    status, _ = api.delete_allowlist_entry(
        app, api.Request(method="DELETE", path="", params={"sha256": entry["sha256"]}),
    )
    assert status == 200
    assert api.get_allowlist(app, api.Request(method="GET", path=""))[1]["entries"] == []

    job = app.start_scan("custom", targets=[str(tmp_path)])
    job.join(timeout=60)
    assert job.progress.threats_found == 1, "revoking must put the file back in scope"


def test_revoking_something_not_allowed_is_a_404(app):
    status, _ = api.delete_allowlist_entry(
        app, api.Request(method="DELETE", path="", params={"sha256": "0" * 64}),
    )
    assert status == 404


def test_detection_action_route_resolves():
    handler, params = api.resolve("POST", "/api/detections/12/quarantine")
    assert handler is api.act_on_detection
    assert params == {"detection_id": "12", "action": "quarantine"}


def test_scan_handler_rejects_bad_type(app):
    status, payload = api.post_scan(
        app, api.Request(method="POST", path="/api/scans", body={"type": "telepathic"})
    )
    assert status == 400
    assert "error" in payload


def test_scan_handler_rejects_missing_target(app):
    status, _ = api.post_scan(
        app, api.Request(method="POST", path="/api/scans", body={"type": "custom", "targets": ["/nope/x"]})
    )
    assert status == 404


def test_config_handler_round_trip(app):
    status, payload = api.put_config(
        app, api.Request(method="PUT", path="/api/config", body={"scanning": {"worker_threads": 3}})
    )
    assert status == 200
    assert payload["scanning"]["worker_threads"] == 3


# ------------------------------------------------------------ http server


@pytest.fixture
def server(app):
    instance = DashboardServer(app=app, host="127.0.0.1", port=0)
    instance.start(open_browser=False)
    yield instance
    instance.stop()


def _request(server, path, method="GET", body=None, token=True, headers=None):
    url = server.url.rstrip("/") + path
    request = urllib.request.Request(url, method=method)
    if token:
        request.add_header("X-Guardiantus-Token", server.token)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    if body is not None:
        request.data = json.dumps(body).encode()
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def test_dashboard_serves_index(server):
    status, body = _request(server, "/", token=False)
    assert status == 200
    assert b"Guardiantus" in body
    assert server.token.encode() in body


def test_static_assets_are_served(server):
    for path in ("/static/css/app.css", "/static/js/app.js", "/static/img/logo.svg"):
        status, body = _request(server, path, token=False)
        assert status == 200, path
        assert body


def test_api_requires_a_token(server):
    assert _request(server, "/api/status", token=False)[0] == 401


def test_api_rejects_a_wrong_token(server):
    status, _ = _request(
        server, "/api/status", token=False, headers={"X-Guardiantus-Token": "not-the-token"}
    )
    assert status == 401


def test_api_accepts_token_in_query(server):
    url = f"/api/health?token={server.token}"
    assert _request(server, url, token=False)[0] == 200


def test_cross_origin_requests_are_rejected(server):
    status, _ = _request(server, "/api/status", headers={"Origin": "http://evil.example"})
    assert status == 403


def test_dns_rebinding_host_is_rejected(server):
    status, _ = _request(server, "/api/status", headers={"Host": "attacker.example"})
    assert status == 403


def test_static_path_traversal_is_blocked():
    assert _safe_static_path("../../../etc/passwd") is None
    assert _safe_static_path("css/app.css") is not None


def test_malformed_json_body_is_rejected(server):
    url = server.url.rstrip("/") + "/api/config"
    request = urllib.request.Request(url, method="PUT", data=b"{not json")
    request.add_header("X-Guardiantus-Token", server.token)
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            code = response.status
    except urllib.error.HTTPError as error:
        code = error.code
    assert code == 400


def test_full_scan_round_trip_over_http(server, samples):
    status, body = _request(
        server, "/api/scans", method="POST", body={"type": "custom", "targets": [str(samples)]}
    )
    assert status == 202
    scan_id = json.loads(body)["scan_id"]

    progress = {}
    for _ in range(80):
        _, body = _request(server, f"/api/scans/{scan_id}")
        progress = json.loads(body)
        if progress["state"] != "running":
            break
        time.sleep(0.25)

    assert progress["state"] == "completed"
    assert progress["threats_found"] >= 4

    _, body = _request(server, "/api/detections?limit=50")
    assert json.loads(body)["detections"]


def test_security_headers_are_present(server):
    url = server.url
    request = urllib.request.Request(url)
    with urllib.request.urlopen(request, timeout=10) as response:
        headers = dict(response.headers)
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in headers["Content-Security-Policy"]


# ------------------------------------------------------------------- cli


def test_cli_check_reports_threats(samples, capsys):
    from guardiantus.cli import main

    assert main(["check", str(samples / "eicar.com")]) == 1
    assert "EICAR" in capsys.readouterr().out


def test_cli_check_clean_file(samples, capsys):
    from guardiantus.cli import main

    assert main(["check", str(samples / "clean.txt")]) == 0


def test_cli_json_output(samples, capsys):
    from guardiantus.cli import main

    main(["--json", "check", str(samples / "eicar.com")])
    payload = json.loads(capsys.readouterr().out)
    assert payload["results"][0]["verdict"] == "malicious"


def test_cli_scan_command(samples, capsys):
    from guardiantus.cli import main

    assert main(["--json", "scan", str(samples)]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["state"] == "completed"
    assert payload["threats_found"] >= 4


def test_cli_can_settle_a_reported_detection(tmp_path, capsys):
    """The terminal has to reach the same decisions the dashboard offers."""
    from guardiantus.cli import main

    (tmp_path / "READ_ME.txt").write_text(
        "All your files are encrypted. Send bitcoin to our wallet.\n"
        "Your decryption key is safe with us.\n"
    )
    main(["--json", "scan", str(tmp_path), "--quarantine"])
    capsys.readouterr()

    assert main(["--json", "detections"]) == 0
    reported = [
        d for d in json.loads(capsys.readouterr().out)["detections"]
        if d["handled"] == "reported"
    ]
    assert reported, "a suspicion should be reported rather than moved"

    assert main(["--json", "detections", "allow", str(reported[0]["id"])]) == 0
    assert json.loads(capsys.readouterr().out)["allowed"]

    assert main(["--json", "allow", "list"]) == 0
    assert json.loads(capsys.readouterr().out)["entries"], "allowing must show up on the list"

    assert main(["--json", "scan", str(tmp_path)]) == 0, "an allowed file must not be flagged"
    capsys.readouterr()


def test_cli_rejects_an_unknown_detection(capsys):
    from guardiantus.cli import main

    assert main(["detections", "quarantine", "999999"]) == 2
    assert "unknown detection" in capsys.readouterr().err


def test_cli_status_and_info(capsys):
    from guardiantus.cli import main

    assert main(["status"]) == 0
    assert main(["info"]) == 0
    assert "Guardiantus" in capsys.readouterr().out


def test_cli_config_set(capsys):
    from guardiantus.cli import main
    from guardiantus.config import get_config

    assert main(["config", "set", "scanning.worker_threads", "6"]) == 0
    assert get_config().get("scanning", "worker_threads") == 6


def test_cli_rejects_unknown_path(capsys):
    from guardiantus.cli import main

    assert main(["check", "/definitely/not/here.bin"]) == 2


# -------------------------------------------------------- packaging/paths


def test_package_root_normal_install():
    from guardiantus import paths

    assert pathlib.Path(paths.__file__).resolve().parent == paths.PACKAGE_ROOT


def test_package_root_under_pyinstaller(monkeypatch, tmp_path):
    """PyInstaller loads modules from an archive, so __file__ is unusable;
    bundled data must instead be found next to the frozen executable."""
    import importlib
    import sys

    from guardiantus import paths

    fake_exe = tmp_path / "guardiantus.exe"
    fake_exe.touch()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    monkeypatch.setattr(sys, "executable", str(fake_exe))
    try:
        importlib.reload(paths)
        assert tmp_path / "guardiantus" == paths.PACKAGE_ROOT
        assert tmp_path / "guardiantus" / "data" / "signatures" == paths.BUNDLED_SIGNATURES
    finally:
        importlib.reload(paths)  # restore the un-frozen state for later tests
