"""Command line interface.

    guardiantus scan ~/Downloads --quarantine
    guardiantus quick
    guardiantus protect start
    guardiantus quarantine list
    guardiantus update signatures
    guardiantus update programs --apply apt:firefox
    guardiantus dashboard
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .application import Application, get_app
from .core.models import ScanState, Severity, Verdict
from .core.quarantine import QuarantineError
from .core.scanner import FileScanner

# ---------------------------------------------------------------- formatting

_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "white": "\033[97m",
    "grey": "\033[90m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
}

_SEVERITY_COLOUR = {
    Severity.INFO: "grey",
    Severity.LOW: "white",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "red",
}


def _colour_enabled(stream: Any = None) -> bool:
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)()) and sys.platform != "emscripten"


def paint(text: str, *styles: str) -> str:
    if not _colour_enabled():
        return text
    prefix = "".join(_ANSI.get(style, "") for style in styles)
    return f"{prefix}{text}{_ANSI['reset']}" if prefix else text


def banner() -> str:
    shield = paint("[ G A ]", "bold", "white")
    return f"{shield} {paint('Guardiantus AV', 'bold')} {paint(f'v{__version__}', 'grey')}"


def human_bytes(count: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(count) < 1024 or unit == "TB":
            return f"{count:.0f} {unit}" if unit == "B" else f"{count:.1f} {unit}"
        count /= 1024
    return f"{count:.1f} TB"


def human_time(timestamp: Optional[float]) -> str:
    if not timestamp:
        return "never"
    return datetime.fromtimestamp(float(timestamp)).strftime("%Y-%m-%d %H:%M")


def _emit(payload: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, default=str))


# -------------------------------------------------------------------- output


def _print_result_line(result_dict: Dict[str, Any]) -> None:
    severity = Severity(result_dict.get("severity", "medium"))
    marker = paint("THREAT", _SEVERITY_COLOUR[severity], "bold")
    name = result_dict.get("name") or "Unknown"
    print(f"  {marker}  {name}")
    print(f"          {paint(result_dict['path'], 'white')}")
    for detection in result_dict.get("detections", [])[:4]:
        print(
            f"          {paint('·', 'grey')} [{detection['source']}] "
            f"{paint(detection['description'][:96], 'grey')}"
        )
    if result_dict.get("quarantined"):
        print(f"          {paint('→ quarantined', 'green')}")


def _print_progress(progress: Dict[str, Any], final: bool = False) -> None:
    if not _colour_enabled() and not final:
        return
    percent = progress.get("percent", 0.0)
    width = 28
    filled = int(width * percent / 100)
    bar = "█" * filled + "░" * (width - filled)
    line = (
        f"\r  {paint(bar, 'white')} {percent:5.1f}%  "
        f"{progress['files_scanned']:>7} files  "
        f"{progress['threats_found']} threat(s)"
    )
    sys.stdout.write(line[:160])
    sys.stdout.flush()
    if final:
        sys.stdout.write("\n")


def _run_scan_blocking(
    app: Application,
    scan_type: str,
    targets: Optional[Sequence[str]],
    quarantine: Optional[bool],
    as_json: bool,
) -> int:
    try:
        job = app.start_scan(scan_type, targets=targets, auto_quarantine=quarantine)
    except (ValueError, FileNotFoundError) as exc:
        print(paint(f"error: {exc}", "red"), file=sys.stderr)
        return 2

    if not as_json:
        print(banner())
        print(f"  {paint('Scan', 'bold')}  {scan_type} · {', '.join(job.progress.targets)}")
        print(f"  {paint('ID', 'grey')}    {job.scan_id}\n")

    seen_threats = 0
    try:
        while job.is_running:
            if not as_json:
                _print_progress(job.progress.to_dict())
                if len(job.threats) > seen_threats:
                    sys.stdout.write("\r" + " " * 100 + "\r")
                    for threat in job.threats[seen_threats:]:
                        _print_result_line(threat.to_dict())
                    seen_threats = len(job.threats)
            time.sleep(0.2)
    except KeyboardInterrupt:
        job.cancel()
        print(paint("\n  cancelled", "yellow"))
    job.join(timeout=30)

    summary = job.summary()
    if as_json:
        _emit(summary, True)
        return 1 if summary["threats_found"] else 0

    _print_progress(summary, final=True)
    for threat in job.threats[seen_threats:]:
        _print_result_line(threat.to_dict())

    print()
    state = summary["state"]
    tone = "green" if state == ScanState.COMPLETED.value and not summary["threats_found"] else "yellow"
    print(f"  {paint('Result', 'bold')}       {paint(summary['message'], tone)}")
    print(f"  {paint('Files', 'grey')}        {summary['files_scanned']} scanned, "
          f"{summary['files_skipped']} skipped, {summary['errors']} error(s)")
    print(f"  {paint('Data', 'grey')}         {human_bytes(summary['bytes_scanned'])}")
    print(f"  {paint('Duration', 'grey')}     {summary['elapsed']:.1f}s")
    return 1 if summary["threats_found"] else 0


# ------------------------------------------------------------------ commands


def cmd_scan(app: Application, args: argparse.Namespace) -> int:
    quarantine = True if args.quarantine else (False if args.no_quarantine else None)
    return _run_scan_blocking(app, "custom", args.paths, quarantine, args.json)


def cmd_quick(app: Application, args: argparse.Namespace) -> int:
    quarantine = True if args.quarantine else (False if args.no_quarantine else None)
    return _run_scan_blocking(app, "quick", None, quarantine, args.json)


def cmd_full(app: Application, args: argparse.Namespace) -> int:
    quarantine = True if args.quarantine else (False if args.no_quarantine else None)
    return _run_scan_blocking(app, "full", None, quarantine, args.json)


def cmd_check(app: Application, args: argparse.Namespace) -> int:
    """Scan single files without recording a scan session."""
    scanner = FileScanner(config=app.config)
    results: List[Dict[str, Any]] = []
    exit_code = 0
    for raw in args.paths:
        path = Path(raw).expanduser()
        if not path.is_file():
            print(paint(f"error: not a file: {raw}", "red"), file=sys.stderr)
            exit_code = max(exit_code, 2)
            continue
        result = scanner.scan_file(path)
        results.append(result.to_dict())
        if result.is_threat:
            exit_code = max(exit_code, 1)
            if not args.json:
                _print_result_line(result.to_dict())
        elif not args.json:
            verdict = result.verdict
            tone = "green" if verdict is Verdict.CLEAN else "grey"
            print(f"  {paint(verdict.value.upper(), tone)}  {path}")
    _emit({"results": results}, args.json)
    return exit_code


def cmd_status(app: Application, args: argparse.Namespace) -> int:
    status = app.protection_status()
    stats = app.stats()
    system = app.system_info()
    if args.json:
        _emit({"protection": status, "stats": stats, "system": system}, True)
        return 0

    tone = {"protected": "green", "attention": "yellow", "at_risk": "red"}[status["state"]]
    print(banner())
    print(f"\n  {paint(status['headline'].upper(), tone, 'bold')}\n")

    realtime = status["realtime"]
    realtime_state = paint("ON", "green") if realtime["running"] else paint("OFF", "red")
    backend_note = paint(f"({realtime['backend']})", "grey") if realtime["running"] else ""
    print(f"  {paint('Real-time', 'grey'):<24} {realtime_state} {backend_note}")
    signatures = status["signatures"]
    print(f"  {paint('Signatures', 'grey'):<24} {signatures['total']} loaded "
          f"{paint('· v' + str(signatures.get('version', '?')), 'grey')}")
    print(f"  {paint('YARA rules', 'grey'):<24} {system['engine']['yara']['rule_count']} "
          f"{paint('(' + system['engine']['yara']['backend'] + ')', 'grey')}")
    print(f"  {paint('Quarantine', 'grey'):<24} {status['quarantine']['count']} item(s)")
    last = status.get("last_scan")
    print(f"  {paint('Last scan', 'grey'):<24} "
          f"{human_time(last['finished_at']) if last else 'never'}")
    print(f"  {paint('Detections (7d)', 'grey'):<24} {stats['detections_7d']}")

    if status["issues"]:
        print(f"\n  {paint('Recommended actions', 'bold')}")
        for issue in status["issues"]:
            colour = {"high": "red", "medium": "yellow", "low": "grey"}[issue["severity"]]
            print(f"    {paint('•', colour)} {issue['title']}")
    print()
    return 0


def cmd_protect(app: Application, args: argparse.Namespace) -> int:
    if args.action == "status":
        status = app.realtime.status()
        _emit(status, args.json)
        if not args.json:
            print(f"  Real-time protection: "
                  f"{paint('running', 'green') if status['running'] else paint('stopped', 'red')}")
            print(f"  Backend             : {status['backend']}")
            print(f"  Watching            : {len(status['watch_paths'])} path(s)")
            for path in status["watch_paths"]:
                print(f"    {paint('·', 'grey')} {path}")
            print(f"  Events handled      : {status['events_handled']}")
            print(f"  Threats blocked     : {status['threats_blocked']}")
        return 0

    if args.action == "start":
        try:
            status = app.enable_realtime()
        except RuntimeError as exc:
            print(paint(f"error: {exc}", "red"), file=sys.stderr)
            return 2
        _emit(status, args.json)
        if not args.json:
            print(paint(f"  Real-time protection started ({status['backend']})", "green"))
            for path in status["watch_paths"]:
                print(f"    {paint('·', 'grey')} {path}")
            if not status["watchdog_available"]:
                print(paint("    note: install 'watchdog' for instant, event-driven detection", "grey"))
        if args.foreground:
            print(paint("  Watching… press Ctrl+C to stop.", "grey"))
            try:
                while app.realtime.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                app.disable_realtime()
                print(paint("\n  stopped", "yellow"))
        return 0

    status = app.disable_realtime()
    _emit(status, args.json)
    if not args.json:
        print(paint("  Real-time protection stopped", "yellow"))
    return 0


def cmd_quarantine(app: Application, args: argparse.Namespace) -> int:
    if args.action == "list":
        entries = app.quarantine.list_entries(include_inactive=args.all)
        _emit({"entries": entries}, args.json)
        if args.json:
            return 0
        if not entries:
            print(paint("  Quarantine is empty.", "grey"))
            return 0
        print(f"  {paint('ID', 'grey'):<14} {paint('THREAT', 'grey'):<32} "
              f"{paint('SIZE', 'grey'):>9}  {paint('WHEN', 'grey')}")
        for entry in entries:
            print(f"  {entry['entry_id'][:12]:<14} {entry['threat_name'][:30]:<32} "
                  f"{human_bytes(entry['size']):>9}  {human_time(entry['quarantined_at'])}")
            print(f"  {'':<14} {paint(entry['original_path'], 'grey')}")
        return 0

    if args.action == "empty":
        removed = app.quarantine.empty()
        _emit({"deleted": removed}, args.json)
        if not args.json:
            print(paint(f"  Deleted {removed} quarantined item(s).", "yellow"))
        return 0

    if not args.entry_id:
        print(paint(f"error: '{args.action}' needs an entry id", "red"), file=sys.stderr)
        return 2

    entry_id = _resolve_entry_id(app, args.entry_id)
    if entry_id is None:
        print(paint(f"error: no quarantine entry matching {args.entry_id!r}", "red"), file=sys.stderr)
        return 2

    try:
        if args.action == "restore":
            target = app.quarantine.restore(entry_id)
            _emit({"restored": str(target)}, args.json)
            if not args.json:
                print(paint(f"  Restored to {target}", "green"))
                print(paint("  This file will not be flagged again.", "grey"))
        else:
            app.quarantine.delete(entry_id)
            _emit({"deleted": entry_id}, args.json)
            if not args.json:
                print(paint(f"  Deleted {entry_id}", "yellow"))
    except QuarantineError as exc:
        print(paint(f"error: {exc}", "red"), file=sys.stderr)
        return 2
    return 0


def cmd_allow(app: Application, args: argparse.Namespace) -> int:
    """Show or clear the digests that scans skip."""
    entries = app.allowlist()

    if args.action == "list":
        _emit({"entries": entries}, args.json)
        if args.json:
            return 0
        if not entries:
            print(paint("  Nothing is allowed. Restoring a file adds it here.", "grey"))
            return 0
        print(f"  {'SHA-256':<18}  {'LAST SEEN':<12}  FILE")
        for entry in entries:
            seen = human_time(entry["last_seen"]) if entry["last_seen"] else "—"
            print(f"  {entry['sha256'][:16]}…  {seen:<12}  {entry['path'] or '(unknown)'}")
        return 0

    if not args.sha256:
        print(paint("error: a SHA-256 is required", "red"), file=sys.stderr)
        return 2
    # Accept the abbreviated digest the list prints.
    matches = [e["sha256"] for e in entries if e["sha256"].startswith(args.sha256.lower())]
    if len(matches) != 1:
        problem = "no allow-list entry matching" if not matches else "ambiguous prefix"
        print(paint(f"error: {problem} {args.sha256!r}", "red"), file=sys.stderr)
        return 2

    app.revoke_allowed(matches[0])
    _emit({"removed": matches[0]}, args.json)
    if not args.json:
        print(paint(f"  {matches[0][:16]}… will be checked again.", "yellow"))
    return 0


def _resolve_entry_id(app: Application, prefix: str) -> Optional[str]:
    matches = [
        entry["entry_id"]
        for entry in app.quarantine.list_entries(include_inactive=True)
        if entry["entry_id"].startswith(prefix)
    ]
    return matches[0] if len(matches) == 1 else None


def cmd_update(app: Application, args: argparse.Namespace) -> int:
    if args.target == "signatures":
        result = (
            app.check_signature_updates() if args.check else app.update_signatures(force=args.force)
        )
        _emit(result, args.json)
        if not args.json:
            print(f"  {result.get('message', 'done')}")
            status = app.signature_updater.status()
            print(f"  {paint('Active signatures', 'grey')}: {status['total']}")
        return 0

    # target == programs
    if args.apply:
        results = []
        exit_code = 0
        for spec in args.apply:
            manager, _, package = spec.partition(":")
            if not package:
                print(paint(f"error: expected manager:package, got {spec!r}", "red"), file=sys.stderr)
                exit_code = 2
                continue
            outcome = app.upgrade_program(manager, package)
            results.append(outcome)
            if not args.json:
                tone = "green" if outcome.get("ok") else "red"
                print(f"  {paint('✓' if outcome.get('ok') else '✗', tone)} {spec} "
                      f"{paint(outcome.get('error', ''), 'grey')}")
            if not outcome.get("ok"):
                exit_code = max(exit_code, 1)
        _emit({"results": results}, args.json)
        return exit_code

    report = app.check_programs(use_cache=False)
    _emit(report, args.json)
    if args.json:
        return 0

    programs = report["programs"]
    if not programs:
        print(paint("  All programs are up to date.", "green"))
    else:
        print(f"  {paint(str(len(programs)) + ' update(s) available', 'yellow', 'bold')}\n")
        print(f"  {paint('MANAGER', 'grey'):<12} {paint('PACKAGE', 'grey'):<32} "
              f"{paint('INSTALLED', 'grey'):<18} {paint('AVAILABLE', 'grey')}")
        for program in programs:
            print(f"  {program['manager']:<12} {program['name'][:30]:<32} "
                  f"{(program['current_version'] or '—')[:16]:<18} "
                  f"{paint(program['available_version'][:20], 'white')}")
        print(f"\n  {paint('Apply with', 'grey')}: guardiantus update programs "
              f"--apply {programs[0]['manager']}:{programs[0]['package_id']}")
    for error in report.get("errors", []):
        print(paint(f"  ! {error['manager']}: {error['error']}", "grey"))
    return 0


def cmd_schedule(app: Application, args: argparse.Namespace) -> int:
    app._register_tasks()
    if args.action == "list":
        tasks = app.scheduler.tasks()
        _emit({"tasks": tasks}, args.json)
        if not args.json:
            print(f"  {paint('TASK', 'grey'):<24} {paint('CRON', 'grey'):<16} "
                  f"{paint('ON', 'grey'):<5} {paint('NEXT RUN', 'grey')}")
            for task in tasks:
                print(f"  {task['name']:<24} {task['cron']:<16} "
                      f"{('yes' if task['enabled'] else 'no'):<5} "
                      f"{human_time(task['next_run'])}")
        return 0

    if args.action == "run":
        if not args.name or not app.scheduler.run_now(args.name):
            print(paint(f"error: unknown task {args.name!r}", "red"), file=sys.stderr)
            return 2
        print(paint(f"  Started '{args.name}'", "green"))
        return 0

    enabled = args.action == "enable"
    if not args.name or not app.scheduler.set_enabled(args.name, enabled):
        print(paint(f"error: unknown task {args.name!r}", "red"), file=sys.stderr)
        return 2
    section_key = {"quick-scan": "quick_scan_enabled", "full-scan": "full_scan_enabled"}.get(args.name)
    if section_key:
        app.config.set("schedule", section_key, enabled)
    print(paint(f"  Task '{args.name}' {'enabled' if enabled else 'disabled'}", "green"))
    return 0


def cmd_events(app: Application, args: argparse.Namespace) -> int:
    events = app.events(limit=args.limit, category=args.category or "")
    _emit({"events": events}, args.json)
    if args.json:
        return 0
    tone = {"error": "red", "warning": "yellow", "info": "grey"}
    for event in reversed(events):
        stamp = datetime.fromtimestamp(event["ts"]).strftime("%m-%d %H:%M:%S")
        print(f"  {paint(stamp, 'grey')} "
              f"{paint(event['level'].upper()[:4], tone.get(event['level'], 'grey')):<4} "
              f"{paint(event['category'], 'grey'):<12} {event['message']}")
    return 0


def cmd_config(app: Application, args: argparse.Namespace) -> int:
    if args.action == "show":
        print(json.dumps(app.config.data, indent=2, sort_keys=True))
        return 0
    if args.action == "path":
        print(app.config.path)
        return 0

    if not args.key or args.value is None:
        print(paint("error: set needs SECTION.KEY VALUE", "red"), file=sys.stderr)
        return 2
    section, _, key = args.key.partition(".")
    if not key:
        print(paint("error: key must look like section.key", "red"), file=sys.stderr)
        return 2
    try:
        value: Any = json.loads(args.value)
    except json.JSONDecodeError:
        value = args.value
    app.update_config({section: {key: value}})
    print(f"  {section}.{key} = {json.dumps(value)}")
    return 0


def cmd_dashboard(app: Application, args: argparse.Namespace) -> int:
    from .service.server import serve

    host = args.host or str(app.config.get("service", "host", "127.0.0.1"))
    port = args.port or int(app.config.get("service", "port", 8787))
    open_browser = not args.no_browser and bool(app.config.get("service", "open_browser", True))
    serve(host=host, port=port, open_browser=open_browser, app=app)
    return 0


def cmd_info(app: Application, args: argparse.Namespace) -> int:
    system = app.system_info()
    _emit(system, args.json)
    if args.json:
        return 0
    print(banner())
    print(f"\n  {paint('Platform', 'grey'):<20} {system['platform']}")
    print(f"  {paint('Python', 'grey'):<20} {system['python']}")
    print(f"  {paint('Data directory', 'grey'):<20} {system['data_dir']}")
    engine = system["engine"]
    print(f"  {paint('Signature sets', 'grey'):<20} {len(engine['signatures']['sets'])}")
    for signature_set in engine["signatures"]["sets"]:
        print(f"    {paint('·', 'grey')} {signature_set['name']} "
              f"({signature_set['hashes']} hashes, {signature_set['patterns']} patterns)")
    print(f"  {paint('YARA backend', 'grey'):<20} {engine['yara']['backend']} "
          f"({engine['yara']['rule_count']} rules)")
    return 0


# ------------------------------------------------------------------- parsing


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardiantus",
        description="Guardiantus AV — real-time protection, scanning and update management.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  guardiantus status\n"
            "  guardiantus quick --quarantine\n"
            "  guardiantus scan ~/Downloads ~/Desktop\n"
            "  guardiantus protect start\n"
            "  guardiantus update programs\n"
            "  guardiantus dashboard\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"Guardiantus AV {__version__}")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--home", metavar="DIR", help="override the data directory")

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    def add_scan_flags(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--quarantine", action="store_true", help="move detected threats to quarantine")
        sp.add_argument("--no-quarantine", action="store_true", help="report only, never move files")

    scan = sub.add_parser("scan", help="scan specific files or directories")
    scan.add_argument("paths", nargs="+", metavar="PATH")
    add_scan_flags(scan)
    scan.set_defaults(func=cmd_scan)

    quick = sub.add_parser("quick", help="scan high-risk locations")
    add_scan_flags(quick)
    quick.set_defaults(func=cmd_quick)

    full = sub.add_parser("full", help="scan the whole system")
    add_scan_flags(full)
    full.set_defaults(func=cmd_full)

    check = sub.add_parser("check", help="inspect individual files, no session recorded")
    check.add_argument("paths", nargs="+", metavar="FILE")
    check.set_defaults(func=cmd_check)

    status = sub.add_parser("status", help="show protection status")
    status.set_defaults(func=cmd_status)

    protect = sub.add_parser("protect", help="control real-time protection")
    protect.add_argument("action", choices=["start", "stop", "status"])
    protect.add_argument("--foreground", action="store_true", help="keep running in the terminal")
    protect.set_defaults(func=cmd_protect)

    quarantine = sub.add_parser("quarantine", help="inspect and manage the quarantine vault")
    quarantine.add_argument("action", choices=["list", "restore", "delete", "empty"])
    quarantine.add_argument("entry_id", nargs="?", metavar="ID")
    quarantine.add_argument("--all", action="store_true", help="include restored/deleted entries")
    quarantine.set_defaults(func=cmd_quarantine)

    allow = sub.add_parser("allow", help="manage files you have vouched for")
    allow.add_argument("action", choices=["list", "remove"])
    allow.add_argument("sha256", nargs="?", metavar="SHA256")
    allow.set_defaults(func=cmd_allow)

    update = sub.add_parser("update", help="update signatures or installed programs")
    update.add_argument("target", choices=["signatures", "programs"])
    update.add_argument("--check", action="store_true", help="only report what is available")
    update.add_argument("--force", action="store_true", help="reinstall every signature set")
    update.add_argument(
        "--apply",
        nargs="+",
        metavar="MANAGER:PACKAGE",
        help="upgrade the given packages, e.g. apt:firefox",
    )
    update.set_defaults(func=cmd_update)

    schedule = sub.add_parser("schedule", help="manage scheduled tasks")
    schedule.add_argument("action", choices=["list", "enable", "disable", "run"])
    schedule.add_argument("name", nargs="?", metavar="TASK")
    schedule.set_defaults(func=cmd_schedule)

    events = sub.add_parser("events", help="show the event log")
    events.add_argument("--limit", type=int, default=40)
    events.add_argument("--category", help="scan | detection | realtime | update | quarantine | scheduler")
    events.set_defaults(func=cmd_events)

    config = sub.add_parser("config", help="read and write configuration")
    config.add_argument("action", choices=["show", "set", "path"])
    config.add_argument("key", nargs="?", metavar="SECTION.KEY")
    config.add_argument("value", nargs="?", metavar="VALUE")
    config.set_defaults(func=cmd_config)

    dashboard = sub.add_parser("dashboard", help="run the local web dashboard")
    dashboard.add_argument("--host")
    dashboard.add_argument("--port", type=int)
    dashboard.add_argument("--no-browser", action="store_true")
    dashboard.set_defaults(func=cmd_dashboard)

    info = sub.add_parser("info", help="show engine and platform details")
    info.set_defaults(func=cmd_info)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.home:
        import os

        os.environ["GUARDIANTUS_HOME"] = str(Path(args.home).expanduser())

    if not getattr(args, "func", None):
        parser.print_help()
        return 0

    app = get_app()
    try:
        return int(args.func(app, args))
    except KeyboardInterrupt:
        print(paint("\ninterrupted", "yellow"), file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover - top-level safety net
        print(paint(f"error: {exc}", "red"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
