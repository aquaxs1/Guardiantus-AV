"""JSON API for the dashboard.

Handlers are plain functions of ``(app, request) -> (status, payload)`` so
they are trivially unit-testable without an HTTP server in the loop.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..application import Application
from ..core.quarantine import QuarantineError
from ..core.scheduler import CronError

Payload = Dict[str, Any]
Response = Tuple[int, Payload]


@dataclass
class Request:
    """Everything a handler needs about an inbound call."""

    method: str
    path: str
    query: Dict[str, List[str]] = field(default_factory=dict)
    body: Payload = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)

    def q(self, name: str, default: str = "") -> str:
        values = self.query.get(name)
        return values[0] if values else default

    def qint(self, name: str, default: int) -> int:
        try:
            return int(self.q(name, str(default)))
        except ValueError:
            return default

    def qbool(self, name: str, default: bool = False) -> bool:
        raw = self.q(name, "").lower()
        if raw in ("1", "true", "yes", "on"):
            return True
        if raw in ("0", "false", "no", "off"):
            return False
        return default


Handler = Callable[[Application, Request], Response]

_ROUTES: List[Tuple[str, str, Handler]] = []


def route(method: str, path: str) -> Callable[[Handler], Handler]:
    """Register ``path`` (supporting ``{name}`` placeholders) for ``method``."""

    def decorator(handler: Handler) -> Handler:
        _ROUTES.append((method.upper(), path, handler))
        return handler

    return decorator


def resolve(method: str, path: str) -> Tuple[Optional[Handler], Dict[str, str]]:
    """Find the handler for a request, extracting any path parameters."""
    path = path.rstrip("/") or "/"
    request_parts = [p for p in path.split("/") if p]
    allowed_methods: List[str] = []

    for route_method, route_path, handler in _ROUTES:
        route_parts = [p for p in route_path.split("/") if p]
        if len(route_parts) != len(request_parts):
            continue
        params: Dict[str, str] = {}
        for expected, actual in zip(route_parts, request_parts):
            if expected.startswith("{") and expected.endswith("}"):
                params[expected[1:-1]] = actual
            elif expected != actual:
                break
        else:
            if route_method == method.upper():
                return handler, params
            allowed_methods.append(route_method)
    if allowed_methods:
        return _method_not_allowed(allowed_methods), {}
    return None, {}


def _method_not_allowed(allowed: List[str]) -> Handler:
    def handler(_app: Application, _request: Request) -> Response:
        return 405, {"error": "method not allowed", "allowed": sorted(set(allowed))}

    return handler


# --------------------------------------------------------------------- status


@route("GET", "/api/status")
def get_status(app: Application, _request: Request) -> Response:
    return 200, {
        "protection": app.protection_status(),
        "stats": app.stats(),
        "system": app.system_info(),
        "server_time": time.time(),
    }


@route("GET", "/api/system")
def get_system(app: Application, _request: Request) -> Response:
    return 200, app.system_info()


@route("GET", "/api/stats")
def get_stats(app: Application, _request: Request) -> Response:
    return 200, app.stats()


# ---------------------------------------------------------------------- scans


@route("POST", "/api/scans")
def post_scan(app: Application, request: Request) -> Response:
    scan_type = str(request.body.get("type", "quick"))
    targets = request.body.get("targets") or None
    auto_quarantine = request.body.get("auto_quarantine")
    if targets is not None and not isinstance(targets, list):
        return 400, {"error": "targets must be a list of paths"}

    try:
        job = app.start_scan(
            scan_type,
            targets=targets,
            auto_quarantine=None if auto_quarantine is None else bool(auto_quarantine),
        )
    except FileNotFoundError as exc:
        return 404, {"error": str(exc)}
    except ValueError as exc:
        return 400, {"error": str(exc)}
    return 202, {"scan_id": job.scan_id, "progress": job.progress.to_dict()}


@route("GET", "/api/scans")
def get_scans(app: Application, request: Request) -> Response:
    return 200, {
        "active": [job.progress.to_dict() for job in app.scans.active()],
        "history": app.scan_history(limit=request.qint("limit", 25)),
    }


@route("GET", "/api/scans/{scan_id}")
def get_scan(app: Application, request: Request) -> Response:
    summary = app.scan_status(request.params["scan_id"])
    if summary is None:
        return 404, {"error": "unknown scan"}
    return 200, summary


@route("DELETE", "/api/scans/{scan_id}")
def delete_scan(app: Application, request: Request) -> Response:
    if not app.cancel_scan(request.params["scan_id"]):
        return 404, {"error": "unknown or finished scan"}
    return 200, {"cancelled": True, "scan_id": request.params["scan_id"]}


@route("POST", "/api/scans/{scan_id}/pause")
def pause_scan(app: Application, request: Request) -> Response:
    job = app.scans.get(request.params["scan_id"])
    if not job:
        return 404, {"error": "unknown scan"}
    job.pause()
    return 200, job.progress.to_dict()


@route("POST", "/api/scans/{scan_id}/resume")
def resume_scan(app: Application, request: Request) -> Response:
    job = app.scans.get(request.params["scan_id"])
    if not job:
        return 404, {"error": "unknown scan"}
    job.resume()
    return 200, job.progress.to_dict()


@route("POST", "/api/scan-file")
def scan_single_file(app: Application, request: Request) -> Response:
    """Synchronously scan one file -- used by the drag-and-drop panel."""
    target = request.body.get("path", "")
    if not target:
        return 400, {"error": "path is required"}
    from pathlib import Path

    candidate = Path(str(target)).expanduser()
    if not candidate.exists():
        return 404, {"error": f"no such path: {target}"}
    if not candidate.is_file():
        return 400, {"error": "path is not a regular file"}
    result = app.scanner.scan_file(candidate)
    return 200, result.to_dict()


# ----------------------------------------------------------------- realtime


@route("GET", "/api/realtime")
def get_realtime_status(app: Application, _request: Request) -> Response:
    return 200, app.realtime.status()


@route("POST", "/api/realtime")
def set_realtime(app: Application, request: Request) -> Response:
    enabled = bool(request.body.get("enabled", True))
    try:
        return 200, app.toggle_realtime(enabled)
    except RuntimeError as exc:
        return 400, {"error": str(exc)}


# --------------------------------------------------------------- quarantine


@route("GET", "/api/quarantine")
def get_quarantine_list(app: Application, request: Request) -> Response:
    entries = app.quarantine.list_entries(include_inactive=request.qbool("all"))
    return 200, {"entries": entries, "stats": app.quarantine.stats()}


@route("POST", "/api/quarantine/{entry_id}/restore")
def restore_quarantine(app: Application, request: Request) -> Response:
    try:
        target = app.quarantine.restore(request.params["entry_id"])
    except QuarantineError as exc:
        return 400, {"error": str(exc)}
    return 200, {"restored": True, "path": str(target)}


@route("DELETE", "/api/quarantine/{entry_id}")
def delete_quarantine(app: Application, request: Request) -> Response:
    try:
        app.quarantine.delete(request.params["entry_id"])
    except QuarantineError as exc:
        return 400, {"error": str(exc)}
    return 200, {"deleted": True, "entry_id": request.params["entry_id"]}


@route("POST", "/api/quarantine/empty")
def empty_quarantine(app: Application, _request: Request) -> Response:
    return 200, {"deleted": app.quarantine.empty()}


# ------------------------------------------------------------------ updates


@route("GET", "/api/updates/signatures")
def get_signature_updates(app: Application, request: Request) -> Response:
    if request.qbool("check"):
        return 200, {**app.signature_updater.status(), "check": app.check_signature_updates()}
    return 200, app.signature_updater.status()


@route("POST", "/api/updates/signatures")
def post_signature_update(app: Application, request: Request) -> Response:
    return 200, app.update_signatures(force=bool(request.body.get("force", False)))


@route("GET", "/api/updates/programs")
def get_program_updates(app: Application, request: Request) -> Response:
    if request.qbool("refresh"):
        return 200, app.check_programs(use_cache=False)
    return 200, {**app.programs.status(), **app.check_programs(use_cache=True)}


@route("POST", "/api/updates/programs")
def post_program_upgrade(app: Application, request: Request) -> Response:
    manager = str(request.body.get("manager", ""))
    package = str(request.body.get("package", ""))
    if not manager:
        return 400, {"error": "manager is required"}
    if request.body.get("all"):
        result = app.upgrade_all_programs(manager)
    elif not package:
        return 400, {"error": "package is required"}
    else:
        result = app.upgrade_program(manager, package)
    return (200 if result.get("ok") else 400), result


# ---------------------------------------------------------------- scheduler


@route("GET", "/api/schedule")
def get_schedule(app: Application, _request: Request) -> Response:
    return 200, {"running": app.scheduler.running, "tasks": app.scheduler.tasks()}


@route("POST", "/api/schedule/{name}")
def post_schedule(app: Application, request: Request) -> Response:
    name = request.params["name"]
    body = request.body

    if body.get("run_now"):
        if not app.scheduler.run_now(name):
            return 404, {"error": "unknown task"}
        return 202, {"started": name}

    if "cron" in body:
        try:
            if not app.scheduler.set_cron(name, str(body["cron"])):
                return 404, {"error": "unknown task"}
        except CronError as exc:
            return 400, {"error": str(exc)}
    if "enabled" in body and not app.scheduler.set_enabled(name, bool(body["enabled"])):
        return 404, {"error": "unknown task"}
    return 200, {"tasks": app.scheduler.tasks()}


# ------------------------------------------------------------------- events


@route("GET", "/api/events")
def get_events(app: Application, request: Request) -> Response:
    return 200, {
        "events": app.events(limit=request.qint("limit", 100), category=request.q("category"))
    }


@route("GET", "/api/detections")
def get_detections(app: Application, request: Request) -> Response:
    return 200, {"detections": app.detections(limit=request.qint("limit", 100))}


# ------------------------------------------------------------------- config


@route("GET", "/api/config")
def get_config_document(app: Application, _request: Request) -> Response:
    return 200, app.config.data


@route("PUT", "/api/config")
def put_config(app: Application, request: Request) -> Response:
    if not isinstance(request.body, dict) or not request.body:
        return 400, {"error": "expected a configuration object"}
    return 200, app.update_config(request.body)


@route("GET", "/api/health")
def get_health(_app: Application, _request: Request) -> Response:
    return 200, {"ok": True, "time": time.time()}
