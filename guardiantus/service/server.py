"""Local dashboard host.

A threaded stdlib HTTP server -- no web framework, no dependencies.  It binds
to the loopback interface and protects the API with two mechanisms:

* a per-run **session token**, injected into the dashboard HTML and required
  on every ``/api/*`` call, and
* **Host / Origin validation**, which blocks DNS-rebinding attacks that would
  otherwise let a web page in the user's browser drive a local API capable of
  quarantining files and installing updates.
"""

from __future__ import annotations

import json
import mimetypes
import os
import secrets
import stat
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from .. import __version__, paths
from ..application import Application, get_app
from . import api

MAX_BODY_BYTES = 8 * 1024 * 1024
TOKEN_HEADER = "X-Guardiantus-Token"
TOKEN_FILE = "session.token"


def _make_token() -> str:
    return secrets.token_urlsafe(32)


class DashboardServer:
    """Owns the socket, the session token and the request handler."""

    def __init__(
        self,
        app: Optional[Application] = None,
        host: str = "127.0.0.1",
        port: int = 8787,
        token: Optional[str] = None,
    ) -> None:
        self.app = app or get_app()
        self.host = host
        self.port = port
        self.token = token or _make_token()
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._index_cache: Optional[str] = None

    # ------------------------------------------------------------ lifecycle
    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.actual_port}/"

    @property
    def actual_port(self) -> int:
        if self._httpd is not None:
            return self._httpd.server_address[1]
        return self.port

    def _write_token_file(self) -> None:
        token_path = paths.runtime_file(TOKEN_FILE)
        token_path.write_text(
            json.dumps({"token": self.token, "url": self.url, "pid": os.getpid()}),
            encoding="utf-8",
        )
        try:
            token_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def serve_forever(self, open_browser: bool = False) -> None:
        """Blocking run loop."""
        self._create_server()
        self._write_token_file()
        if open_browser:
            threading.Timer(0.7, lambda: webbrowser.open(self.url)).start()
        assert self._httpd is not None
        try:
            self._httpd.serve_forever()
        finally:
            self.stop()

    def start(self, open_browser: bool = False) -> str:
        """Start in a background thread and return the dashboard URL."""
        self._create_server()
        self._write_token_file()
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)  # type: ignore[union-attr]
        self._thread.start()
        if open_browser:
            threading.Timer(0.7, lambda: webbrowser.open(self.url)).start()
        return self.url

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        try:
            paths.runtime_file(TOKEN_FILE).unlink(missing_ok=True)
        except OSError:
            pass

    def _create_server(self) -> None:
        if self._httpd is not None:
            return
        server = ThreadingHTTPServer((self.host, self.port), _make_handler(self))
        server.daemon_threads = True
        self._httpd = server

    # ------------------------------------------------------------- security
    def allowed_hosts(self) -> Tuple[str, ...]:
        port = self.actual_port
        return (
            f"127.0.0.1:{port}",
            f"localhost:{port}",
            f"[::1]:{port}",
            f"{self.host}:{port}",
        )

    def host_allowed(self, header: str) -> bool:
        return bool(header) and header.lower() in {h.lower() for h in self.allowed_hosts()}

    def origin_allowed(self, origin: str) -> bool:
        if not origin:
            return True  # same-origin fetches from the dashboard send no Origin
        parsed = urlparse(origin)
        return f"{parsed.hostname}:{parsed.port or 80}".lower() in {
            h.lower() for h in self.allowed_hosts()
        }

    # ------------------------------------------------------------------ ui
    def index_html(self) -> str:
        """The dashboard shell with the session token injected."""
        if self._index_cache is None:
            template = (paths.UI_TEMPLATES / "index.html").read_text(encoding="utf-8")
            self._index_cache = template
        return (
            self._index_cache
            .replace("{{TOKEN}}", self.token)
            .replace("{{VERSION}}", __version__)
        )


def _make_handler(server: DashboardServer):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"GuardiantusAV/{__version__}"
        protocol_version = "HTTP/1.1"

        # -------------------------------------------------------- plumbing
        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
            # The dashboard is chatty by design; keep stdout for real events.
            pass

        def _send(
            self,
            status: int,
            body: bytes,
            content_type: str,
            extra: Optional[Dict[str, str]] = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            )
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
            body = json.dumps(payload, default=str).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8", {"Cache-Control": "no-store"})

        def _read_body(self) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                return None, "invalid Content-Length"
            if length <= 0:
                return {}, None
            if length > MAX_BODY_BYTES:
                return None, "request body too large"
            raw = self.rfile.read(length)
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return None, "body must be valid JSON"
            if not isinstance(parsed, dict):
                return None, "body must be a JSON object"
            return parsed, None

        # --------------------------------------------------------- security
        def _guard(self) -> bool:
            if not server.host_allowed(self.headers.get("Host", "")):
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "invalid Host header"})
                return False
            if not server.origin_allowed(self.headers.get("Origin", "")):
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "cross-origin request rejected"})
                return False
            return True

        def _authorised(self, query: Dict[str, Any]) -> bool:
            supplied = self.headers.get(TOKEN_HEADER, "")
            if not supplied:
                values = query.get("token") or []
                supplied = values[0] if values else ""
            return secrets.compare_digest(supplied, server.token)

        # ---------------------------------------------------------- routing
        def do_GET(self) -> None:  # noqa: N802
            self._handle("GET")

        def do_HEAD(self) -> None:  # noqa: N802
            self._handle("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._handle("POST")

        def do_PUT(self) -> None:  # noqa: N802
            self._handle("PUT")

        def do_DELETE(self) -> None:  # noqa: N802
            self._handle("DELETE")

        def _handle(self, method: str) -> None:
            if not self._guard():
                return

            parsed = urlparse(self.path)
            path = unquote(parsed.path)
            query = parse_qs(parsed.query)

            if path.startswith("/api/"):
                self._handle_api(method, path, query)
                return
            if method != "GET":
                self._send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "method not allowed"})
                return
            self._handle_static(path)

        def _handle_api(self, method: str, path: str, query: Dict[str, Any]) -> None:
            if not self._authorised(query):
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "missing or invalid session token"})
                return

            handler, params = api.resolve(method, path)
            if handler is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": f"no such endpoint: {path}"})
                return

            body: Dict[str, Any] = {}
            if method in ("POST", "PUT", "PATCH"):
                parsed_body, error = self._read_body()
                if error:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": error})
                    return
                body = parsed_body or {}

            request = api.Request(method=method, path=path, query=query, body=body, params=params)
            try:
                status, payload = handler(server.app, request)
            except Exception as exc:  # pragma: no cover - last-resort guard
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": "internal error", "detail": str(exc)},
                )
                return
            self._send_json(status, payload)

        def _handle_static(self, path: str) -> None:
            if path in ("/", "/index.html"):
                body = server.index_html().encode("utf-8")
                self._send(HTTPStatus.OK, body, "text/html; charset=utf-8", {"Cache-Control": "no-store"})
                return

            if not path.startswith("/static/"):
                self._send(HTTPStatus.NOT_FOUND, b"Not found", "text/plain; charset=utf-8")
                return

            relative = path[len("/static/"):]
            target = _safe_static_path(relative)
            if target is None or not target.is_file():
                self._send(HTTPStatus.NOT_FOUND, b"Not found", "text/plain; charset=utf-8")
                return

            content_type, _ = mimetypes.guess_type(str(target))
            try:
                body = target.read_bytes()
            except OSError:
                self._send(HTTPStatus.NOT_FOUND, b"Not found", "text/plain; charset=utf-8")
                return
            self._send(
                HTTPStatus.OK,
                body,
                content_type or "application/octet-stream",
                {"Cache-Control": "no-cache"},
            )

    return Handler


def _safe_static_path(relative: str) -> Optional[Path]:
    """Resolve a static asset, refusing anything outside the asset root."""
    root = paths.UI_STATIC.resolve()
    candidate = (root / relative).resolve()
    if candidate == root or root in candidate.parents:
        return candidate
    return None


def serve(
    host: str = "127.0.0.1",
    port: int = 8787,
    open_browser: bool = True,
    app: Optional[Application] = None,
) -> None:
    """Run the dashboard until interrupted."""
    application = app or get_app()
    application.start_background_services()
    server = DashboardServer(app=application, host=host, port=port)
    server._create_server()
    print(f"Guardiantus AV {__version__}")
    print(f"  Dashboard : {server.url}?token={server.token}")
    print(f"  Data dir  : {paths.home()}")
    print("  Press Ctrl+C to stop.")
    try:
        server.serve_forever(open_browser=open_browser)
    except KeyboardInterrupt:
        print("\nShutting down…")
    finally:
        application.shutdown()
        server.stop()
