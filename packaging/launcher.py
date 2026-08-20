"""Double-click entry point for the packaged desktop build.

This is what ``guardiantus.exe`` / ``Guardiantus AV`` / ``guardiantus`` (the
onefile binaries built by PyInstaller) actually run. It is deliberately not
the CLI: someone who double-clicks an icon does not want an argument parser,
they want the app to start.

Behaviour:
  * Starts the local dashboard and opens it in the default browser --
    identical to ``guardiantus dashboard``.
  * Keeps the console window open and waits for Ctrl+C, so on Windows the
    window does not just flash and vanish.
  * On startup failure, prints the error and waits for a keypress before
    exiting, for the same reason.
"""

from __future__ import annotations

import sys


def _pause_before_exit(message: str) -> None:
    print(f"\n{message}")
    try:
        input("Press Enter to close this window...")
    except (EOFError, KeyboardInterrupt):
        pass


def main() -> int:
    try:
        from guardiantus.application import get_app
        from guardiantus.service.server import serve
    except Exception as exc:  # pragma: no cover - defensive, packaging issue
        _pause_before_exit(f"Guardiantus AV failed to start: {exc}")
        return 1

    app = get_app()
    try:
        serve(
            host=str(app.config.get("service", "host", "127.0.0.1")),
            port=int(app.config.get("service", "port", 8787)),
            open_browser=bool(app.config.get("service", "open_browser", True)),
            app=app,
        )
    except OSError as exc:
        # Most likely: the configured port is already in use (e.g. a previous
        # instance is still running).
        _pause_before_exit(
            f"Could not start the dashboard: {exc}\n"
            "Another copy of Guardiantus AV may already be running."
        )
        return 1
    except Exception as exc:  # pragma: no cover - last-resort safety net
        _pause_before_exit(f"Guardiantus AV stopped unexpectedly: {exc}")
        return 1

    _pause_before_exit("Guardiantus AV has stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
