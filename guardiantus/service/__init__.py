"""Local dashboard API and HTTP host."""

from .server import DashboardServer, serve  # noqa: F401

__all__ = ["DashboardServer", "serve"]
