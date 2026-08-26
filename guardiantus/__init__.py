"""Guardiantus AV -- a modern, dependency-light antivirus suite.

The package is split into four layers:

``guardiantus.core``
    Detection engine: hashing, signatures, heuristics, YARA, scanning,
    quarantine, real-time protection and scheduling.
``guardiantus.updater``
    Signature database updates and third-party program update management.
``guardiantus.service``
    Local HTTP API + dashboard host.
``guardiantus.ui``
    Static assets for the dashboard (white / black / grey design system).
"""

__all__ = ["__version__", "APP_NAME"]

__version__ = "1.1.0"
APP_NAME = "Guardiantus AV"
