"""Task scheduler for recurring scans and update checks.

Includes a small five-field cron parser (``minute hour day month weekday``)
supporting ``*``, ``a-b`` ranges, ``a,b,c`` lists and ``*/n`` steps -- enough
for scheduling without pulling in a dependency.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from .db import Database, get_db

_FIELD_RANGES = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)]


class CronError(ValueError):
    """Raised for malformed cron expressions."""


def parse_cron(expression: str) -> List[set]:
    """Expand a five-field cron expression into per-field value sets."""
    fields = expression.split()
    if len(fields) != 5:
        raise CronError(f"expected 5 fields, got {len(fields)}: {expression!r}")

    parsed: List[set] = []
    for field_text, (low, high) in zip(fields, _FIELD_RANGES):
        values: set = set()
        for part in field_text.split(","):
            step = 1
            if "/" in part:
                part, _, step_text = part.partition("/")
                try:
                    step = int(step_text)
                except ValueError as exc:
                    raise CronError(f"bad step in {field_text!r}") from exc
                if step <= 0:
                    raise CronError(f"bad step in {field_text!r}")
            if part in ("*", ""):
                start, end = low, high
            elif "-" in part:
                start_text, _, end_text = part.partition("-")
                try:
                    start, end = int(start_text), int(end_text)
                except ValueError as exc:
                    raise CronError(f"bad range in {field_text!r}") from exc
            else:
                try:
                    start = end = int(part)
                except ValueError as exc:
                    raise CronError(f"bad value in {field_text!r}") from exc
            if start < low or end > high or start > end:
                raise CronError(f"{field_text!r} out of range [{low}, {high}]")
            values.update(range(start, end + 1, step))
        if not values:
            raise CronError(f"empty field: {field_text!r}")
        parsed.append(values)
    return parsed


def cron_matches(expression: str, when: datetime) -> bool:
    minutes, hours, days, months, weekdays = parse_cron(expression)
    # cron weekdays: 0 = Sunday; Python: 0 = Monday.
    weekday = (when.weekday() + 1) % 7
    return (
        when.minute in minutes
        and when.hour in hours
        and when.day in days
        and when.month in months
        and weekday in weekdays
    )


def next_run(
    expression: str, after: Optional[datetime] = None, horizon_days: int = 366
) -> Optional[datetime]:
    """First minute at or after ``after`` that satisfies ``expression``."""
    parse_cron(expression)  # validate early
    start = (after or datetime.now()).replace(second=0, microsecond=0) + timedelta(minutes=1)
    limit = start + timedelta(days=horizon_days)
    cursor = start
    while cursor < limit:
        if cron_matches(expression, cursor):
            return cursor
        cursor += timedelta(minutes=1)
    return None


@dataclass
class ScheduledTask:
    """A named job that fires on a cron expression."""

    name: str
    cron: str
    action: Callable[[], Any]
    enabled: bool = True
    description: str = ""
    last_run: Optional[float] = None
    last_result: str = ""
    last_error: str = ""
    run_count: int = 0
    _last_fire_minute: Optional[str] = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        upcoming = None
        if self.enabled:
            try:
                candidate = next_run(self.cron)
                upcoming = candidate.timestamp() if candidate else None
            except CronError:
                upcoming = None
        return {
            "name": self.name,
            "cron": self.cron,
            "enabled": self.enabled,
            "description": self.description,
            "last_run": self.last_run,
            "last_result": self.last_result,
            "last_error": self.last_error,
            "run_count": self.run_count,
            "next_run": upcoming,
        }


class Scheduler:
    """Minute-resolution task runner."""

    def __init__(self, db: Optional[Database] = None) -> None:
        self.db = db or get_db()
        self._tasks: Dict[str, ScheduledTask] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ----------------------------------------------------------- registration
    def register(
        self,
        name: str,
        cron: str,
        action: Callable[[], Any],
        enabled: bool = True,
        description: str = "",
    ) -> ScheduledTask:
        parse_cron(cron)  # raises CronError on bad input
        task = ScheduledTask(
            name=name, cron=cron, action=action, enabled=enabled, description=description
        )
        with self._lock:
            self._tasks[name] = task
        return task

    def unregister(self, name: str) -> bool:
        with self._lock:
            return self._tasks.pop(name, None) is not None

    def set_enabled(self, name: str, enabled: bool) -> bool:
        with self._lock:
            task = self._tasks.get(name)
            if not task:
                return False
            task.enabled = enabled
            return True

    def set_cron(self, name: str, cron: str) -> bool:
        parse_cron(cron)
        with self._lock:
            task = self._tasks.get(name)
            if not task:
                return False
            task.cron = cron
            return True

    def tasks(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [task.to_dict() for task in self._tasks.values()]

    # -------------------------------------------------------------- running
    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="gav-scheduler", daemon=True)
            self._thread.start()
            self.db.add_event("info", "scheduler", "Scheduler started", {})

    def stop(self) -> None:
        with self._lock:
            self._stop.set()
            thread = self._thread
            self._thread = None
        if thread:
            thread.join(timeout=5)
        self.db.add_event("info", "scheduler", "Scheduler stopped", {})

    def _loop(self) -> None:
        while not self._stop.is_set():
            self.tick()
            # Align to the next minute boundary so tasks fire promptly.
            delay = 60 - (time.time() % 60)
            self._stop.wait(min(delay, 60))

    def tick(self, when: Optional[datetime] = None) -> List[str]:
        """Fire every task due at ``when``. Returns the names that ran."""
        now = (when or datetime.now()).replace(second=0, microsecond=0)
        stamp = now.strftime("%Y-%m-%dT%H:%M")
        fired: List[str] = []

        with self._lock:
            candidates = [t for t in self._tasks.values() if t.enabled and t._last_fire_minute != stamp]

        for task in candidates:
            try:
                due = cron_matches(task.cron, now)
            except CronError as exc:
                task.last_error = str(exc)
                continue
            if not due:
                continue
            task._last_fire_minute = stamp
            fired.append(task.name)
            threading.Thread(
                target=self._execute, args=(task,), name=f"gav-task-{task.name}", daemon=True
            ).start()
        return fired

    def run_now(self, name: str) -> bool:
        """Fire a task immediately, outside its schedule."""
        with self._lock:
            task = self._tasks.get(name)
        if not task:
            return False
        threading.Thread(target=self._execute, args=(task,), name=f"gav-task-{name}", daemon=True).start()
        return True

    def _execute(self, task: ScheduledTask) -> None:
        task.last_run = time.time()
        task.run_count += 1
        self.db.add_event("info", "scheduler", f"Task '{task.name}' started", {"cron": task.cron})
        try:
            result = task.action()
            task.last_result = str(result)[:500] if result is not None else "ok"
            task.last_error = ""
        except Exception as exc:  # pragma: no cover - task bodies vary
            task.last_error = str(exc)
            task.last_result = "failed"
            self.db.add_event("error", "scheduler", f"Task '{task.name}' failed: {exc}", {})
        else:
            self.db.add_event(
                "info", "scheduler", f"Task '{task.name}' finished", {"result": task.last_result}
            )


_INSTANCE: Optional[Scheduler] = None
_INSTANCE_LOCK = threading.Lock()


def get_scheduler() -> Scheduler:
    global _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is None:
            _INSTANCE = Scheduler()
        return _INSTANCE


def reset_scheduler_cache() -> None:
    global _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is not None and _INSTANCE.running:
            _INSTANCE.stop()
        _INSTANCE = None
