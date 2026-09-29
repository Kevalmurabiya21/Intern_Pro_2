"""
Phase 2: Real-time file monitoring.

Wraps `watchdog` to watch the configured folders and turn its raw
filesystem-specific events into our own small FileEvent objects (event type,
path, time, extension), then hands each one to a callback - normally
DetectionEngine.ingest().
"""
from __future__ import annotations

import threading
import time
import os
from pathlib import Path
from typing import Callable, List

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver

from app.core.entropy import file_entropy
from app.core.models import FileEvent
from app.core.logging_setup import get_logger

_events_log = get_logger("events")


class _Handler(FileSystemEventHandler):
    def __init__(self, on_event: Callable[[FileEvent], None], ignore_patterns: List[str]):
        super().__init__()
        self._on_event = on_event
        self._ignore_patterns = ignore_patterns
        self.event_count = 0
        self._lock = threading.Lock()

    def _ignored(self, path: str) -> bool:
        return any(pat in path for pat in self._ignore_patterns)

    def _emit(self, event_type: str, src_path: str, dest_path: str | None = None):
        if self._ignored(src_path) or (dest_path and self._ignored(dest_path)):
            return

        entropy = None
        if event_type in ("created", "modified", "moved"):
            check_path = dest_path or src_path
            if Path(check_path).is_file():
                entropy = file_entropy(check_path)

        fe = FileEvent(
            event_type=event_type,
            src_path=src_path,
            dest_path=dest_path,
            entropy=entropy,
        )

        with self._lock:
            self.event_count += 1
            count = self.event_count

        _events_log.info(
            f"#{count} {event_type:8s} {dest_path or src_path}"
            + (f" (entropy={entropy:.2f})" if entropy is not None else "")
        )
        self._on_event(fe)

    def on_created(self, event):
        if not event.is_directory:
            self._emit("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._emit("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._emit("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._emit("moved", event.src_path, event.dest_path)


class FileMonitor:
    """Watches one or more folders (recursively) and reports every
    create/modify/delete/rename to a callback in real time."""

    def __init__(self, watch_paths: List[str], ignore_patterns: List[str] | None = None,
                 on_event: Callable[[FileEvent], None] | None = None):
        self.watch_paths = [str(Path(p).resolve()) for p in watch_paths]
        self._ignore_patterns = ignore_patterns or []
        self._on_event = on_event or (lambda e: None)
        # Docker Desktop bind mounts on Windows do not always relay inotify
        # events. Compose enables polling explicitly so container monitoring
        # remains reliable; native runs retain the more efficient observer.
        observer_type = PollingObserver if os.getenv("RDRS_USE_POLLING_MONITOR") == "true" else Observer
        self._observer = observer_type()
        self._handler = _Handler(self._on_event, self._ignore_patterns)

    @property
    def event_count(self) -> int:
        return self._handler.event_count

    def start(self) -> None:
        for path in self.watch_paths:
            Path(path).mkdir(parents=True, exist_ok=True)
            self._observer.schedule(self._handler, path, recursive=True)
        self._observer.start()
        get_logger("system").info(f"FileMonitor watching: {', '.join(self.watch_paths)}")

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join(timeout=5)

    def run_forever(self) -> None:
        self.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
