"""
Phase 4 & 5: Detection engine and threat scoring.

The engine keeps a sliding window of recent FileEvents. Every time a new
event arrives it recomputes burst statistics over that window (files/min,
renames/min, extension changes/min, average entropy), compares them against
configured thresholds to decide which "signals" have fired, and turns the
fired signals into a single weighted 0-100 threat score.

This is deliberately a plain rule engine, not a model: every point in the
score can be explained by naming the exact rule that added it, and no
training data is required.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Deque, List, Optional

from app.core.config import Settings
from app.core.models import FileEvent, SignalState, ThreatScore
from app.core.logging_setup import get_logger
from app.detectors.process_monitor import snapshot_processes

_alerts_log = get_logger("alerts")
_system_log = get_logger("system")


def band_for_score(score: int, normal_max: int, warning_max: int) -> str:
    if score <= normal_max:
        return "Normal"
    if score <= warning_max:
        return "Warning"
    return "Critical"


class DetectionEngine:
    def __init__(self, settings: Settings,
                 on_score: Optional[Callable[[ThreatScore, SignalState], None]] = None):
        self.settings = settings
        self._window: Deque[FileEvent] = deque()
        self._lock = threading.Lock()
        self._on_score = on_score or (lambda score, state: None)
        self.last_score: Optional[ThreatScore] = None
        self.last_state: Optional[SignalState] = None
        # Process enumeration can be expensive on Windows. File-system bursts
        # can contain hundreds of events per second, so sample the process
        # list at most once per second rather than once per file event.
        self._last_process_sample_at = 0.0
        self._last_top_process = None

    # -- ingestion -----------------------------------------------------
    def ingest(self, event: FileEvent) -> ThreatScore:
        """Add a new event, evict anything outside the window, recompute
        signals, score them, and return the resulting ThreatScore."""
        with self._lock:
            self._window.append(event)
            self._evict_old(event.timestamp)
            state = self._compute_signals(list(self._window))
            score = self._score(state)
            self.last_score = score
            self.last_state = state

        if score.band != "Normal":
            _alerts_log.warning(
                f"{score.band} band | score={score.score} | signals={score.fired_signals}"
            )

        self._on_score(score, state)
        return score

    def _evict_old(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.settings.detection.window_seconds)
        while self._window and self._window[0].timestamp < cutoff:
            self._window.popleft()

    # -- signal computation ---------------------------------------------
    def _compute_signals(self, window_events: List[FileEvent]) -> SignalState:
        window_seconds = max(self.settings.detection.window_seconds, 1)
        minutes = window_seconds / 60.0

        modified = [e for e in window_events if e.event_type in ("created", "modified")]
        renamed = [e for e in window_events if e.event_type == "moved"]
        ext_changes = [e for e in renamed if e.is_extension_change]
        # Initial file creation often contains normal low-entropy text. The
        # ransomware signal is the subsequent encrypted rewrite or rename,
        # so score entropy from those events instead of diluting it with setup
        # activity from the same batch.
        entropies = [
            e.entropy for e in window_events
            if e.event_type in ("modified", "moved") and e.entropy is not None
        ]

        affected = sorted({e.dest_path or e.src_path for e in window_events})

        state = SignalState(
            files_modified_per_minute=len(modified) / minutes,
            renames_per_minute=len(renamed) / minutes,
            extension_changes_per_minute=len(ext_changes) / minutes,
            avg_entropy=(sum(entropies) / len(entropies)) if entropies else 0.0,
            affected_files=affected,
        )

        # Process signal: highest CPU among currently running processes, and
        # whether it's outside our configured allow-list of known programs.
        if time.monotonic() - self._last_process_sample_at >= 1.0:
            procs = snapshot_processes(top_n_by_cpu=1)
            self._last_top_process = procs[0] if procs else None
            self._last_process_sample_at = time.monotonic()

        if self._last_top_process:
            top = self._last_top_process
            state.max_cpu_percent = top.cpu_percent
            state.suspect_pid = top.pid
            state.suspect_process_name = top.name
            state.unknown_program_seen = top.name not in self.settings.response.known_programs

        return state

    # -- scoring ----------------------------------------------------------
    def _score(self, state: SignalState) -> ThreatScore:
        w = self.settings.scoring.weights
        t = self.settings.detection.thresholds
        fired: List[str] = []
        total = 0

        if state.files_modified_per_minute >= t.files_modified_per_minute:
            total += w.rapid_encryption
            fired.append("rapid_encryption")

        if state.renames_per_minute >= t.renames_per_minute or \
           state.extension_changes_per_minute >= t.extension_changes_per_minute:
            total += w.mass_rename
            fired.append("mass_rename")

        if state.avg_entropy >= t.high_entropy_value:
            total += w.high_entropy
            fired.append("high_entropy")

        if state.max_cpu_percent >= t.cpu_spike_percent:
            total += w.cpu_spike
            fired.append("cpu_spike")

        if state.unknown_program_seen:
            total += w.unknown_program
            fired.append("unknown_program")

        total = min(total, 100)
        band = band_for_score(total, self.settings.scoring.bands.normal_max,
                               self.settings.scoring.bands.warning_max)
        return ThreatScore(score=total, band=band, fired_signals=fired)
