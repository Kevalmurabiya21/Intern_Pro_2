"""
Shared plain-data types used across RDRS modules.

Kept dependency-free (stdlib dataclasses only) so core/detectors/database/api
can all import from here without circular imports.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class FileEvent:
    """One observed file-system change."""
    event_type: str          # "created" | "modified" | "deleted" | "moved"
    src_path: str
    dest_path: Optional[str] = None   # only set for "moved" (rename) events
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    extension: str = ""
    entropy: Optional[float] = None   # populated for created/modified/moved events

    def __post_init__(self):
        if not self.extension:
            p = Path(self.dest_path or self.src_path)
            self.extension = p.suffix.lower()

    @property
    def is_extension_change(self) -> bool:
        """True when a move/rename also changed the file extension
        (e.g. report.docx -> report.locked) - a classic ransomware signal."""
        if self.event_type != "moved" or not self.dest_path:
            return False
        return Path(self.src_path).suffix.lower() != Path(self.dest_path).suffix.lower()


@dataclass
class ProcessSnapshot:
    """A point-in-time snapshot of one running process."""
    pid: int
    name: str
    cpu_percent: float
    memory_rss_bytes: int
    exe_path: Optional[str]
    parent_pid: Optional[int]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SignalState:
    """Sliding-window statistics recomputed on every new event."""
    files_modified_per_minute: float = 0.0
    renames_per_minute: float = 0.0
    extension_changes_per_minute: float = 0.0
    avg_entropy: float = 0.0
    max_cpu_percent: float = 0.0
    unknown_program_seen: bool = False
    suspect_pid: Optional[int] = None
    suspect_process_name: Optional[str] = None
    affected_files: list = field(default_factory=list)


@dataclass
class ThreatScore:
    """Result of scoring a SignalState against configured weights."""
    score: int
    band: str  # "Normal" | "Warning" | "Critical"
    fired_signals: list  # list of signal names that contributed points
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Incident:
    """A recorded Critical-band detection."""
    id: Optional[int]
    created_at: datetime
    score: int
    band: str
    suspect_process: Optional[str]
    suspect_pid: Optional[int]
    affected_files: list
    quarantine_paths: list
    simulated_response: bool
