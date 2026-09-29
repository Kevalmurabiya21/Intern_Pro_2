"""
Phase 3: Process monitoring.

Takes point-in-time snapshots of running processes using psutil: name,
CPU%, memory, exe path, and parent process. Some system processes refuse
access (permissions) - we skip those quietly rather than crashing.
"""
from __future__ import annotations

from typing import List

import psutil

from app.core.models import ProcessSnapshot
from app.core.logging_setup import get_logger

_log = get_logger("system")


def snapshot_processes(top_n_by_cpu: int | None = None) -> List[ProcessSnapshot]:
    """Return a snapshot of all currently visible processes.

    If top_n_by_cpu is given, only the N highest-CPU processes are returned
    (useful for the dashboard/API so we don't ship hundreds of rows).
    """
    snapshots: List[ProcessSnapshot] = []

    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "exe", "ppid"]):
        try:
            info = proc.info
            mem = info.get("memory_info")
            snapshots.append(
                ProcessSnapshot(
                    pid=info["pid"],
                    name=info.get("name") or "unknown",
                    cpu_percent=info.get("cpu_percent") or 0.0,
                    memory_rss_bytes=mem.rss if mem else 0,
                    exe_path=info.get("exe"),
                    parent_pid=info.get("ppid"),
                )
            )
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            # Protected system process or it exited mid-scan - skip gracefully.
            continue
        except Exception as e:  # pragma: no cover - defensive catch-all
            _log.error(f"Unexpected error snapshotting a process: {e}")
            continue

    if top_n_by_cpu is not None:
        snapshots.sort(key=lambda s: s.cpu_percent, reverse=True)
        snapshots = snapshots[:top_n_by_cpu]

    return snapshots


def find_process(pid: int) -> ProcessSnapshot | None:
    try:
        proc = psutil.Process(pid)
        with proc.oneshot():
            mem = proc.memory_info()
            return ProcessSnapshot(
                pid=pid,
                name=proc.name(),
                cpu_percent=proc.cpu_percent(interval=0.1),
                memory_rss_bytes=mem.rss,
                exe_path=_safe(proc.exe),
                parent_pid=proc.ppid(),
            )
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return None


def _safe(fn):
    try:
        return fn()
    except Exception:
        return None
