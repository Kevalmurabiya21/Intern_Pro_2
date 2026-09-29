"""
Phase 5: Incident response.

On a Critical score: create an incident record, copy evidence into
quarantine, and write to the alert/audit logs. Response stays in simulation
mode by default - if process termination is ever enabled, this module only
LOGS what it would do; it never actually calls Process.kill().

Evidence handling is copy-only: originals are never modified or deleted.
"""
from __future__ import annotations

import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from app.core.config import Settings
from app.core.models import Incident, SignalState, ThreatScore
from app.core.logging_setup import get_logger
from app.database import db

_alerts_log = get_logger("alerts")
_audit_log = get_logger("audit")


def quarantine_files(paths: List[str], quarantine_dir: str) -> List[str]:
    """Copy each existing file at `paths` into quarantine_dir, preserving a
    timestamped, collision-free name. Returns the list of quarantine paths
    actually written. Originals are never touched.

    Never raises: if the quarantine directory can't be created or written to
    (e.g. a permissions misconfiguration), this logs the failure and returns
    whatever it managed to write (possibly an empty list) rather than
    crashing the caller - a failed quarantine copy should not also take down
    the detection/incident pipeline that's reporting the attack.
    """
    qdir = Path(quarantine_dir)
    try:
        qdir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        _audit_log.error(
            f"Cannot create quarantine directory '{qdir}': {e}. "
            f"Evidence for this incident will NOT be quarantined - check permissions."
        )
        return []

    written: List[str] = []
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    for i, src in enumerate(paths):
        src_path = Path(src)
        if not src_path.is_file():
            continue
        dest = qdir / f"{ts}_{i:04d}_{src_path.name}"
        try:
            shutil.copy2(src_path, dest)  # copy2 preserves metadata; never move/delete
            written.append(str(dest))
        except OSError as e:
            _audit_log.error(f"Failed to quarantine {src_path}: {e}")
    return written


def handle_critical(score: ThreatScore, state: SignalState, settings: Settings) -> Incident:
    """Respond to a Critical-band score: quarantine evidence, log, and
    persist an incident record. Returns the created Incident."""
    quarantine_paths = quarantine_files(state.affected_files, settings.response.quarantine_dir)

    _audit_log.info(
        f"CRITICAL response | suspect={state.suspect_process_name} (pid={state.suspect_pid}) | "
        f"quarantined {len(quarantine_paths)} file(s) | originals untouched"
    )

    if settings.response.simulation_mode:
        _audit_log.info(
            f"SIMULATION MODE: would terminate pid={state.suspect_pid} "
            f"({state.suspect_process_name}) - no process was actually killed."
        )
    else:
        # Even with simulation_mode off, we deliberately do NOT implement
        # real process termination in this educational build - see README.
        _audit_log.warning(
            "simulation_mode is disabled in config, but RDRS never performs "
            "real process termination in this build. No action taken."
        )

    incident = Incident(
        id=None,
        created_at=datetime.now(timezone.utc),
        score=score.score,
        band=score.band,
        suspect_process=state.suspect_process_name,
        suspect_pid=state.suspect_pid,
        affected_files=state.affected_files,
        quarantine_paths=quarantine_paths,
        simulated_response=settings.response.simulation_mode,
    )
    incident_id = db.save_incident(incident)
    incident.id = incident_id

    _alerts_log.warning(f"Incident #{incident_id} created | score={score.score} | "
                         f"{len(state.affected_files)} affected file(s)")
    return incident
