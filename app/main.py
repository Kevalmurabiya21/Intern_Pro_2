"""
RDRS entry point.

Wires together: config -> logging -> database -> file monitor -> detection
engine -> response -> REST API. Run with:

    python -m app.main
    python -m app.main --watch ./data/sandbox

Then, in a second terminal, trigger a detection safely:

    python scripts/sandbox_attack_sim.py

And open the dashboard in a browser:

    http://127.0.0.1:8000/dashboard
"""
from __future__ import annotations

import argparse
import signal
import sys
import time

from app.core.config import load_settings
from app.core.logging_setup import setup_logging, get_logger
from app.core.models import FileEvent
from app.database import db
from app.detectors.file_monitor import FileMonitor
from app.detectors.engine import DetectionEngine
from app.detectors.response import handle_critical
from app.reports.generator import generate_all_reports
from app.api import server as api_server

_system_log = get_logger("system")


def parse_args():
    parser = argparse.ArgumentParser(description="RDRS - Ransomware Detection and Response System")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--watch", action="append", default=None,
                         help="Folder to watch (repeatable). Overrides config.yaml if given.")
    parser.add_argument("--no-api", action="store_true", help="Don't start the REST API/dashboard")
    parser.add_argument("--auto-report", action="store_true",
                         help="Automatically generate reports for every new incident")
    return parser.parse_args()


def main():
    args = parse_args()
    settings = load_settings(args.config)
    if args.watch:
        settings.monitor.watch_paths = args.watch

    setup_logging(settings)
    db.init_db(settings.database.path)

    _system_log.info("=" * 60)
    _system_log.info("RDRS starting up")
    _system_log.info(f"Watching: {settings.monitor.watch_paths}")
    _system_log.info(f"Simulation mode: {settings.response.simulation_mode}")
    _system_log.info("=" * 60)

    engine = DetectionEngine(settings)

    # Edge-triggered + cooldown response: only react the moment we CROSS
    # INTO Critical, AND only if enough time has passed since the last
    # incident. Edge-triggering alone still isn't enough - during a burst,
    # noisy signals (especially cpu_spike/unknown_program, which key off
    # whatever process momentarily has the highest CPU) can make the score
    # flap in and out of Critical rapidly, re-triggering a "fresh" edge
    # dozens of times a second. The cooldown collapses one continuous burst
    # into one incident regardless of how much the score flaps underneath it.
    state_holder = {"previous_band": "Normal", "last_incident_time": None}

    def on_event(event: FileEvent):
        db.save_event(event)
        score = engine.ingest(event)
        db.save_score(score)

        if score.band != "Normal":
            db.save_alert(score, f"{score.band} band, score={score.score}, signals={score.fired_signals}")

        entering_critical = score.band == "Critical" and state_holder["previous_band"] != "Critical"
        state_holder["previous_band"] = score.band

        if not entering_critical:
            return

        now = time.time()
        last = state_holder["last_incident_time"]
        cooldown = settings.response.incident_cooldown_seconds
        if last is not None and (now - last) < cooldown:
            _system_log.info(
                f"Critical edge detected but within {cooldown}s incident cooldown "
                f"({now - last:.1f}s since last incident) - suppressing duplicate incident"
            )
            return

        state_holder["last_incident_time"] = now
        incident = handle_critical(score, engine.last_state, settings)
        if args.auto_report:
            try:
                paths = generate_all_reports(incident.id)
                _system_log.info(f"Auto-generated reports for incident #{incident.id}: {paths}")
            except Exception as e:
                get_logger("errors").error(f"Report generation failed: {e}")

    monitor = FileMonitor(
        watch_paths=settings.monitor.watch_paths,
        ignore_patterns=settings.monitor.ignore_patterns,
        on_event=on_event,
    )
    monitor.start()

    httpd = None
    if not args.no_api:
        api_server.configure(engine, monitor, settings)
        httpd = api_server.run_server(settings.api.host, settings.api.port)
        _system_log.info(f"Dashboard: http://{settings.api.host}:{settings.api.port}/dashboard")

    def shutdown(signum=None, frame=None):
        _system_log.info("Shutting down RDRS...")
        monitor.stop()
        if httpd:
            httpd.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    _system_log.info("RDRS is running. Press Ctrl+C to stop.")
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
