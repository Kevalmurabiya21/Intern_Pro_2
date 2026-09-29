"""Wiring tests for the Windows application entry point."""
import signal
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import main
from app.core.config import load_settings
from app.core.models import FileEvent, SignalState, ThreatScore


class _FakeMonitor:
    def __init__(self, watch_paths, ignore_patterns, on_event):
        self.watch_paths = watch_paths
        self.ignore_patterns = ignore_patterns
        self.on_event = on_event
        self.started = False
        self.stopped = False

    def start(self):
        self.started = True
        self.on_event(FileEvent("modified", "C:/sandbox/evidence.locked", entropy=7.9))

    def stop(self):
        self.stopped = True


class _FakeEngine:
    def __init__(self, settings):
        self.last_state = SignalState(
            affected_files=["C:/sandbox/evidence.locked"],
            suspect_process_name="python.exe",
            suspect_pid=42,
        )
        self.last_score = None

    def ingest(self, event):
        self.last_score = ThreatScore(100, "Critical", ["rapid_encryption"])
        return self.last_score


class TestMainWiring(unittest.TestCase):
    def test_main_starts_full_pipeline_handles_critical_event_and_shuts_down(self):
        settings = load_settings(Path(__file__).resolve().parent.parent / "config.yaml")
        settings.response.incident_cooldown_seconds = 30
        handlers = {}
        monitor_holder = {}
        fake_httpd = Mock()

        def monitor_factory(*args, **kwargs):
            monitor_holder["monitor"] = _FakeMonitor(*args, **kwargs)
            return monitor_holder["monitor"]

        def register_signal(sig, handler):
            handlers[sig] = handler

        def sleep_until_shutdown(_seconds):
            handlers[signal.SIGINT](signal.SIGINT, None)

        with (
            patch.object(sys, "argv", ["rdrs", "--auto-report"]),
            patch.object(main, "load_settings", return_value=settings),
            patch.object(main, "setup_logging"),
            patch.object(main.db, "init_db"),
            patch.object(main.db, "save_event"),
            patch.object(main.db, "save_score"),
            patch.object(main.db, "save_alert"),
            patch.object(main, "FileMonitor", side_effect=monitor_factory),
            patch.object(main, "DetectionEngine", _FakeEngine),
            patch.object(main, "handle_critical", return_value=Mock(id=1)) as critical_response,
            patch.object(main, "generate_all_reports", return_value={"json": "incident_1.json"}) as report_generation,
            patch.object(main.api_server, "configure"),
            patch.object(main.api_server, "run_server", return_value=fake_httpd),
            patch.object(main.signal, "signal", side_effect=register_signal),
            patch.object(main.time, "time", return_value=100.0),
            patch.object(main.time, "sleep", side_effect=sleep_until_shutdown),
        ):
            with self.assertRaises(SystemExit):
                main.main()

            self.assertTrue(monitor_holder["monitor"].started)
            self.assertTrue(monitor_holder["monitor"].stopped)
            critical_response.assert_called_once()
            report_generation.assert_called_once_with(1)
        fake_httpd.shutdown.assert_called_once()

    def test_parse_args_accepts_no_api_and_repeated_watch_paths(self):
        with patch.object(sys, "argv", ["rdrs", "--no-api", "--watch", "one", "--watch", "two"]):
            args = main.parse_args()
        self.assertTrue(args.no_api)
        self.assertEqual(args.watch, ["one", "two"])
