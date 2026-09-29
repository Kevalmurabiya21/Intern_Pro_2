"""Tests for file event translation, filtering, and monitor lifecycle."""
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.detectors.file_monitor import FileMonitor, _Handler


class TestFileMonitor(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_handler_ignores_matching_paths(self):
        received = []
        handler = _Handler(received.append, ["ignore-me"])
        handler._emit("created", str(self.tmpdir / "ignore-me.txt"))
        self.assertEqual(received, [])
        self.assertEqual(handler.event_count, 0)

    def test_handler_emits_entropy_for_a_real_file(self):
        received = []
        path = self.tmpdir / "evidence.txt"
        path.write_text("normal content", encoding="utf-8")
        handler = _Handler(received.append, [])
        handler._emit("created", str(path))
        self.assertEqual(handler.event_count, 1)
        self.assertEqual(received[0].event_type, "created")
        self.assertIsNotNone(received[0].entropy)

    def test_handler_records_moved_destination(self):
        received = []
        source = self.tmpdir / "before.txt"
        destination = self.tmpdir / "after.locked"
        destination.write_bytes(b"x" * 100)
        handler = _Handler(received.append, [])
        handler._emit("moved", str(source), str(destination))
        self.assertEqual(received[0].dest_path, str(destination))
        self.assertTrue(received[0].is_extension_change)

    def test_monitor_start_and_stop_on_windows(self):
        monitor = FileMonitor([str(self.tmpdir)], on_event=lambda event: None)
        monitor.start()
        self.assertTrue(monitor._observer.is_alive())
        monitor.stop()
        time.sleep(0.1)
        self.assertFalse(monitor._observer.is_alive())

