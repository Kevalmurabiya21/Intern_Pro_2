"""Tests for Windows-safe process snapshot and lookup behaviour."""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.detectors import process_monitor


class TestProcessMonitor(unittest.TestCase):
    def test_find_current_process_returns_a_snapshot(self):
        snapshot = process_monitor.find_process(os.getpid())
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.pid, os.getpid())
        self.assertTrue(snapshot.name)
        self.assertGreaterEqual(snapshot.memory_rss_bytes, 0)

    def test_find_missing_process_returns_none(self):
        self.assertIsNone(process_monitor.find_process(99999999))

    def test_snapshot_limit_is_sorted_and_respected(self):
        snapshots = process_monitor.snapshot_processes(top_n_by_cpu=3)
        self.assertLessEqual(len(snapshots), 3)
        self.assertEqual(snapshots, sorted(snapshots, key=lambda item: item.cpu_percent, reverse=True))

    def test_snapshot_skips_access_denied_process(self):
        blocked = Mock()
        blocked.info = property(lambda _: (_ for _ in ()).throw(process_monitor.psutil.AccessDenied()))
        with patch.object(process_monitor.psutil, "process_iter", return_value=[blocked]):
            self.assertEqual(process_monitor.snapshot_processes(), [])

    def test_safe_returns_none_when_process_detail_is_unavailable(self):
        self.assertIsNone(process_monitor._safe(lambda: (_ for _ in ()).throw(OSError("denied"))))

