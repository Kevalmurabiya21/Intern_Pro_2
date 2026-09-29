"""Unit tests for the detection engine's scoring logic (app.detectors.engine)."""
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import load_settings
from app.core.models import FileEvent
from app.detectors.engine import DetectionEngine, band_for_score


class TestBandForScore(unittest.TestCase):
    def test_normal_band_boundaries(self):
        self.assertEqual(band_for_score(0, 40, 70), "Normal")
        self.assertEqual(band_for_score(40, 40, 70), "Normal")

    def test_warning_band_boundaries(self):
        self.assertEqual(band_for_score(41, 40, 70), "Warning")
        self.assertEqual(band_for_score(70, 40, 70), "Warning")

    def test_critical_band(self):
        self.assertEqual(band_for_score(71, 40, 70), "Critical")
        self.assertEqual(band_for_score(100, 40, 70), "Critical")


class TestDetectionEngineScoring(unittest.TestCase):
    def setUp(self):
        self.settings = load_settings(str(Path(__file__).resolve().parent.parent / "config.yaml"))
        self.engine = DetectionEngine(self.settings)

    def test_light_normal_activity_does_not_reach_critical(self):
        now = datetime.now(timezone.utc)
        for i in range(2):
            event = FileEvent(event_type="created", src_path=f"data/sandbox/note_{i}.txt",
                               entropy=3.0, timestamp=now)
            score = self.engine.ingest(event)
        self.assertNotEqual(score.band, "Critical")

    def test_burst_of_high_entropy_renames_reaches_critical(self):
        now = datetime.now(timezone.utc)
        score = None
        for i in range(60):
            self.engine.ingest(FileEvent(event_type="modified", src_path=f"data/sandbox/f_{i}.txt",
                                          entropy=7.9, timestamp=now))
        for i in range(60):
            score = self.engine.ingest(FileEvent(
                event_type="moved", src_path=f"data/sandbox/f_{i}.txt",
                dest_path=f"data/sandbox/f_{i}.locked", entropy=7.9, timestamp=now,
            ))
        self.assertEqual(score.band, "Critical")
        self.assertIn("rapid_encryption", score.fired_signals)
        self.assertIn("mass_rename", score.fired_signals)
        self.assertIn("high_entropy", score.fired_signals)

    def test_score_is_capped_at_100(self):
        now = datetime.now(timezone.utc)
        score = None
        for i in range(200):
            self.engine.ingest(FileEvent(event_type="modified", src_path=f"data/sandbox/f_{i}.txt",
                                          entropy=8.0, timestamp=now))
        for i in range(200):
            score = self.engine.ingest(FileEvent(
                event_type="moved", src_path=f"data/sandbox/f_{i}.txt",
                dest_path=f"data/sandbox/f_{i}.locked", entropy=8.0, timestamp=now,
            ))
        self.assertLessEqual(score.score, 100)

    def test_extension_change_counts_as_rename_signal(self):
        e = FileEvent(event_type="moved", src_path="a.docx", dest_path="a.locked")
        self.assertTrue(e.is_extension_change)
        e2 = FileEvent(event_type="moved", src_path="a.txt", dest_path="b.txt")
        self.assertFalse(e2.is_extension_change)


if __name__ == "__main__":
    unittest.main()
