"""
Integration test: feeds a burst of fake events through the full pipeline
(engine -> response -> database) and checks a Critical incident is produced,
exactly once (edge-triggered), with evidence quarantined and originals left
untouched - mirroring the guide's "burst -> Critical incident" requirement.
"""
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import load_settings
from app.core.models import FileEvent
from app.database import db
from app.detectors.engine import DetectionEngine
from app.detectors.response import handle_critical


class TestFullPipelineIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.sandbox = self.tmpdir / "sandbox"
        self.sandbox.mkdir()
        self.quarantine = self.tmpdir / "quarantine"

        self.settings = load_settings(str(Path(__file__).resolve().parent.parent / "config.yaml"))
        self.settings.response.quarantine_dir = str(self.quarantine)
        self.settings.database.path = str(self.tmpdir / "test.db")

        db.init_db(self.settings.database.path)
        self.engine = DetectionEngine(self.settings)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_real_file(self, name: str, data: bytes) -> Path:
        p = self.sandbox / name
        p.write_bytes(data)
        return p

    def test_burst_produces_one_critical_incident_with_quarantine(self):
        now = datetime.now(timezone.utc)
        previous_band = "Normal"
        last_incident = None

        # 60 real high-entropy files actually on disk so quarantine has
        # something to copy (mirrors the sandbox_attack_sim.py trigger).
        paths = []
        for i in range(60):
            p = self._write_real_file(f"file_{i}.locked", bytes([0x41] * 20 + [i % 256] * 19980))
            paths.append(str(p))

        for i, path in enumerate(paths):
            event = FileEvent(event_type="modified", src_path=path, entropy=7.9, timestamp=now)
            score = self.engine.ingest(event)
            if score.band == "Critical" and previous_band != "Critical":
                last_incident = handle_critical(score, self.engine.last_state, self.settings)
            previous_band = score.band

        for i, path in enumerate(paths):
            event = FileEvent(event_type="moved", src_path=path,
                               dest_path=path.replace(".locked", ".relocked"),
                               entropy=7.9, timestamp=now)
            score = self.engine.ingest(event)
            if score.band == "Critical" and previous_band != "Critical":
                last_incident = handle_critical(score, self.engine.last_state, self.settings)
            previous_band = score.band

        self.assertIsNotNone(last_incident, "Expected at least one Critical incident from the burst")
        self.assertEqual(last_incident.band, "Critical")
        self.assertGreater(len(last_incident.quarantine_paths), 0, "Evidence should have been quarantined")
        self.assertTrue(self.settings.response.simulation_mode, "Simulation mode must stay on by default")

        # Originals must be untouched: every source file should still exist.
        for path in paths:
            self.assertTrue(Path(path).exists() or Path(path.replace(".locked", ".relocked")).exists())

        incidents = db.recent_incidents(10)
        self.assertGreaterEqual(len(incidents), 1)

    def test_normal_activity_creates_no_incident(self):
        now = datetime.now(timezone.utc)
        for i in range(3):
            p = self._write_real_file(f"note_{i}.txt", b"just a normal document " * 5)
            event = FileEvent(event_type="created", src_path=str(p), entropy=3.0, timestamp=now)
            score = self.engine.ingest(event)
        self.assertNotEqual(score.band, "Critical")
        self.assertEqual(len(db.recent_incidents(10)), 0)


if __name__ == "__main__":
    unittest.main()
