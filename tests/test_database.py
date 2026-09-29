"""Tests for app.database.db - exercises save/read functions directly to
close a real coverage gap (this module previously had no dedicated tests)."""
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import db
from app.core.models import FileEvent, ProcessSnapshot, ThreatScore, Incident


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        db.init_db(str(self.tmpdir / "test.db"))

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_save_and_read_event(self):
        db.save_event(FileEvent(event_type="created", src_path="a.txt", entropy=3.1))
        events = db.recent_events(10)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "created")
        self.assertEqual(events[0]["src_path"], "a.txt")

    def test_save_process_snapshot(self):
        db.save_process_snapshot(ProcessSnapshot(
            pid=123, name="testproc", cpu_percent=12.5,
            memory_rss_bytes=1024, exe_path="/usr/bin/testproc", parent_pid=1,
        ))
        self.assertEqual(db.counts()["processes"], 1)

    def test_save_score(self):
        db.save_score(ThreatScore(score=55, band="Warning", fired_signals=["high_entropy"]))
        self.assertEqual(db.counts()["scores"], 1)

    def test_save_and_read_alert(self):
        score = ThreatScore(score=80, band="Critical", fired_signals=["mass_rename"])
        alert_id = db.save_alert(score, "Critical band, score=80")
        self.assertIsInstance(alert_id, int)
        alerts = db.recent_alerts(10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["band"], "Critical")
        self.assertEqual(alerts[0]["score"], 80)

    def test_save_and_read_incident_round_trip(self):
        incident = Incident(
            id=None, created_at=datetime.now(timezone.utc), score=90, band="Critical",
            suspect_process="evil.exe", suspect_pid=999,
            affected_files=["a.txt", "b.txt"], quarantine_paths=["/q/a.txt"],
            simulated_response=True,
        )
        incident_id = db.save_incident(incident)
        self.assertIsInstance(incident_id, int)

        fetched = db.get_incident(incident_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["suspect_process"], "evil.exe")
        self.assertEqual(fetched["affected_files"], ["a.txt", "b.txt"])
        self.assertEqual(fetched["quarantine_paths"], ["/q/a.txt"])
        self.assertTrue(fetched["simulated_response"])

    def test_get_incident_missing_returns_none(self):
        self.assertIsNone(db.get_incident(99999))

    def test_recent_incidents_lists_multiple_in_order(self):
        for i in range(3):
            db.save_incident(Incident(
                id=None, created_at=datetime.now(timezone.utc), score=70 + i, band="Critical",
                suspect_process=f"proc{i}", suspect_pid=i,
                affected_files=[], quarantine_paths=[], simulated_response=True,
            ))
        incidents = db.recent_incidents(10)
        self.assertEqual(len(incidents), 3)
        # Most recent first.
        self.assertEqual(incidents[0]["suspect_process"], "proc2")

    def test_counts_reflects_all_tables(self):
        db.save_event(FileEvent(event_type="created", src_path="x.txt"))
        db.save_score(ThreatScore(score=10, band="Normal", fired_signals=[]))
        c = db.counts()
        self.assertEqual(c["events"], 1)
        self.assertEqual(c["scores"], 1)
        self.assertEqual(c["processes"], 0)
        self.assertEqual(c["alerts"], 0)
        self.assertEqual(c["incidents"], 0)

    def test_limit_is_respected(self):
        for i in range(20):
            db.save_event(FileEvent(event_type="created", src_path=f"f{i}.txt"))
        self.assertEqual(len(db.recent_events(5)), 5)
        self.assertEqual(len(db.recent_events(100)), 20)

    def test_reinit_with_new_path_switches_cleanly(self):
        # This exercises the fix for the connection-caching bug found while
        # writing the integration tests: init_db must not keep serving the
        # previous database after being pointed at a new path.
        db.save_event(FileEvent(event_type="created", src_path="first_db.txt"))
        self.assertEqual(db.counts()["events"], 1)

        second_dir = Path(tempfile.mkdtemp())
        try:
            db.init_db(str(second_dir / "second.db"))
            self.assertEqual(db.counts()["events"], 0, "New db should start empty, not see old data")
        finally:
            shutil.rmtree(second_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
