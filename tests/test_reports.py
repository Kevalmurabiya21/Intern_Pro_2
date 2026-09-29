"""End-to-end tests for all incident-report formats."""
import csv
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.models import Incident
from app.database import db
from app.reports import generator


class TestReportGeneration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.previous_cwd = Path.cwd()
        os.chdir(self.tmpdir)
        db.init_db(str(self.tmpdir / "reports.db"))
        incident = Incident(
            id=None,
            created_at=datetime.now(timezone.utc),
            score=100,
            band="Critical",
            suspect_process="python.exe",
            suspect_pid=1234,
            affected_files=[f"C:/evidence/file_{i}.locked" for i in range(45)],
            quarantine_paths=["C:/quarantine/file_0.locked"],
            simulated_response=True,
        )
        self.incident_id = db.save_incident(incident)

    def tearDown(self):
        os.chdir(self.previous_cwd)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_json_csv_html_and_pdf_reports_are_created(self):
        paths = generator.generate_all_reports(self.incident_id)
        self.assertEqual(set(paths), {"json", "csv", "html", "pdf"})
        for path in paths.values():
            self.assertTrue(Path(path).is_file())

        report_data = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        self.assertEqual(report_data["band"], "Critical")
        self.assertEqual(len(report_data["affected_files"]), 45)

        with Path(paths["csv"]).open(encoding="utf-8", newline="") as stream:
            rows = list(csv.reader(stream))
        self.assertIn(["affected_file"], rows)
        self.assertIn(["C:/evidence/file_0.locked"], rows)

        html = Path(paths["html"]).read_text(encoding="utf-8")
        self.assertIn("RDRS Incident Report", html)
        self.assertIn("#f85149", html)
        self.assertTrue(Path(paths["pdf"]).read_bytes().startswith(b"%PDF"))

    def test_missing_incident_has_a_clear_error(self):
        for make_report in (
            generator.generate_json_report,
            generator.generate_csv_report,
            generator.generate_html_report,
            generator.generate_pdf_report,
        ):
            with self.assertRaisesRegex(ValueError, "No incident"):
                make_report(99999)

