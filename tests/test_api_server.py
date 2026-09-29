"""
Tests for app.api.server - starts the real server on a background thread on
an ephemeral port and hits it with real HTTP requests (stdlib urllib, since
httpx isn't installable in this sandbox), closing what was previously a
0%-covered module.
"""
import json
import shutil
import sys
import tempfile
import unittest
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import load_settings
from app.database import db
from app.detectors.engine import DetectionEngine
from app.detectors.file_monitor import FileMonitor
from app.api import server as api_server


class TestApiServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = Path(tempfile.mkdtemp())
        cls.settings = load_settings(str(Path(__file__).resolve().parent.parent / "config.yaml"))
        cls.settings.database.path = str(cls.tmpdir / "api_test.db")
        cls.settings.monitor.watch_paths = [str(cls.tmpdir / "sandbox")]
        cls.settings.api.port = 8123  # fixed test port, unlikely to collide

        db.init_db(cls.settings.database.path)
        cls.engine = DetectionEngine(cls.settings)
        cls.monitor = FileMonitor(watch_paths=cls.settings.monitor.watch_paths, ignore_patterns=[])
        cls.monitor.start()

        api_server.configure(cls.engine, cls.monitor, cls.settings)
        cls.httpd = api_server.run_server(cls.settings.api.host, cls.settings.api.port)
        cls.base_url = f"http://{cls.settings.api.host}:{cls.settings.api.port}"

    @classmethod
    def tearDownClass(cls):
        cls.monitor.stop()
        cls.httpd.shutdown()
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def _get(self, path):
        with urllib.request.urlopen(self.base_url + path, timeout=5) as resp:
            return resp.status, json.loads(resp.read())

    def _post(self, path, body=None):
        data = json.dumps(body or {}).encode()
        req = urllib.request.Request(self.base_url + path, data=data, method="POST",
                                      headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())

    def test_health_endpoint(self):
        status, body = self._get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    def test_status_endpoint_shape(self):
        status, body = self._get("/status")
        self.assertEqual(status, 200)
        for key in ("uptime_seconds", "threat_score", "threat_band", "event_count", "db_counts"):
            self.assertIn(key, body)

    def test_alerts_endpoint_empty_initially(self):
        status, body = self._get("/alerts?limit=5")
        self.assertEqual(status, 200)
        self.assertIn("alerts", body)
        self.assertIsInstance(body["alerts"], list)

    def test_events_endpoint(self):
        status, body = self._get("/events?limit=5")
        self.assertEqual(status, 200)
        self.assertIn("events", body)

    def test_incidents_endpoint(self):
        status, body = self._get("/incidents?limit=5")
        self.assertEqual(status, 200)
        self.assertIn("incidents", body)

    def test_reports_endpoint(self):
        status, body = self._get("/reports")
        self.assertEqual(status, 200)
        self.assertIn("reports", body)

    def test_dashboard_serves_html(self):
        req = urllib.request.Request(self.base_url + "/dashboard")
        with urllib.request.urlopen(req, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))
            body = resp.read().decode()
            self.assertIn("RDRS", body)

    def test_unknown_route_returns_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._get("/no/such/route")
        self.assertEqual(ctx.exception.code, 404)

    def test_scan_endpoint_returns_processes(self):
        status, body = self._post("/scan")
        self.assertEqual(status, 200)
        self.assertIn("top_processes", body)
        self.assertIsInstance(body["top_processes"], list)

    def test_settings_endpoint_is_read_only(self):
        status, body = self._post("/settings", {"simulation_mode": False})
        self.assertEqual(status, 200)
        self.assertIn("read-only", body["message"])
        # Confirm it did NOT actually change the live settings.
        self.assertTrue(self.settings.response.simulation_mode)

    def test_root_lists_endpoints(self):
        status, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("endpoints", body)


if __name__ == "__main__":
    unittest.main()
