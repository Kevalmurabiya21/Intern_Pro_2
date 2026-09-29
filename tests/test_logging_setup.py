"""Focused tests for RDRS's rotating, channel-separated logging setup."""
import logging
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import load_settings
from app.core import logging_setup


class TestLoggingSetup(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.settings = load_settings(str(Path(__file__).resolve().parent.parent / "config.yaml"))
        self.settings.logging.dir = str(self.tmpdir)
        self._clear_handlers()

    def tearDown(self):
        self._clear_handlers()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    @staticmethod
    def _clear_handlers():
        for channel in logging_setup._CHANNELS:
            logger = logging.getLogger(f"rdrs.{channel}")
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)

    def test_parse_size_accepts_common_units(self):
        self.assertEqual(logging_setup._parse_size("1 KB"), 1024)
        self.assertEqual(logging_setup._parse_size("1.5 MB"), 1572864)
        self.assertEqual(logging_setup._parse_size("2 GB"), 2 * 1024 ** 3)
        self.assertEqual(logging_setup._parse_size("42"), 42)

    def test_setup_creates_all_channel_logs_and_routes_messages(self):
        logging_setup.setup_logging(self.settings)
        logging_setup.get_logger("system").info("startup marker")
        logging_setup.get_logger("alerts").warning("alert marker")
        logging_setup.get_logger("system").error("error marker")

        for channel in logging_setup._CHANNELS:
            path = self.tmpdir / f"{channel}.log"
            self.assertTrue(path.exists(), f"Missing {path.name}")

        self.assertIn("startup marker", (self.tmpdir / "system.log").read_text(encoding="utf-8"))
        self.assertIn("alert marker", (self.tmpdir / "alerts.log").read_text(encoding="utf-8"))
        self.assertIn("error marker", (self.tmpdir / "errors.log").read_text(encoding="utf-8"))

    def test_second_setup_does_not_duplicate_handlers(self):
        logging_setup.setup_logging(self.settings)
        first_count = len(logging_setup.get_logger("system").handlers)
        logging_setup.setup_logging(self.settings)
        self.assertEqual(len(logging_setup.get_logger("system").handlers), first_count)

