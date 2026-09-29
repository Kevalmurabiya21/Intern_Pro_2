"""
Regression tests for config loading bugs found via manual testing: bad types
and malformed top-level structure used to be silently accepted (and would
crash something far away, e.g. a division in the detection engine, instead
of failing loudly and clearly at startup).
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import load_settings, ConfigError


class TestConfigValidation(unittest.TestCase):
    def _write(self, content: str) -> str:
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8")
        f.write(content)
        f.close()
        return f.name

    def test_missing_file_raises_filenotfounderror(self):
        with self.assertRaises(FileNotFoundError):
            load_settings("/no/such/config.yaml")

    def test_empty_file_loads_defaults(self):
        path = self._write("")
        s = load_settings(path)
        self.assertEqual(s.monitor.watch_paths, ["./data/sandbox"])

    def test_partial_config_fills_in_defaults(self):
        path = self._write('monitor:\n  watch_paths:\n    - "./custom"\n')
        s = load_settings(path)
        self.assertEqual(s.monitor.watch_paths, ["./custom"])
        self.assertEqual(s.scoring.weights.rapid_encryption, 40)  # default preserved

    def test_wrong_type_for_numeric_field_raises_configerror(self):
        path = self._write('detection:\n  window_seconds: "not_a_number"\n')
        with self.assertRaises(ConfigError):
            load_settings(path)

    def test_wrong_type_for_boolean_field_raises_configerror(self):
        path = self._write('response:\n  simulation_mode: "yes_please"\n')
        with self.assertRaises(ConfigError):
            load_settings(path)

    def test_top_level_list_instead_of_mapping_raises_configerror(self):
        path = self._write("- just\n- a\n- list\n")
        with self.assertRaises(ConfigError):
            load_settings(path)

    def test_list_field_given_a_string_raises_configerror(self):
        path = self._write('monitor:\n  watch_paths: "not_a_list"\n')
        with self.assertRaises(ConfigError):
            load_settings(path)

    def test_real_project_config_still_loads(self):
        real_config = str(Path(__file__).resolve().parent.parent / "config.yaml")
        s = load_settings(real_config)
        self.assertGreater(s.detection.window_seconds, 0)
        self.assertIsInstance(s.response.incident_cooldown_seconds, int)


if __name__ == "__main__":
    unittest.main()
