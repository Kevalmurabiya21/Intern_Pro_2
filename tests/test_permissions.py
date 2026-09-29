"""
Regression tests for permission-related failures found via manual testing
with a genuine non-root user: quarantine_files() must never crash the
detection pipeline just because the quarantine directory can't be created
or written to - it should log the failure and return gracefully instead.
"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.detectors.response import quarantine_files
from app.core.entropy import file_entropy


class TestQuarantinePermissionHandling(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_quarantine_dir_under_a_file_does_not_crash(self):
        # A quarantine_dir whose parent path component is actually a file
        # (not a directory) makes mkdir() fail with NotADirectoryError/OSError.
        blocking_file = self.tmpdir / "not_a_directory"
        blocking_file.write_text("x")
        bad_quarantine_dir = str(blocking_file / "quarantine")

        src = self.tmpdir / "evidence.txt"
        src.write_text("secret")

        # Must not raise.
        written = quarantine_files([str(src)], bad_quarantine_dir)
        self.assertEqual(written, [], "Should fail gracefully with an empty result, not raise")
        self.assertTrue(src.exists(), "Original file must be untouched even when quarantine fails")

    def test_missing_source_files_are_skipped_not_raised(self):
        written = quarantine_files(
            ["/no/such/file/one.txt", "/no/such/file/two.txt"],
            str(self.tmpdir / "quarantine"),
        )
        self.assertEqual(written, [])

    def test_mixed_valid_and_missing_sources(self):
        good = self.tmpdir / "real_evidence.txt"
        good.write_text("real content")
        written = quarantine_files(
            [str(good), "/no/such/file.txt"],
            str(self.tmpdir / "quarantine"),
        )
        self.assertEqual(len(written), 1)
        self.assertTrue(Path(written[0]).exists())
        # Original must still exist (copy, never move).
        self.assertTrue(good.exists())

    def test_empty_source_list_does_not_crash(self):
        written = quarantine_files([], str(self.tmpdir / "quarantine"))
        self.assertEqual(written, [])


class TestEntropyPermissionHandling(unittest.TestCase):
    def test_unreadable_path_returns_zero_not_raise(self):
        # We can't reliably deny read access to ourselves as root in CI, so
        # this test targets the code path directly: a path that raises
        # PermissionError on open() must be handled, which file_entropy's
        # except clause explicitly covers (see app/core/entropy.py).
        # A directory passed as a "file" reliably raises IsADirectoryError
        # (a subclass of OSError, which file_entropy also catches).
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(file_entropy(d), 0.0)


if __name__ == "__main__":
    unittest.main()
