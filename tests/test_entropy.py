"""Unit tests for Shannon entropy - pure logic, no I/O dependencies needed
beyond a temp file for file_entropy()."""
import os
import tempfile
import unittest

from app.core.entropy import shannon_entropy, file_entropy


class TestShannonEntropy(unittest.TestCase):
    def test_empty_input_is_zero(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_all_zero_bytes_is_zero_entropy(self):
        self.assertEqual(shannon_entropy(bytes(1000)), 0.0)

    def test_repetitive_text_has_low_entropy(self):
        data = b"hello world " * 500
        e = shannon_entropy(data)
        self.assertLess(e, 5.0)

    def test_random_bytes_have_high_entropy(self):
        data = os.urandom(50_000)
        e = shannon_entropy(data)
        self.assertGreater(e, 7.5)

    def test_entropy_is_bounded_0_to_8(self):
        for data in (b"", bytes(100), b"abc" * 1000, os.urandom(10_000)):
            e = shannon_entropy(data)
            self.assertGreaterEqual(e, 0.0)
            self.assertLessEqual(e, 8.0)

    def test_single_repeated_byte_value_has_zero_entropy(self):
        # Every byte identical -> completely predictable -> 0 entropy,
        # regardless of which byte value it is.
        self.assertEqual(shannon_entropy(b"\xff" * 5000), 0.0)


class TestFileEntropy(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def _write(self, name: str, data: bytes) -> str:
        path = os.path.join(self.tmpdir, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def test_text_file_has_low_entropy(self):
        path = self._write("a.txt", b"normal document content " * 100)
        self.assertLess(file_entropy(path), 5.0)

    def test_random_file_has_high_entropy(self):
        path = self._write("b.bin", os.urandom(20_000))
        self.assertGreater(file_entropy(path), 7.5)

    def test_missing_file_returns_zero_not_raises(self):
        self.assertEqual(file_entropy("/no/such/file/at/all"), 0.0)

    def test_sampling_only_reads_first_chunk(self):
        # A big low-entropy file with a random tail should still read as
        # low entropy, since only the first 64KB is sampled.
        data = (b"a" * (100 * 1024)) + os.urandom(50_000)
        path = self._write("c.bin", data)
        self.assertLess(file_entropy(path), 2.0)


if __name__ == "__main__":
    unittest.main()
