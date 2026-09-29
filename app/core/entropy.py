"""
Shannon entropy calculation.

Ransomware encryption turns structured file content into what looks like
random noise. Shannon entropy measures exactly that: how unpredictable the
byte values in a chunk of data are.

  - entropy ~= 0   -> totally predictable (e.g. a file of all zero bytes)
  - entropy ~= 4-5 -> typical structured text/office documents
  - entropy ~= 8.0 -> totally random (encrypted or compressed data)

We only read the first SAMPLE_SIZE bytes of a file so this stays fast even
on large files - the first 64KB is plenty to tell "structured" from "random".
"""
from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

SAMPLE_SIZE = 64 * 1024  # 64 KB


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of `data` in bits per byte, range 0.0-8.0.

    Empty input has no information content, so we define its entropy as 0.0
    rather than raising - callers (e.g. a just-created empty file) shouldn't
    have to special-case this.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def file_entropy(path: str | Path, sample_size: int = SAMPLE_SIZE) -> float:
    """Read up to `sample_size` bytes from the start of a file and return
    its Shannon entropy. Returns 0.0 for missing/unreadable files rather than
    raising, since a file can legitimately disappear between event and read
    (e.g. a temp file that gets deleted immediately after being written)."""
    try:
        with open(path, "rb") as f:
            data = f.read(sample_size)
    except (FileNotFoundError, PermissionError, OSError):
        return 0.0
    return shannon_entropy(data)
