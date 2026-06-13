"""Small shared helpers used by multiple analyzers."""
from __future__ import annotations

import math
import re
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of ``data`` in bits per byte (0.0 - 8.0).

    High entropy (>~7.2) typically indicates compression or encryption and is a
    classic marker of packed or obfuscated content.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# Printable ASCII string extraction (mirrors GNU `strings` default behaviour).
_ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}")
# Wide (UTF-16LE) strings, common in Windows binaries.
_WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}")


def extract_strings(data: bytes, min_len: int = 4, limit: int = 20000) -> list[str]:
    """Extract printable ASCII and UTF-16LE strings from a byte buffer."""
    results: list[str] = []
    ascii_re = re.compile(_ASCII_RE.pattern % min_len)
    wide_re = re.compile(_WIDE_RE.pattern % min_len)

    for match in ascii_re.finditer(data):
        results.append(match.group().decode("ascii", "ignore"))
        if len(results) >= limit:
            return results
    for match in wide_re.finditer(data):
        results.append(match.group().decode("utf-16-le", "ignore"))
        if len(results) >= limit:
            break
    return results


def human_size(num: int) -> str:
    size = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
