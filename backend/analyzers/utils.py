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


_WORD_RE = re.compile(r"[A-Za-z]{2,}")
_PATHISH_RE = re.compile(r"[\\/][A-Za-z0-9._-]+[\\/]")


def is_human_readable(s: str, min_len: int = 4) -> bool:
    """Heuristic: does ``s`` look like meaningful human-readable text?

    Filters out the random-looking byte sequences that dominate raw `strings`
    output (mangled symbols, base64 fragments, binary noise) so the report can
    highlight only strings a person would actually find informative.
    """
    s = s.strip()
    if len(s) < min_len:
        return False
    letters = sum(c.isalpha() for c in s)
    if letters == 0:
        return False
    alpha_ratio = letters / len(s)
    # Low alphabetic ratio: only keep if it clearly looks like a path or URL.
    if alpha_ratio < 0.45:
        low = s.lower()
        if _PATHISH_RE.search(s) or low.startswith(("http", "www.", "c:\\", "/usr", "/lib", "/tmp", "/users")):
            return True
        return False
    if not any(c in "aeiouAEIOU" for c in s):
        return False  # consonant-only soup
    # Reject low-diversity repetition like "aaaaaa" or "======".
    if len(set(s)) / len(s) < 0.3:
        return False
    words = _WORD_RE.findall(s)
    longest = max((len(w) for w in words), default=0)
    # Needs at least one real-ish word, or a multi-token phrase.
    return longest >= 3 or " " in s


def human_size(num: int) -> str:
    size = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
