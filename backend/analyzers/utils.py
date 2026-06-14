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


def char_entropy(s: str) -> float:
    """Shannon entropy of a string's characters (used to tell real base64 from
    concatenated word/symbol tables)."""
    return shannon_entropy(s.encode("utf-8", "ignore"))


def looks_like_base64(s: str) -> bool:
    """Heuristic: is ``s`` a genuine base64-encoded blob (not a word/symbol run)?

    Long runs of ``[A-Za-z0-9]`` also occur in densely-packed string tables
    (e.g. Go's runtime/timezone/Unicode tables), which are NOT base64. Real
    base64 of binary data almost always contains ``+``/``/`` or ``=`` padding
    and has high per-character entropy; word tables do not.
    """
    s = s.strip()
    if len(s) < 32:
        return False
    has_specials = ("+" in s) or ("/" in s) or s.endswith("=")
    ent = char_entropy(s)
    if has_specials:
        return ent >= 4.0
    # Pure [A-Za-z0-9]: only base64 if it looks random (high entropy), which
    # excludes dictionary-word and hex-digit tables.
    return ent >= 4.8


# Strong markers of statically-linked managed runtimes. These binaries embed
# their runtime (and large symbol/string tables), which trips naive heuristics —
# detecting them lets analyzers suppress the resulting false positives.
_GO_MARKERS = (
    b"Go buildinf:",
    b"go.buildid",
    b"runtime.morestack",
    b"runtime.gopanic",
    b"runtime.gcWriteBarrier",
    b"runtime.goexit",
)
_RUST_MARKERS = (
    b"/rustc/",
    b"RUST_BACKTRACE",
    b"cargo/registry",
    b"library/std/src/",
    b"rust_eh_personality",
)


def detect_runtime(data: bytes) -> str | None:
    """Return 'go', 'rust', or None for the binary's toolchain runtime."""
    if any(m in data for m in _GO_MARKERS):
        return "go"
    if any(m in data for m in _RUST_MARKERS):
        return "rust"
    return None


# IANA-style top-level-domain knowledge: a domain candidate is only accepted if
# its final label is a real TLD. This removes the bulk of false positives where
# code symbols (e.g. ``reflect.Value.CanInterface``, ``uuid.FromString``) look
# domain-shaped. Covers common gTLDs/new-gTLDs and the full ccTLD set.
_GTLDS = {
    "com", "net", "org", "info", "biz", "io", "co", "ai", "app", "dev", "xyz",
    "online", "site", "top", "club", "shop", "store", "tech", "cloud", "me",
    "tv", "cc", "ws", "name", "pro", "mobi", "asia", "int", "gov", "edu", "mil",
    "arpa", "blog", "page", "link", "live", "work", "world", "space", "website",
    "host", "press", "news", "media", "email", "digital", "network", "systems",
    "solutions", "services", "group", "team", "center", "zone", "life", "today",
    "fun", "run", "download", "stream", "win", "men", "loan", "date", "racing",
    "party", "trade", "science", "review", "country", "gdn", "finance", "money",
    "bank", "market", "exchange", "capital", "ventures", "fund", "partners",
    "agency", "studio", "design", "art", "video", "audio", "games", "game",
    "software", "codes", "technology", "tools", "wiki", "guru", "ninja",
    "expert", "consulting", "management", "marketing", "careers", "jobs",
    "academy", "school", "university", "training", "courses", "support", "help",
    "care", "health", "clinic", "fit", "fitness", "beauty", "travel", "hotel",
    "restaurant", "cafe", "bar", "pizza", "food", "kitchen", "coffee", "wine",
    "shopping", "deals", "sale", "gift", "gifts", "toys", "fashion", "clothing",
    "shoes", "jewelry", "luxury", "boutique", "crypto", "global", "one", "vip",
    "plus", "pics", "photo", "photography", "gallery", "cam", "chat", "social",
    "dating", "tube", "fyi", "ltd", "inc", "llc", "company", "enterprises",
    "holdings", "industries", "international", "africa", "nyc", "london",
    "berlin", "tokyo", "paris", "moscow", "app", "web",
}
_CCTLDS = {
    "ac", "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "aq", "ar", "as",
    "at", "au", "aw", "ax", "az", "ba", "bb", "bd", "be", "bf", "bg", "bh",
    "bi", "bj", "bm", "bn", "bo", "br", "bs", "bt", "bw", "by", "bz", "ca",
    "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn", "co", "cr",
    "cu", "cv", "cw", "cx", "cy", "cz", "de", "dj", "dk", "dm", "do", "dz",
    "ec", "ee", "eg", "er", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo",
    "fr", "ga", "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp",
    "gq", "gr", "gs", "gt", "gu", "gw", "gy", "hk", "hm", "hn", "hr", "ht",
    "hu", "id", "ie", "il", "im", "in", "io", "iq", "ir", "is", "it", "je",
    "jm", "jo", "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw",
    "ky", "kz", "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv",
    "ly", "ma", "mc", "md", "me", "mg", "mh", "mk", "ml", "mm", "mn", "mo",
    "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw", "mx", "my", "mz", "na",
    "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om",
    "pa", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt",
    "pw", "py", "qa", "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd",
    "se", "sg", "sh", "si", "sk", "sl", "sm", "sn", "so", "sr", "ss", "st",
    "su", "sv", "sx", "sy", "sz", "tc", "td", "tf", "tg", "th", "tj", "tk",
    "tl", "tm", "tn", "to", "tr", "tt", "tv", "tw", "tz", "ua", "ug", "uk",
    "us", "uy", "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ws",
    "ye", "yt", "za", "zm", "zw",
}
VALID_TLDS = frozenset(_GTLDS | _CCTLDS)


def is_valid_domain(domain: str) -> bool:
    """True if ``domain``'s final label is a recognised TLD."""
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return False
    return parts[-1] in VALID_TLDS


def human_size(num: int) -> str:
    size = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
