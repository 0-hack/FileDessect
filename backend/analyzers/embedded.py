"""Embedded / hidden content analyzer.

Detects content that is not visible to a casual user:
  * executables or archives appended/embedded inside another file (polyglots,
    trailing data after an image's logical end, ZIPs hidden in PNGs, etc.);
  * data appended after the structural end of common formats (steganography
    and "stego-loader" tricks);
  * embedded scripts inside otherwise-benign documents.
"""
from __future__ import annotations

from .base import Analyzer, AnalyzerResult, FileContext, Severity
from .utils import shannon_entropy

# Signatures we consider "interesting" if found embedded *after* offset 0.
_EMBEDDED_SIGNATURES: list[tuple[bytes, str, Severity]] = [
    (b"MZ\x90\x00", "Windows PE executable", Severity.HIGH),
    (b"\x7fELF", "Linux ELF executable", Severity.HIGH),
    (b"PK\x03\x04", "ZIP archive", Severity.MEDIUM),
    (b"Rar!\x1a\x07", "RAR archive", Severity.MEDIUM),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", Severity.MEDIUM),
    (b"%PDF", "PDF document", Severity.MEDIUM),
    (b"<?php", "PHP script", Severity.HIGH),
    (b"<script", "HTML/JS script block", Severity.MEDIUM),
    (b"#!/bin/", "Unix shell script", Severity.MEDIUM),
    (b"powershell", "PowerShell command", Severity.MEDIUM),
]

# Markers for the *logical* end of a container format. Bytes beyond this point
# are "extra" data the viewing application normally ignores.
_FORMAT_END_MARKERS: dict[str, bytes] = {
    "png-image": b"IEND\xaeB`\x82",
    "gif-image": b"\x00\x3b",
    "jpeg-image": b"\xff\xd9",
}


class EmbeddedAnalyzer(Analyzer):
    name = "embedded"

    def run(self, ctx: FileContext) -> AnalyzerResult:
        result = self._result()
        data = ctx.data
        kind = ctx.metadata.get("file_kind")

        # --- Embedded foreign file signatures ------------------------------
        # Skip offset 0 (that's the file's own type) and skip ZIP-based formats
        # for the ZIP signature (docx/jar legitimately contain many PK headers).
        embedded = []
        is_zip_container = kind in {"zip-archive"} or ctx.metadata.get("extension") in {
            ".zip", ".jar", ".apk", ".docx", ".xlsx", ".pptx", ".jar", ".war",
        }
        for sig, label, sev in _EMBEDDED_SIGNATURES:
            if sig == b"PK\x03\x04" and is_zip_container:
                continue
            idx = data.find(sig, 1)
            if idx > 0:
                item = {"type": label, "offset": idx, "severity": sev, "validated": True}
                # A 4-byte ZIP local-file-header signature alone is weak — it
                # appears coincidentally in large binaries (notably Go/Rust). Only
                # treat it as a real embedded archive if an End-of-Central-Directory
                # record (PK\x05\x06) also exists after it.
                if sig == b"PK\x03\x04" and data.find(b"PK\x05\x06", idx) == -1:
                    item["severity"] = Severity.INFO
                    item["validated"] = False
                embedded.append(item)

        for item in embedded:
            if item["validated"]:
                desc = (
                    f"A {item['type']} signature was found at byte offset "
                    f"{item['offset']}, embedded within a file that presents "
                    f"itself as '{kind or ctx.metadata.get('mime', 'unknown')}'. "
                    "Hidden executable or archive content like this is not visible "
                    "to a normal user and is a strong indicator of a dropper or "
                    "polyglot payload."
                )
            else:
                desc = (
                    f"A {item['type']} signature byte sequence appears at offset "
                    f"{item['offset']}, but no valid archive structure (End-of-"
                    "Central-Directory) was found — this is most likely a "
                    "coincidental byte match in binary data rather than a real "
                    "embedded archive. Reported for completeness only."
                )
            result.add(
                id="embedded.foreign_signature",
                title=(
                    f"Embedded {item['type']} found inside file"
                    if item["validated"]
                    else f"Unvalidated {item['type']} signature (likely coincidental)"
                ),
                description=desc,
                severity=item["severity"],
                category="embedded",
                embedded_type=item["type"],
                offset=item["offset"],
                validated=item["validated"],
            )

        # --- Trailing / appended data after a format's logical end ---------
        end_marker = _FORMAT_END_MARKERS.get(kind or "")
        if end_marker:
            end_idx = data.rfind(end_marker)
            if end_idx != -1:
                trailing_start = end_idx + len(end_marker)
                trailing = data[trailing_start:]
                # Ignore a few bytes of benign padding.
                if len(trailing) > 64:
                    trail_entropy = shannon_entropy(trailing)
                    result.add(
                        id="embedded.trailing_data",
                        title="Hidden data appended after end of file",
                        description=(
                            f"{len(trailing)} bytes follow the logical end of this "
                            f"{kind}. Image/media viewers ignore this region, so it "
                            "is a common place to hide payloads or exfiltrated data "
                            f"(steganography). Entropy of the hidden region is "
                            f"{trail_entropy:.2f}/8.0."
                        ),
                        severity=Severity.MEDIUM if trail_entropy < 7.0 else Severity.HIGH,
                        category="embedded",
                        trailing_bytes=len(trailing),
                        offset=trailing_start,
                        entropy=round(trail_entropy, 3),
                    )

        return result
