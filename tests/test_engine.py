"""Smoke / behaviour tests for the FileDessect engine.

These run without the optional native dependencies (libmagic, yara, pefile,
oletools); analyzers degrade gracefully, and the engine still produces a
coherent verdict from the pure-Python analyzers (identity, content, embedded).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.engine import Engine  # noqa: E402


def analyze(data: bytes, filename: str = "sample.bin") -> dict:
    return Engine().analyze(path="/tmp/x", filename=filename, data=data)


def test_clean_text_file_is_clean():
    report = analyze(b"Hello, this is a perfectly ordinary text file.\n" * 5, "notes.txt")
    assert report["verdict"] == "clean"
    assert report["identity"]["hashes"]["sha256"]
    assert report["risk_score"] < 30


def test_embedded_pe_inside_image_is_flagged():
    # PNG header + IEND + an embedded MZ/PE header appended after it.
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64 + b"IEND\xaeB`\x82"
    payload = png + b"MZ\x90\x00\x03\x00\x00\x00" + b"This program cannot be run" + b"\x00" * 200
    report = analyze(payload, "picture.png")
    finding_ids = {f["id"] for f in report["findings"]}
    assert "embedded.foreign_signature" in finding_ids
    assert report["verdict"] in {"suspicious", "malicious"}


def test_double_extension_is_high_severity():
    report = analyze(b"MZ" + b"\x00" * 100, "invoice.pdf.exe")
    finding_ids = {f["id"] for f in report["findings"]}
    assert "identity.double_extension" in finding_ids


def test_suspicious_powershell_strings_escalate():
    data = (
        b"powershell -nop -w hidden -EncodedCommand SQBFAFgA "
        b"DownloadString Invoke-Expression VirtualAlloc CreateRemoteThread"
    )
    report = analyze(data, "loader.txt")
    assert report["verdict"] in {"suspicious", "malicious"}
    assert any(f["id"] == "content.suspicious_api" for f in report["findings"])


def test_report_structure():
    report = analyze(b"abc", "a.txt")
    for key in ("verdict", "risk_score", "explanation", "summary", "findings",
                "identity", "analyzers"):
        assert key in report
