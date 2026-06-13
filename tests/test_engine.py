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
                "identity", "analyzers", "scoring"):
        assert key in report


def test_scoring_breakdown_matches_findings():
    # PE-looking content with several keyword hits to generate findings.
    data = b"MZ" + b"\x00" * 64 + b"powershell -enc DownloadString Invoke-Expression"
    report = analyze(data, "x.bin")
    sc = report["scoring"]
    # Breakdown has one row per finding and the weights sum to the risk score.
    assert len(sc["breakdown"]) == len(report["findings"])
    assert sum(b["weight"] for b in sc["breakdown"]) == report["risk_score"]
    assert sc["reason"]
    assert sc["thresholds"] == {"suspicious": 30, "malicious": 90}


def test_scoring_model_is_self_consistent():
    from backend.engine import scoring_model

    model = scoring_model()
    weights = {s["severity"]: s["weight"] for s in model["severity_weights"]}
    assert weights == {"info": 0, "low": 10, "medium": 30, "high": 60, "critical": 100}
    assert len(model["verdict_thresholds"]) == 3
    assert model["hard_overrides"]


def test_full_iocs_included():
    data = b"visit http://evil.example.com/payload and http://c2.test/beacon now"
    report = analyze(data, "ioc.txt")
    content = next(a for a in report["analyzers"] if a["analyzer"] == "content")
    urls = content["metadata"]["urls"]
    assert any("evil.example.com" in u for u in urls)
    assert content["metadata"]["url_count"] == len(urls)
