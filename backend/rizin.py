"""Rizin engine integration — the open-source RE engine that powers Cutter.

This module drives the ``rizin`` command-line engine (the same core the
[Cutter](https://cutter.re) GUI is built on) to provide deep, function-level
analysis of native binaries that the always-available Capstone path cannot:

  * a full function listing (names, addresses, sizes, instruction counts);
  * per-function disassembly with addresses, bytes and operands;
  * cross-references from *dangerous imports* to the functions that call them —
    i.e. "where in the code is ``CreateRemoteThread`` actually used?";
  * decompilation, when a decompiler plugin (``rz-ghidra``) is installed;
  * a ready-to-run Cutter/Rizin session script so the analyst can continue
    interactive debugging in the real Cutter GUI.

Everything degrades gracefully: when the ``rizin`` binary is absent the public
helpers return ``None`` and callers fall back to Capstone. No third-party Python
package is required — only the ``rizin`` executable, driven over its ``-c``
command interface with marker-delimited output so several queries share a single
process (one load + one analysis pass).
"""
from __future__ import annotations

import base64
import json
import re
import shutil
import subprocess
from functools import lru_cache
from typing import Any

# A line that separates one command's output from the next in a batched run.
# We emit it with rizin's ``?e`` (echo) command between sub-commands. The marker
# deliberately uses only ``[A-Za-z0-9_]`` — rizin/r2 treat ``< > | ~ @ ; #`` and
# backticks as redirection / piping / seek operators, so a marker containing any
# of them would be swallowed by the command parser instead of printed.
_MARKER_PREFIX = "FDxMARKERx"
_MARKER_SUFFIX = "xENDx"
_MARKER_RE = re.compile(
    rf"^{_MARKER_PREFIX}(.+?){_MARKER_SUFFIX}\s*$", re.M
)

# Imported symbols that are interesting to locate in the code, used for ELF /
# Mach-O binaries where we have no PE capability map to draw on. Kept small and
# behaviour-focused (process injection, exec, networking, crypto, hooking).
_DANGEROUS_SYMBOLS = {
    # process / code injection & execution
    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
    "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
    "ptrace", "execve", "execl", "execvp", "system", "popen", "fork",
    "mprotect", "mmap", "dlopen", "dlsym",
    # networking
    "connect", "socket", "send", "recv", "WSAStartup", "InternetOpenA",
    "InternetOpenUrlA", "URLDownloadToFileA", "HttpSendRequestA",
    # hooking / spying
    "SetWindowsHookExA", "GetAsyncKeyState",
    # crypto
    "CryptEncrypt", "EVP_EncryptInit", "EVP_EncryptInit_ex",
}


@lru_cache(maxsize=1)
def rizin_binary() -> str | None:
    """Path to the ``rizin`` (or legacy ``rz``) executable, if installed."""
    return shutil.which("rizin") or shutil.which("rz")


def available() -> bool:
    return rizin_binary() is not None


@lru_cache(maxsize=1)
def version() -> str | None:
    rz = rizin_binary()
    if not rz:
        return None
    try:
        proc = subprocess.run([rz, "-v"], capture_output=True, timeout=10, check=False)
        first = proc.stdout.decode("utf-8", "ignore").splitlines()
        return first[0].strip() if first else None
    except (OSError, subprocess.SubprocessError):
        return None


# --------------------------------------------------------------------------- #
# Low-level batched command runner.
# --------------------------------------------------------------------------- #
def _batch(path: str, commands: list[tuple[str, str]], timeout: int) -> dict[str, str] | None:
    """Run several rizin commands in one process; return {key: raw_output}.

    ``commands`` is an ordered list of ``(key, rizin_command)``. Each command's
    output is captured under its key. The first command should perform analysis
    (e.g. ``aaa``); its (noisy) output is captured under its own key and ignored.
    """
    rz = rizin_binary()
    if not rz:
        return None
    script_parts: list[str] = []
    for key, cmd in commands:
        script_parts.append(f"?e {_MARKER_PREFIX}{key}{_MARKER_SUFFIX}")
        script_parts.append(cmd)
    script = "; ".join(script_parts)
    try:
        proc = subprocess.run(
            [rz, "-q", "-e", "scr.color=0", "-e", "scr.interactive=false",
             "-c", script, path],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    return _split_markers(proc.stdout.decode("utf-8", "ignore"))


def _split_markers(out: str) -> dict[str, str]:
    result: dict[str, str] = {}
    matches = list(_MARKER_RE.finditer(out))
    for i, m in enumerate(matches):
        key = m.group(1)
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(out)
        result[key] = out[start:end].strip()
    return result


def _loadj(chunk: str | None) -> Any:
    """Best-effort JSON parse of a command chunk (rizin JSON commands)."""
    if not chunk:
        return None
    try:
        return json.loads(chunk)
    except (json.JSONDecodeError, ValueError):
        # Some builds prepend warnings; try to recover the first JSON value.
        for opener, closer in (("[", "]"), ("{", "}")):
            a, b = chunk.find(opener), chunk.rfind(closer)
            if 0 <= a < b:
                try:
                    return json.loads(chunk[a : b + 1])
                except (json.JSONDecodeError, ValueError):
                    pass
    return None


def _decode_comment(value: Any) -> str | None:
    """rizin sometimes base64-encodes comments in JSON output."""
    if not isinstance(value, str) or not value:
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
        text = decoded.decode("utf-8", "ignore").strip()
        if text and text.isprintable():
            return text
    except (ValueError, UnicodeError):
        pass
    return value if value.isprintable() else None


def _normalize_ops(pdfj: Any) -> dict[str, Any] | None:
    """Turn a ``pdfj`` (disassemble-function-as-JSON) result into our shape."""
    if not isinstance(pdfj, dict):
        return None
    ops_in = pdfj.get("ops") or []
    ops: list[dict[str, Any]] = []
    for op in ops_in:
        if not isinstance(op, dict):
            continue
        addr = op.get("offset")
        ops.append(
            {
                "addr": f"0x{addr:x}" if isinstance(addr, int) else None,
                "bytes": op.get("bytes"),
                "text": op.get("disasm") or op.get("opcode") or "",
                "type": op.get("type"),
                "comment": _decode_comment(op.get("comment")),
            }
        )
    if not ops:
        return None
    addr = pdfj.get("addr") or pdfj.get("offset")
    return {
        "name": pdfj.get("name"),
        "addr": f"0x{addr:x}" if isinstance(addr, int) else None,
        "size": pdfj.get("size"),
        "ops": ops,
    }


# --------------------------------------------------------------------------- #
# Stateless deep analysis (used by the `cutter` analyzer during /api/analyze).
# --------------------------------------------------------------------------- #
def deep_analysis(
    path: str,
    *,
    filename: str = "sample.bin",
    dangerous_imports: list[str] | None = None,
    max_functions: int = 250,
    max_disasm_functions: int = 8,
    decompile: bool = True,
    timeout: int = 90,
) -> dict[str, Any] | None:
    """Run a full Rizin pass over ``path`` and return a structured report.

    Returns ``None`` when rizin is unavailable or produced nothing usable.
    """
    if not available():
        return None

    # Pass 1: analyse, then pull the function list, info, imports and the xrefs
    # for the dangerous imports we already know about — all in one process.
    wanted = _dangerous_targets(dangerous_imports)
    cmds: list[tuple[str, str]] = [
        ("_setup", "e anal.timeout=30; e scr.html=false; aaa"),
        ("functions", "aflj"),
        ("info", "ij"),
        ("entrypoints", "iej"),
        ("imports", "iij"),
        ("disasm_entry0", "pdfj @ entry0"),
        ("disasm_main", "pdfj @ main"),
    ]
    for sym in wanted:
        cmds.append((f"xref_{sym}", f"axtj @ sym.imp.{sym}"))
    if decompile:
        cmds.append(("decprobe", "pdg @ entry0"))

    raw = _batch(path, cmds, timeout)
    if not raw:
        return None

    funcs_json = _loadj(raw.get("functions")) or []
    if not isinstance(funcs_json, list):
        funcs_json = []
    info = _loadj(raw.get("info")) or {}
    bin_info = info.get("bin", {}) if isinstance(info, dict) else {}

    functions = [
        {
            "name": f.get("name"),
            "addr": f"0x{f.get('offset'):x}" if isinstance(f.get("offset"), int) else None,
            "size": f.get("size"),
            "ninstrs": f.get("ninstrs") or f.get("ninstr") or f.get("nins"),
            "nargs": f.get("nargs"),
        }
        for f in funcs_json
        if isinstance(f, dict)
    ][:max_functions]

    # Import cross-references: import name -> list of calling sites.
    import_xrefs: list[dict[str, Any]] = []
    caller_addrs: dict[str, int] = {}  # fcn_name -> fcn_addr, for pass-2 disasm
    for sym in wanted:
        xj = _loadj(raw.get(f"xref_{sym}"))
        if not isinstance(xj, list) or not xj:
            continue
        callers = []
        for x in xj:
            if not isinstance(x, dict):
                continue
            frm = x.get("from")
            fcn_name = x.get("fcn_name")
            fcn_addr = x.get("fcn_addr")
            callers.append(
                {
                    "from": f"0x{frm:x}" if isinstance(frm, int) else None,
                    "fcn_name": fcn_name,
                    "fcn_addr": f"0x{fcn_addr:x}" if isinstance(fcn_addr, int) else None,
                    "opcode": x.get("opcode"),
                }
            )
            if fcn_name and isinstance(fcn_addr, int):
                caller_addrs.setdefault(fcn_name, fcn_addr)
        if callers:
            import_xrefs.append({"import": sym, "callers": callers})

    # Disassembly we always have: entry0 and main.
    disassembly: dict[str, Any] = {}
    for key, label in (("disasm_entry0", "entry0"), ("disasm_main", "main")):
        norm = _normalize_ops(_loadj(raw.get(key)))
        if norm:
            disassembly[label] = norm

    # Decompiler availability (did `pdg @ entry0` yield code, or an error?).
    decompiler = None
    decompilation: dict[str, str] = {}
    dec_probe = raw.get("decprobe", "")
    if decompile and dec_probe and not _looks_like_rz_error(dec_probe):
        decompiler = "rz-ghidra"
        decompilation["entry0"] = dec_probe

    # Pass 2 (optional): disassemble the functions that call dangerous imports,
    # so the analyst sees the actual call sites, not just the entry point.
    extra_targets = list(caller_addrs.items())[:max_disasm_functions]
    if extra_targets:
        cmds2: list[tuple[str, str]] = [("_setup", "e anal.timeout=30; aaa")]
        for name, addr in extra_targets:
            cmds2.append((f"d_{addr:x}", f"pdfj @ 0x{addr:x}"))
            if decompiler:
                cmds2.append((f"c_{addr:x}", f"pdg @ 0x{addr:x}"))
        raw2 = _batch(path, cmds2, timeout) or {}
        for name, addr in extra_targets:
            norm = _normalize_ops(_loadj(raw2.get(f"d_{addr:x}")))
            if norm:
                disassembly[name] = norm
            ctext = raw2.get(f"c_{addr:x}")
            if decompiler and ctext and not _looks_like_rz_error(ctext):
                decompilation[name] = ctext

    report = {
        "engine": version() or "rizin",
        "decompiler": decompiler,
        "function_count": len(funcs_json),
        "functions": functions,
        "info": {
            "arch": bin_info.get("arch"),
            "bits": bin_info.get("bits"),
            "class": bin_info.get("class"),
            "machine": bin_info.get("machine"),
            "os": bin_info.get("os"),
            "compiler": bin_info.get("compiler"),
            "language": bin_info.get("lang"),
            "baddr": bin_info.get("baddr"),
        },
        "entrypoints": _entrypoints(_loadj(raw.get("entrypoints"))),
        "import_xrefs": import_xrefs,
        "disassembly": disassembly,
        "decompilation": decompilation,
        "session_script": build_session_script(filename, wanted),
    }
    return report


def _dangerous_targets(dangerous_imports: list[str] | None) -> list[str]:
    """Sanitised, de-duplicated list of import names to cross-reference."""
    names = list(dangerous_imports or [])
    if not names:
        names = sorted(_DANGEROUS_SYMBOLS)
    out: list[str] = []
    seen: set[str] = set()
    for n in names:
        safe = re.sub(r"[^A-Za-z0-9_]", "", n or "")
        if safe and safe not in seen:
            seen.add(safe)
            out.append(safe)
        if len(out) >= 40:
            break
    return out


def _entrypoints(ej: Any) -> list[dict[str, Any]]:
    if not isinstance(ej, list):
        return []
    out = []
    for e in ej:
        if not isinstance(e, dict):
            continue
        v = e.get("vaddr")
        out.append({"vaddr": f"0x{v:x}" if isinstance(v, int) else None, "type": e.get("type")})
    return out


def _looks_like_rz_error(text: str) -> bool:
    t = text.strip().lower()
    if not t:
        return True
    return t.startswith(("error", "cannot", "unknown command", "no decompiler"))


# --------------------------------------------------------------------------- #
# Interactive helpers (used by the opt-in session endpoints).
# --------------------------------------------------------------------------- #
def function_list(path: str, *, max_functions: int = 1000, timeout: int = 60):
    if not available():
        return None
    raw = _batch(path, [("_setup", "e anal.timeout=30; aaa"), ("functions", "aflj")], timeout)
    if not raw:
        return None
    funcs = _loadj(raw.get("functions")) or []
    if not isinstance(funcs, list):
        return None
    return [
        {
            "name": f.get("name"),
            "addr": f"0x{f.get('offset'):x}" if isinstance(f.get("offset"), int) else None,
            "size": f.get("size"),
            "ninstrs": f.get("ninstrs") or f.get("ninstr") or f.get("nins"),
        }
        for f in funcs
        if isinstance(f, dict)
    ][:max_functions]


def disassemble(path: str, target: str, *, timeout: int = 60):
    """Disassemble a single function by name (e.g. ``main``) or ``0x``-address."""
    seek = _safe_seek(target)
    if seek is None or not available():
        return None
    raw = _batch(path, [("_setup", "e anal.timeout=30; aaa"), ("d", f"pdfj @ {seek}")], timeout)
    if not raw:
        return None
    return _normalize_ops(_loadj(raw.get("d")))


def decompile(path: str, target: str, *, timeout: int = 90):
    seek = _safe_seek(target)
    if seek is None or not available():
        return None
    raw = _batch(path, [("_setup", "e anal.timeout=30; aaa"), ("c", f"pdg @ {seek}")], timeout)
    if not raw:
        return None
    code = raw.get("c", "")
    if not code or _looks_like_rz_error(code):
        return None
    return code


def _safe_seek(target: str) -> str | None:
    """Validate a seek target so it cannot inject extra rizin commands."""
    if not target:
        return None
    t = target.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]+", t):
        return t
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,127}", t):
        return t
    return None


# --------------------------------------------------------------------------- #
# Cutter/Rizin session-script generation.
# --------------------------------------------------------------------------- #
def build_session_script(filename: str, dangerous_imports: list[str]) -> str:
    """A ready-to-run rizin script the analyst can open in Cutter.

    Cutter is a GUI and cannot run inside this sandbox, but it loads the same
    rizin engine — so we hand the user a script that reproduces our analysis and
    jumps straight to the interesting call sites for hands-on debugging.
    """
    safe_name = re.sub(r"[\r\n]", " ", filename or "sample.bin")
    lines = [
        f"# FileDessect -> Cutter / Rizin session for: {safe_name}",
        "#",
        "# How to use:",
        f"#   rizin -i filedessect_session.rz '{safe_name}'",
        "#   ...or load the file in Cutter and paste these into the console (`;` tab).",
        "#",
        "# Full auto-analysis (functions, xrefs, strings):",
        "e scr.color=2",
        "aaa",
        "",
        "# Land on the entry point and show it:",
        "s entry0",
        "pdf @ entry0",
        "",
    ]
    if dangerous_imports:
        lines.append("# Jump to the call sites of dangerous imports flagged by FileDessect:")
        for sym in dangerous_imports[:20]:
            lines.append(f"axt @ sym.imp.{sym}   # who calls {sym}?")
        lines.append("")
    lines += [
        "# Useful interactive commands once inside:",
        "#   afl            list all functions",
        "#   pdf @ <fcn>    disassemble a function",
        "#   pdg @ <fcn>    decompile (needs rz-ghidra)",
        "#   axt @ <addr>   cross-references to an address",
        "#   VV             visual graph mode (rizin shell)",
        "",
    ]
    return "\n".join(lines)
