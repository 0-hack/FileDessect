"""PE (Windows executable) reverse-engineering analyzer.

Parses the PE structure to help a user understand *what a compiled binary
does* without running it: imported APIs (its capabilities), section layout and
entropy (packing), the compile timestamp, suspicious section names, presence
of a digital signature, TLS callbacks, and more.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .base import Analyzer, AnalyzerResult, FileContext, Severity
from .utils import shannon_entropy

try:
    import pefile  # type: ignore

    _HAVE_PEFILE = True
except Exception:  # pragma: no cover
    _HAVE_PEFILE = False

# Imported functions grouped into behavioural capabilities. This is what turns
# a raw import list into an understandable "this program can ..." summary.
_CAPABILITY_MAP: dict[str, tuple[str, Severity]] = {
    # networking
    "WSAStartup": ("Network communication", Severity.LOW),
    "connect": ("Network communication", Severity.LOW),
    "InternetOpenA": ("HTTP/Internet access", Severity.LOW),
    "InternetOpenUrlA": ("HTTP/Internet access", Severity.LOW),
    "HttpSendRequestA": ("HTTP/Internet access", Severity.LOW),
    "URLDownloadToFileA": ("Download files from the internet", Severity.MEDIUM),
    # process / injection
    "CreateRemoteThread": ("Inject code into other processes", Severity.HIGH),
    "WriteProcessMemory": ("Inject code into other processes", Severity.HIGH),
    "VirtualAllocEx": ("Inject code into other processes", Severity.MEDIUM),
    "NtUnmapViewOfSection": ("Process hollowing", Severity.HIGH),
    "OpenProcess": ("Access other processes", Severity.LOW),
    "CreateProcessA": ("Launch other programs", Severity.LOW),
    "ShellExecuteA": ("Launch other programs", Severity.LOW),
    "WinExec": ("Launch other programs", Severity.LOW),
    # persistence / registry
    "RegSetValueExA": ("Modify the registry (persistence)", Severity.MEDIUM),
    "RegCreateKeyExA": ("Modify the registry (persistence)", Severity.LOW),
    # hooking / spying
    "SetWindowsHookExA": ("Install hooks / keylogging", Severity.HIGH),
    "GetAsyncKeyState": ("Capture keystrokes", Severity.HIGH),
    "GetKeyState": ("Capture keystrokes", Severity.MEDIUM),
    # crypto (ransomware)
    "CryptEncrypt": ("Encrypt data (possible ransomware)", Severity.MEDIUM),
    "CryptAcquireContextA": ("Use cryptographic APIs", Severity.LOW),
    # anti-analysis
    "IsDebuggerPresent": ("Detect debuggers (anti-analysis)", Severity.MEDIUM),
    "CheckRemoteDebuggerPresent": ("Detect debuggers (anti-analysis)", Severity.MEDIUM),
    "GetTickCount": ("Timing-based sandbox evasion", Severity.LOW),
    # privilege
    "AdjustTokenPrivileges": ("Adjust privileges", Severity.MEDIUM),
    "LookupPrivilegeValueA": ("Adjust privileges", Severity.LOW),
    # dynamic resolution (evasion)
    "LoadLibraryA": ("Dynamically load libraries", Severity.LOW),
    "GetProcAddress": ("Dynamically resolve APIs (evasion)", Severity.LOW),
    # file system
    "CreateFileA": ("File system access", Severity.INFO),
    "FindFirstFileA": ("Enumerate files", Severity.INFO),
}

# Section names that legitimate compilers never produce — typical of packers.
_KNOWN_PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX",
    ".aspack": "ASPack", ".adata": "ASPack",
    ".themida": "Themida", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".petite": "Petite", "MEW": "MEW", "FSG!": "FSG",
    ".nsp0": "NsPack", ".enigma1": "Enigma",
}


class PEAnalyzer(Analyzer):
    name = "pe"

    def applies(self, ctx: FileContext) -> bool:
        return ctx.data[:2] == b"MZ"

    def run(self, ctx: FileContext) -> AnalyzerResult:
        result = self._result()
        if not _HAVE_PEFILE:
            result.error = "pefile not installed; PE analysis unavailable"
            return result

        try:
            pe = pefile.PE(data=ctx.data, fast_load=True)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
                ]
            )
        except Exception as exc:  # malformed PE
            result.error = f"Could not parse PE: {exc}"
            return result

        meta: dict = {}
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        machine = pe.FILE_HEADER.Machine
        meta["type"] = "DLL" if is_dll else "EXE"
        meta["machine"] = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM",
                            0xaa64: "ARM64"}.get(machine, hex(machine))

        # Compile timestamp.
        ts = pe.FILE_HEADER.TimeDateStamp
        if ts:
            try:
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                meta["compile_time"] = dt.isoformat()
                if dt.year < 2000 or dt > datetime.now(timezone.utc):
                    result.add(
                        id="pe.suspicious_timestamp",
                        title="Implausible compile timestamp",
                        description=(
                            f"The PE compile timestamp ({dt.isoformat()}) is in the "
                            "future or implausibly old, which often means it was "
                            "deliberately faked to hinder analysis."
                        ),
                        severity=Severity.LOW,
                        category="executable",
                        timestamp=dt.isoformat(),
                    )
            except (OSError, ValueError, OverflowError):
                meta["compile_time"] = None

        self._analyze_sections(pe, result, meta)
        self._analyze_imports(pe, result, meta)
        self._analyze_signature(pe, result, meta)
        self._analyze_tls(pe, result, meta)

        # Share the dangerous imports with later analyzers (notably `cutter`,
        # which cross-references them to their call sites in the disassembly).
        ctx.metadata["dangerous_imports"] = meta.get("dangerous_imports", [])

        result.metadata = meta
        try:
            pe.close()
        except Exception:
            pass
        return result

    # ------------------------------------------------------------------ #
    def _analyze_sections(self, pe, result, meta) -> None:
        sections = []
        packer_detected = None
        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("latin-1", "ignore")
            sdata = section.get_data()
            ent = shannon_entropy(sdata) if sdata else 0.0
            writable = bool(section.Characteristics & 0x80000000)
            executable = bool(section.Characteristics & 0x20000000)
            sections.append(
                {
                    "name": name,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": round(ent, 2),
                    "writable": writable,
                    "executable": executable,
                }
            )
            if name in _KNOWN_PACKER_SECTIONS:
                packer_detected = _KNOWN_PACKER_SECTIONS[name]

            # Writable + executable section: classic self-modifying / unpacking.
            if writable and executable:
                result.add(
                    id="pe.wx_section",
                    title=f"Writable and executable section '{name}'",
                    description=(
                        f"Section '{name}' is both writable and executable, which "
                        "lets the program rewrite its own code at runtime — a "
                        "hallmark of self-unpacking packers and shellcode loaders."
                    ),
                    severity=Severity.MEDIUM,
                    category="executable",
                    section=name,
                )
            # High-entropy executable section -> packed code.
            if executable and ent >= 7.2 and section.SizeOfRawData > 2048:
                result.add(
                    id="pe.packed_section",
                    title=f"High-entropy code section '{name}'",
                    description=(
                        f"Executable section '{name}' has entropy {ent:.2f}/8.0, "
                        "indicating the real code is compressed/encrypted and only "
                        "unpacked at runtime to evade static analysis."
                    ),
                    severity=Severity.MEDIUM,
                    category="executable",
                    section=name,
                    entropy=round(ent, 2),
                )

        meta["sections"] = sections
        if packer_detected:
            result.add(
                id="pe.packer",
                title=f"Packed with {packer_detected}",
                description=(
                    f"Section names reveal the binary is packed with "
                    f"{packer_detected}. Packing hides the program's true code; "
                    "while some legitimate software is packed, malware relies on it "
                    "heavily to evade detection."
                ),
                severity=Severity.MEDIUM,
                category="executable",
                packer=packer_detected,
            )

    def _analyze_imports(self, pe, result, meta) -> None:
        capabilities: dict[str, Severity] = {}
        import_count = 0
        imported_dlls = []
        # Functions present in the capability map — the ones worth locating in
        # the disassembly (consumed by the `cutter` analyzer).
        dangerous_imports: list[str] = []
        # Full DLL -> [function] map so the report lists every imported API.
        imports_detail: dict[str, list[str]] = {}
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("latin-1", "ignore") if entry.dll else "?"
                imported_dlls.append(dll)
                funcs = imports_detail.setdefault(dll, [])
                for imp in entry.imports:
                    if imp.name:
                        fname = imp.name.decode("latin-1", "ignore")
                    elif imp.ordinal is not None:
                        # Functions imported by ordinal have no name.
                        fname = f"Ordinal#{imp.ordinal}"
                    else:
                        continue
                    import_count += 1
                    funcs.append(fname)
                    cap = _CAPABILITY_MAP.get(fname)
                    if cap:
                        label, sev = cap
                        if fname not in dangerous_imports:
                            dangerous_imports.append(fname)
                        if label not in capabilities or sev > capabilities[label]:
                            capabilities[label] = sev

        meta["imported_dlls"] = imported_dlls
        meta["import_count"] = import_count
        meta["imports"] = imports_detail
        meta["dangerous_imports"] = dangerous_imports
        meta["capabilities"] = [
            {"capability": c, "severity": s.label} for c, s in capabilities.items()
        ]

        # Very few or no imports often means the imports are resolved at runtime
        # (dynamic API resolution) to hide intent — common in packed malware.
        if import_count == 0 and not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            result.add(
                id="pe.no_imports",
                title="No static imports (dynamic API resolution)",
                description=(
                    "The binary declares almost no imported functions. Such "
                    "programs usually resolve the APIs they need at runtime to "
                    "hide their behaviour — common in packed or malicious code."
                ),
                severity=Severity.MEDIUM,
                category="executable",
            )

        for label, sev in capabilities.items():
            if sev >= Severity.MEDIUM:
                result.add(
                    id=f"pe.capability.{label.lower().replace(' ', '_')[:30]}",
                    title=f"Capability: {label}",
                    description=(
                        f"Imported APIs indicate this program can: {label}. This "
                        "capability is frequently abused by malware."
                    ),
                    severity=sev,
                    category="executable",
                    capability=label,
                )

    def _analyze_signature(self, pe, result, meta) -> None:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        signed = sec_dir.VirtualAddress != 0 and sec_dir.Size != 0
        meta["digitally_signed"] = signed
        if not signed:
            result.add(
                id="pe.unsigned",
                title="Executable is not digitally signed",
                description=(
                    "The binary carries no Authenticode digital signature. "
                    "Unsigned executables cannot be attributed to a verified "
                    "publisher; most reputable software is signed."
                ),
                severity=Severity.LOW,
                category="executable",
            )

    def _analyze_tls(self, pe, result, meta) -> None:
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
            result.add(
                id="pe.tls_callback",
                title="TLS callbacks present",
                description=(
                    "The binary registers TLS callbacks, code that runs before the "
                    "main entry point. Malware uses these to execute (and to detect "
                    "debuggers) before an analyst's breakpoint at the entry point."
                ),
                severity=Severity.LOW,
                category="executable",
            )
            meta["tls_callbacks"] = True
