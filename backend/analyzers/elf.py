"""ELF (Linux executable) reverse-engineering analyzer.

Uses pyelftools to surface a Linux binary's capabilities the way the PE
analyzer does for Windows: imported symbols, section/segment layout, whether
it is stripped, statically linked, and any RWX segments.
"""
from __future__ import annotations

import io

from .base import Analyzer, AnalyzerResult, FileContext, Severity

try:
    from elftools.elf.elffile import ELFFile  # type: ignore
    from elftools.elf.dynamic import DynamicSection  # type: ignore
    from elftools.elf.sections import SymbolTableSection  # type: ignore

    _HAVE_ELF = True
except Exception:  # pragma: no cover
    _HAVE_ELF = False

# Libc / syscall-ish symbol names mapped to behavioural capabilities.
_CAPABILITY_MAP: dict[str, tuple[str, Severity]] = {
    "system": ("Execute shell commands", Severity.MEDIUM),
    "popen": ("Execute shell commands", Severity.MEDIUM),
    "execve": ("Execute other programs", Severity.LOW),
    "execvp": ("Execute other programs", Severity.LOW),
    "fork": ("Spawn child processes", Severity.INFO),
    "ptrace": ("Anti-debugging / process tracing", Severity.MEDIUM),
    "socket": ("Network communication", Severity.LOW),
    "connect": ("Outbound network connection", Severity.LOW),
    "bind": ("Listen for network connections", Severity.LOW),
    "dlopen": ("Dynamically load libraries", Severity.LOW),
    "dlsym": ("Dynamically resolve symbols (evasion)", Severity.LOW),
    "setuid": ("Change user identity (privilege)", Severity.MEDIUM),
    "chmod": ("Change file permissions", Severity.INFO),
    "unlink": ("Delete files", Severity.INFO),
    "inotify_init": ("Monitor filesystem", Severity.INFO),
    "mprotect": ("Change memory protection (shellcode)", Severity.LOW),
}


class ELFAnalyzer(Analyzer):
    name = "elf"

    def applies(self, ctx: FileContext) -> bool:
        return ctx.data[:4] == b"\x7fELF"

    def run(self, ctx: FileContext) -> AnalyzerResult:
        result = self._result()
        if not _HAVE_ELF:
            result.error = "pyelftools not installed; ELF analysis unavailable"
            return result

        try:
            elf = ELFFile(io.BytesIO(ctx.data))
        except Exception as exc:
            result.error = f"Could not parse ELF: {exc}"
            return result

        meta: dict = {
            "arch": elf.get_machine_arch(),
            "bits": elf.elfclass,
            "type": elf["e_type"],
            "entry_point": hex(elf["e_entry"]),
        }

        # Imported / referenced symbols -> capabilities.
        capabilities: dict[str, Severity] = {}
        symbol_names: set[str] = set()
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for sym in section.iter_symbols():
                    if sym.name:
                        symbol_names.add(sym.name)
        for name in symbol_names:
            cap = _CAPABILITY_MAP.get(name)
            if cap:
                label, sev = cap
                if label not in capabilities or sev > capabilities[label]:
                    capabilities[label] = sev

        meta["symbol_count"] = len(symbol_names)
        meta["capabilities"] = [
            {"capability": c, "severity": s.label} for c, s in capabilities.items()
        ]

        # Stripped binary?
        has_symtab = any(
            isinstance(s, SymbolTableSection) and s.name == ".symtab"
            for s in elf.iter_sections()
        )
        meta["stripped"] = not has_symtab
        if not has_symtab:
            result.add(
                id="elf.stripped",
                title="Binary is stripped of symbols",
                description=(
                    "The ELF binary has no symbol table, so function and variable "
                    "names have been removed. Stripping is normal for release "
                    "builds but also hinders analysis and is common in malware."
                ),
                severity=Severity.INFO,
                category="executable",
            )

        # Statically linked? (no dynamic section / interpreter)
        has_dynamic = any(isinstance(s, DynamicSection) for s in elf.iter_sections())
        meta["statically_linked"] = not has_dynamic

        # RWX segments — code that can be written then executed.
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                flags = seg["p_flags"]
                if (flags & 0x1) and (flags & 0x2):  # X and W
                    result.add(
                        id="elf.rwx_segment",
                        title="Writable + executable memory segment",
                        description=(
                            "A loadable segment is both writable and executable, "
                            "allowing the program to generate and run code at "
                            "runtime — a technique used by packers and loaders."
                        ),
                        severity=Severity.MEDIUM,
                        category="executable",
                    )
                    break

        for label, sev in capabilities.items():
            if sev >= Severity.MEDIUM:
                result.add(
                    id=f"elf.capability.{label.lower().replace(' ', '_')[:30]}",
                    title=f"Capability: {label}",
                    description=(
                        f"Referenced symbols indicate this program can: {label}."
                    ),
                    severity=sev,
                    category="executable",
                    capability=label,
                )

        result.metadata = meta
        return result
