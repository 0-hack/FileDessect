"""Cutter / Rizin deep-disassembly analyzer.

Where the Capstone-based :mod:`~backend.analyzers.disasm` analyzer reads a flat
window of bytes at the entry point, this analyzer drives the full **Rizin**
engine — the open-source core the [Cutter](https://cutter.re) GUI is built on —
to recover *program structure*:

  * a complete function listing;
  * per-function disassembly of the entry point and of the functions that
    actually call dangerous imports (the real call sites, not just the prologue);
  * import -> caller cross-references;
  * decompilation, when ``rz-ghidra`` is installed;
  * a downloadable Cutter/Rizin session script for hands-on debugging.

It only runs when the ``rizin`` binary is present; otherwise it is skipped and
the Capstone path still provides a basic listing. The heavy lifting lives in
:mod:`backend.rizin`.
"""
from __future__ import annotations

from .. import rizin
from .base import Analyzer, AnalyzerResult, FileContext, Severity

# Native-binary magics this analyzer understands (PE / ELF / Mach-O, incl. fat).
_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
}

# Above this size, skip deep analysis — `aaa` on a huge binary is too slow for an
# interactive web request.
_MAX_BYTES = 20 * 1024 * 1024


class CutterAnalyzer(Analyzer):
    name = "cutter"

    def applies(self, ctx: FileContext) -> bool:
        if not rizin.available() or ctx.size > _MAX_BYTES:
            return False
        head = ctx.data[:4]
        return head[:2] == b"MZ" or head == b"\x7fELF" or head in _MACHO_MAGICS

    def run(self, ctx: FileContext) -> AnalyzerResult:
        result = self._result()
        if not rizin.available():
            result.error = "rizin engine not installed; deep disassembly unavailable"
            return result

        # The PE analyzer (which runs earlier) shares the names of the dangerous
        # imports it found via ctx.metadata; for ELF/Mach-O this is empty and the
        # rizin layer falls back to its own built-in symbol list.
        dangerous = ctx.metadata.get("dangerous_imports") or []

        report = rizin.deep_analysis(
            ctx.path,
            filename=ctx.filename,
            dangerous_imports=dangerous,
        )
        if not report:
            result.error = "rizin analysis produced no usable output"
            return result

        result.metadata = report
        self._emit_findings(result, report)
        return result

    # ------------------------------------------------------------------ #
    @staticmethod
    def _emit_findings(result: AnalyzerResult, report: dict) -> None:
        # Locating the exact call sites of dangerous imports is high-value
        # context for an analyst. We report it as INFO/LOW — it does not by
        # itself prove malice (the PE capability findings already weigh the
        # presence of the import); this pinpoints *where* it is used.
        xrefs = report.get("import_xrefs") or []
        if xrefs:
            summary = {x["import"]: len(x["callers"]) for x in xrefs}
            result.add(
                id="cutter.import_callsites",
                title=f"Located call sites of {len(xrefs)} dangerous import(s)",
                description=(
                    "Rizin pinpointed where notable imported APIs are actually "
                    "invoked in the code. Review these functions to understand the "
                    "program's behaviour. Call sites: "
                    + ", ".join(f"{k} (x{v})" for k, v in summary.items())
                    + "."
                ),
                severity=Severity.INFO,
                category="disassembly",
                callsites=summary,
            )

        if report.get("decompiler"):
            result.add(
                id="cutter.decompiled",
                title="Decompilation available (rz-ghidra)",
                description=(
                    "A decompiler plugin is installed, so pseudo-C for the entry "
                    "point and flagged functions is included below for easier "
                    "reading."
                ),
                severity=Severity.INFO,
                category="disassembly",
            )
