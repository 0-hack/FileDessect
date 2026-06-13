"""Office / OLE document analyzer.

Uses oletools to detect VBA macros and known malicious macro patterns in
Microsoft Office documents (both legacy OLE .doc/.xls and OOXML .docx/.xlsm).
Macros embedded in documents are one of the most common malware delivery
vectors and are not visible to a user simply opening the file.
"""
from __future__ import annotations

from .base import Analyzer, AnalyzerResult, FileContext, Severity

try:
    from oletools.olevba import VBA_Parser  # type: ignore

    _HAVE_OLEVBA = True
except Exception:  # pragma: no cover
    _HAVE_OLEVBA = False

_OLE_MAGIC = b"\xd0\xcf\x11\xe0"
_ZIP_MAGIC = b"PK\x03\x04"
_OFFICE_EXTS = {".doc", ".docm", ".dot", ".xls", ".xlsm", ".xlsb", ".ppt",
                ".pptm", ".docx", ".xlsx", ".pptx", ".rtf"}


class OfficeAnalyzer(Analyzer):
    name = "office"

    def applies(self, ctx: FileContext) -> bool:
        ext = ctx.metadata.get("extension", "")
        head = ctx.data[:4]
        return ext in _OFFICE_EXTS or head in (_OLE_MAGIC, _ZIP_MAGIC)

    def run(self, ctx: FileContext) -> AnalyzerResult:
        result = self._result()
        if not _HAVE_OLEVBA:
            result.error = "oletools not installed; macro analysis unavailable"
            return result

        try:
            parser = VBA_Parser(ctx.filename, data=ctx.data)
        except Exception as exc:
            # Not actually an Office file — quietly skip.
            result.metadata = {"is_office": False, "detail": str(exc)}
            return result

        if not parser.detect_vba_macros():
            result.metadata = {"has_macros": False}
            try:
                parser.close()
            except Exception:
                pass
            return result

        keywords: list[dict] = []
        max_sev = Severity.LOW
        try:
            for kw_type, keyword, description in parser.analyze_macros():
                # oletools categorises as: AutoExec, Suspicious, IOC, etc.
                sev = {
                    "AutoExec": Severity.MEDIUM,
                    "Suspicious": Severity.HIGH,
                    "IOC": Severity.LOW,
                    "Hex String": Severity.LOW,
                    "Base64 String": Severity.LOW,
                    "Dridex String": Severity.HIGH,
                    "VBA string": Severity.INFO,
                }.get(kw_type, Severity.LOW)
                max_sev = max(max_sev, sev)
                keywords.append(
                    {"type": kw_type, "keyword": keyword, "description": description}
                )
        except Exception:  # pragma: no cover
            pass

        result.metadata = {"has_macros": True, "macro_indicators": len(keywords)}
        result.add(
            id="office.vba_macros",
            title="Document contains VBA macros",
            description=(
                "This Office document embeds VBA macro code that can run "
                "automatically when the document is opened. Macros are a leading "
                f"malware delivery method. {len(keywords)} notable macro "
                "pattern(s) were analysed (see evidence)."
            ),
            severity=max(max_sev, Severity.MEDIUM),
            category="document",
            indicators=keywords[:40],
        )

        # Auto-execution + suspicious behaviour together => strong signal.
        has_autoexec = any(k["type"] == "AutoExec" for k in keywords)
        has_suspicious = any(k["type"] == "Suspicious" for k in keywords)
        if has_autoexec and has_suspicious:
            result.add(
                id="office.malicious_macro_pattern",
                title="Auto-executing macro with suspicious actions",
                description=(
                    "The document combines an auto-execution trigger (e.g. "
                    "AutoOpen / Document_Open) with suspicious operations such as "
                    "shell execution or payload download. This pattern is "
                    "characteristic of weaponised malicious documents."
                ),
                severity=Severity.HIGH,
                category="document",
            )

        try:
            parser.close()
        except Exception:
            pass
        return result
