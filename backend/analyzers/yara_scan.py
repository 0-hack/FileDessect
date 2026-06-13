"""YARA signature analyzer.

Compiles every ``*.yar`` rule under the configured rules directory and matches
them against the uploaded file. YARA is the de-facto standard for pattern-based
malware identification; bundled rules ship in ``rules/`` and users can drop in
their own.
"""
from __future__ import annotations

from pathlib import Path

from ..config import get_settings
from .base import Analyzer, AnalyzerResult, FileContext, Severity

try:
    import yara  # type: ignore

    _HAVE_YARA = True
except Exception:  # pragma: no cover
    _HAVE_YARA = False


# Map a rule's `meta: severity = "..."` value to our Severity scale.
_SEVERITY_BY_NAME = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class YaraAnalyzer(Analyzer):
    name = "yara"

    _compiled = None
    _compile_error: str | None = None

    def _get_rules(self):
        if self._compiled is not None or self._compile_error is not None:
            return self._compiled
        settings = get_settings()
        rules_dir = Path(settings.rules_dir)
        filepaths = {
            p.stem: str(p) for p in rules_dir.glob("**/*.yar")
        }
        filepaths.update({f"{p.stem}_yara": str(p) for p in rules_dir.glob("**/*.yara")})
        if not filepaths:
            self._compile_error = "no rules found"
            return None
        try:
            type(self)._compiled = yara.compile(filepaths=filepaths)
        except Exception as exc:  # pragma: no cover
            type(self)._compile_error = str(exc)
            return None
        return self._compiled

    def run(self, ctx: FileContext) -> AnalyzerResult:
        result = self._result()
        if not _HAVE_YARA:
            result.error = "yara-python not installed; signature scanning unavailable"
            return result

        rules = self._get_rules()
        if rules is None:
            result.error = f"YARA rules unavailable: {self._compile_error}"
            return result

        try:
            matches = rules.match(data=ctx.data)
        except Exception as exc:  # pragma: no cover
            result.error = f"YARA scan failed: {exc}"
            return result

        result.metadata = {"matched_rules": [m.rule for m in matches]}
        for match in matches:
            meta = match.meta or {}
            sev_name = str(meta.get("severity", "medium")).lower()
            severity = _SEVERITY_BY_NAME.get(sev_name, Severity.MEDIUM)
            description = meta.get("description", "Matched a YARA detection rule.")
            result.add(
                id=f"yara.{match.rule}",
                title=f"YARA rule matched: {match.rule}",
                description=(
                    f"{description} (rule '{match.rule}'"
                    + (f", author {meta['author']}" if meta.get("author") else "")
                    + ")."
                ),
                severity=severity,
                category="signature",
                rule=match.rule,
                tags=list(match.tags),
                meta={k: str(v) for k, v in meta.items()},
            )

        return result
