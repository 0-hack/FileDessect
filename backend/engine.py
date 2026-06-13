"""Analysis engine: orchestrates analyzers and derives the overall verdict.

Pipeline:
  1. Identity analyzer runs first and seeds shared metadata (hashes, type).
  2. Every applicable analyzer runs and returns findings.
  3. Findings' severity weights are summed into a risk score.
  4. The score (plus hard overrides like a YARA/VT malicious hit) maps to a
     verdict: clean / suspicious / malicious.
  5. A human-readable explanation is assembled from the contributing findings.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .analyzers.base import AnalyzerResult, FileContext, Finding, Severity, Verdict
from .analyzers.content import ContentAnalyzer
from .analyzers.elf import ELFAnalyzer
from .analyzers.embedded import EmbeddedAnalyzer
from .analyzers.identity import IdentityAnalyzer
from .analyzers.office import OfficeAnalyzer
from .analyzers.pe import PEAnalyzer
from .analyzers.virustotal import VirusTotalAnalyzer
from .analyzers.yara_scan import YaraAnalyzer

# Score thresholds for mapping the summed severity weights to a verdict.
SUSPICIOUS_THRESHOLD = 30
MALICIOUS_THRESHOLD = 90

# Findings that force a "malicious" verdict regardless of total score.
_HARD_MALICIOUS_IDS = {"virustotal.detections", "office.malicious_macro_pattern"}


class Engine:
    """Runs the analyzer pipeline over a file and produces a report."""

    def __init__(self) -> None:
        # Identity must be first; the rest can run in any order.
        self.identity = IdentityAnalyzer()
        self.analyzers = [
            ContentAnalyzer(),
            EmbeddedAnalyzer(),
            PEAnalyzer(),
            ELFAnalyzer(),
            OfficeAnalyzer(),
            YaraAnalyzer(),
            VirusTotalAnalyzer(),
        ]

    def analyze(self, *, path: str, filename: str, data: bytes) -> dict:
        ctx = FileContext(path=path, filename=filename, size=len(data), data=data)

        results: list[AnalyzerResult] = []
        results.append(self.identity.run(ctx))  # seeds ctx.metadata

        for analyzer in self.analyzers:
            try:
                if analyzer.applies(ctx):
                    results.append(analyzer.run(ctx))
            except Exception as exc:  # never let one analyzer break the report
                failed = AnalyzerResult(analyzer=analyzer.name, error=str(exc))
                results.append(failed)

        return self._build_report(ctx, results)

    # ------------------------------------------------------------------ #
    def _build_report(self, ctx: FileContext, results: list[AnalyzerResult]) -> dict:
        all_findings: list[Finding] = []
        for r in results:
            all_findings.extend(r.findings)

        score = sum(int(f.severity) for f in all_findings)
        verdict = self._verdict(score, all_findings)
        explanation = self._explain(verdict, score, all_findings)

        # Sort findings by severity (highest first) for presentation.
        ordered = sorted(all_findings, key=lambda f: int(f.severity), reverse=True)

        ident = ctx.metadata
        return {
            "filename": ctx.filename,
            "size": ctx.size,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "identity": {
                "hashes": ident.get("hashes", {}),
                "mime": ident.get("mime"),
                "magic": ident.get("magic"),
                "extension": ident.get("extension"),
                "detected_kind": ident.get("file_kind"),
            },
            "verdict": verdict.value,
            "risk_score": score,
            "explanation": explanation,
            "summary": self._summary_counts(all_findings),
            "findings": [f.to_dict() for f in ordered],
            "analyzers": [r.to_dict() for r in results],
        }

    @staticmethod
    def _verdict(score: int, findings: list[Finding]) -> Verdict:
        if any(f.id in _HARD_MALICIOUS_IDS for f in findings):
            return Verdict.MALICIOUS
        if any(f.severity == Severity.CRITICAL for f in findings):
            return Verdict.MALICIOUS
        if score >= MALICIOUS_THRESHOLD:
            return Verdict.MALICIOUS
        if score >= SUSPICIOUS_THRESHOLD:
            return Verdict.SUSPICIOUS
        return Verdict.CLEAN

    @staticmethod
    def _summary_counts(findings: list[Finding]) -> dict[str, int]:
        counts = {s.label: 0 for s in Severity}
        for f in findings:
            counts[f.severity.label] += 1
        return counts

    @staticmethod
    def _explain(verdict: Verdict, score: int, findings: list[Finding]) -> str:
        if not findings:
            return (
                "No suspicious characteristics were detected. The file appears "
                "clean based on static analysis, though no static scan can offer "
                "an absolute guarantee."
            )

        top = sorted(findings, key=lambda f: int(f.severity), reverse=True)
        notable = [f for f in top if f.severity >= Severity.MEDIUM][:5]
        if not notable:
            notable = top[:3]

        reasons = "; ".join(f.title for f in notable)

        if verdict == Verdict.MALICIOUS:
            lead = (
                "This file is assessed as MALICIOUS. Strong indicators of harmful "
                "behaviour were found"
            )
        elif verdict == Verdict.SUSPICIOUS:
            lead = (
                "This file is assessed as SUSPICIOUS. It shows characteristics that "
                "warrant caution and further review"
            )
        else:
            lead = (
                "This file is assessed as likely CLEAN, with only minor or "
                "informational observations"
            )

        return (
            f"{lead} (risk score {score}). Key findings: {reasons}. "
            "Review the detailed findings and the VirusTotal reputation link below."
        )
