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
from .analyzers.code import ScriptAnalyzer
from .analyzers.content import ContentAnalyzer
from .analyzers.disasm import DisassemblyAnalyzer
from .analyzers.elf import ELFAnalyzer
from .analyzers.embedded import EmbeddedAnalyzer
from .analyzers.identity import IdentityAnalyzer
from .analyzers.macho import MachOAnalyzer
from .analyzers.office import OfficeAnalyzer
from .analyzers.pe import PEAnalyzer
from .analyzers.virustotal import VirusTotalAnalyzer
from .analyzers.yara_scan import YaraAnalyzer

# Score thresholds for mapping the summed severity weights to a verdict.
SUSPICIOUS_THRESHOLD = 30
MALICIOUS_THRESHOLD = 90

# Findings that force a "malicious" verdict regardless of total score.
_HARD_MALICIOUS_IDS = {"virustotal.detections", "office.malicious_macro_pattern"}

# Human descriptions of each hard override, surfaced on the scoring page.
_HARD_OVERRIDE_DESCRIPTIONS = {
    "virustotal.detections": (
        "One or more antivirus engines on VirusTotal flag the file's hash as "
        "malicious."
    ),
    "office.malicious_macro_pattern": (
        "An Office document combines an auto-execution trigger with a suspicious "
        "macro action (e.g. shell execution or payload download)."
    ),
}

# What each severity level means and how much weight it adds to the score.
_SEVERITY_DESCRIPTIONS = {
    Severity.INFO: "Contextual observation only. Adds 0 to the risk score.",
    Severity.LOW: "Minor trait; common in benign files but worth noting.",
    Severity.MEDIUM: "Notable trait frequently associated with malicious behaviour.",
    Severity.HIGH: "Strong indicator of malicious behaviour.",
    Severity.CRITICAL: (
        "Near-certain malicious indicator; forces a MALICIOUS verdict on its own."
    ),
}


def scoring_model() -> dict:
    """Return the full scoring/verdict model (single source of truth).

    Served at ``/api/scoring`` and rendered on the ``/scoring`` reference page so
    the documentation can never drift from the constants the engine actually uses.
    """
    return {
        "how_it_works": (
            "Every analyzer emits findings. Each finding carries a severity whose "
            "numeric weight is added to a cumulative risk score. The total score is "
            "mapped to a verdict using the thresholds below. Some findings are "
            "'hard overrides' that force a MALICIOUS verdict regardless of score."
        ),
        "severity_weights": [
            {
                "severity": s.label,
                "weight": int(s),
                "description": _SEVERITY_DESCRIPTIONS[s],
            }
            for s in Severity
        ],
        "verdict_thresholds": [
            {
                "verdict": "clean",
                "range": f"score < {SUSPICIOUS_THRESHOLD}",
                "meaning": "No suspicious traits, or only minor/informational ones.",
            },
            {
                "verdict": "suspicious",
                "range": f"{SUSPICIOUS_THRESHOLD} ≤ score < {MALICIOUS_THRESHOLD}",
                "meaning": "Traits that warrant caution and manual review.",
            },
            {
                "verdict": "malicious",
                "range": f"score ≥ {MALICIOUS_THRESHOLD}",
                "meaning": "Strong evidence of harmful behaviour.",
            },
        ],
        "hard_overrides": [
            {"finding_id": fid, "description": desc}
            for fid, desc in _HARD_OVERRIDE_DESCRIPTIONS.items()
        ]
        + [
            {
                "finding_id": "<any critical-severity finding>",
                "description": "Any single CRITICAL finding forces a MALICIOUS verdict.",
            }
        ],
        "caveat": (
            "Static analysis cannot prove a file is safe. A 'clean' verdict means "
            "no suspicious traits were detected, not a guarantee of safety."
        ),
    }


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
            MachOAnalyzer(),
            DisassemblyAnalyzer(),
            ScriptAnalyzer(),
            OfficeAnalyzer(),
            YaraAnalyzer(),
            VirusTotalAnalyzer(),
        ]

    def analyze(
        self,
        *,
        path: str,
        filename: str,
        data: bytes,
        enable_virustotal: bool = True,
    ) -> dict:
        ctx = FileContext(path=path, filename=filename, size=len(data), data=data)

        results: list[AnalyzerResult] = []
        results.append(self.identity.run(ctx))  # seeds ctx.metadata

        for analyzer in self.analyzers:
            # VirusTotal runs by default; users can opt out (e.g. for privacy or
            # fully offline analysis), in which case no hash leaves the sandbox.
            if analyzer.name == "virustotal" and not enable_virustotal:
                continue
            try:
                if analyzer.applies(ctx):
                    results.append(analyzer.run(ctx))
            except Exception as exc:  # never let one analyzer break the report
                failed = AnalyzerResult(analyzer=analyzer.name, error=str(exc))
                results.append(failed)

        report = self._build_report(ctx, results)
        report["virustotal_enabled"] = enable_virustotal
        return report

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

        # Per-finding contribution to the score, so the user can see exactly how
        # the verdict was reached (and cross-reference the /scoring page).
        breakdown = [
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity.label,
                "weight": int(f.severity),
            }
            for f in ordered
        ]

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
                "runtime": ident.get("runtime"),
            },
            "verdict": verdict.value,
            "risk_score": score,
            "explanation": explanation,
            "summary": self._summary_counts(all_findings),
            "scoring": {
                "score": score,
                "verdict": verdict.value,
                "reason": self._verdict_reason(score, all_findings),
                "thresholds": {
                    "suspicious": SUSPICIOUS_THRESHOLD,
                    "malicious": MALICIOUS_THRESHOLD,
                },
                "breakdown": breakdown,
                "reference": "/scoring",
            },
            "findings": [f.to_dict() for f in ordered],
            "analyzers": [r.to_dict() for r in results],
        }

    @staticmethod
    def _verdict_reason(score: int, findings: list[Finding]) -> str:
        overrides = [f for f in findings if f.id in _HARD_MALICIOUS_IDS]
        if overrides:
            ids = ", ".join(f.id for f in overrides)
            return f"Forced to MALICIOUS by hard-override finding(s): {ids}."
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        if crit:
            return (
                f"Forced to MALICIOUS by a critical-severity finding: {crit[0].title}."
            )
        if score >= MALICIOUS_THRESHOLD:
            return (
                f"Risk score {score} reached the malicious threshold "
                f"({MALICIOUS_THRESHOLD})."
            )
        if score >= SUSPICIOUS_THRESHOLD:
            return (
                f"Risk score {score} reached the suspicious threshold "
                f"({SUSPICIOUS_THRESHOLD}) but is below the malicious threshold "
                f"({MALICIOUS_THRESHOLD})."
            )
        return (
            f"Risk score {score} is below the suspicious threshold "
            f"({SUSPICIOUS_THRESHOLD})."
        )

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
