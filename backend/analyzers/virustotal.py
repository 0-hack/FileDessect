"""VirusTotal reputation analyzer.

For every file FileDessect provides a VirusTotal permalink keyed on the file's
SHA-256. When a ``VT_API_KEY`` is configured, it additionally queries the
VirusTotal v3 API to report how many antivirus engines flag the hash and
whether the file is already known in the wild.

No file content is ever uploaded — only the hash is sent, so analysis stays
private unless the user explicitly chooses otherwise elsewhere.
"""
from __future__ import annotations

from ..config import get_settings
from .base import Analyzer, AnalyzerResult, FileContext, Severity

try:
    import httpx  # type: ignore

    _HAVE_HTTPX = True
except Exception:  # pragma: no cover
    _HAVE_HTTPX = False

_VT_API = "https://www.virustotal.com/api/v3/files/{sha256}"
_VT_GUI = "https://www.virustotal.com/gui/file/{sha256}"


class VirusTotalAnalyzer(Analyzer):
    name = "virustotal"

    def run(self, ctx: FileContext) -> AnalyzerResult:
        result = self._result()
        sha256 = ctx.metadata.get("hashes", {}).get("sha256")
        if not sha256:
            result.error = "no sha256 available"
            return result

        permalink = _VT_GUI.format(sha256=sha256)
        result.metadata = {"permalink": permalink, "queried": False}

        settings = get_settings()
        if not settings.vt_api_key or not _HAVE_HTTPX:
            result.metadata["note"] = (
                "VT_API_KEY not configured — showing reputation link only."
            )
            result.add(
                id="virustotal.link",
                title="Check this file on VirusTotal",
                description=(
                    "No VirusTotal API key is configured, so a live reputation "
                    "lookup was not performed. You can manually review this file's "
                    f"reputation at the linked report (by SHA-256)."
                ),
                severity=Severity.INFO,
                category="reputation",
                permalink=permalink,
            )
            return result

        try:
            resp = httpx.get(
                _VT_API.format(sha256=sha256),
                headers={"x-apikey": settings.vt_api_key},
                timeout=20.0,
            )
        except Exception as exc:  # network error
            result.error = f"VirusTotal request failed: {exc}"
            result.add(
                id="virustotal.link",
                title="Check this file on VirusTotal",
                description=(
                    "The live VirusTotal lookup could not be completed, but you "
                    "can review the report manually at the linked page."
                ),
                severity=Severity.INFO,
                category="reputation",
                permalink=permalink,
            )
            return result

        if resp.status_code == 404:
            result.metadata["queried"] = True
            result.metadata["known"] = False
            result.add(
                id="virustotal.unknown",
                title="File not seen before on VirusTotal",
                description=(
                    "VirusTotal has no record of this file's hash. A file that is "
                    "unknown in the wild is neither inherently safe nor malicious, "
                    "but freshly built or rare files warrant extra caution."
                ),
                severity=Severity.LOW,
                category="reputation",
                permalink=permalink,
            )
            return result

        if resp.status_code != 200:
            result.error = f"VirusTotal returned HTTP {resp.status_code}"
            return result

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected

        result.metadata.update(
            {
                "queried": True,
                "known": True,
                "stats": stats,
                "reputation": attrs.get("reputation"),
                "names": attrs.get("names", [])[:10],
                "permalink": permalink,
            }
        )

        if malicious > 0:
            sev = Severity.CRITICAL if malicious >= 5 else Severity.HIGH
            result.add(
                id="virustotal.detections",
                title=f"VirusTotal: {malicious}/{total} engines flag this file",
                description=(
                    f"{malicious} antivirus engine(s) on VirusTotal classify this "
                    f"exact file as malicious ({suspicious} as suspicious). This is "
                    "a known-bad file in the wild."
                ),
                severity=sev,
                category="reputation",
                malicious=malicious,
                suspicious=suspicious,
                total=total,
                permalink=permalink,
            )
        elif suspicious > 0:
            result.add(
                id="virustotal.suspicious",
                title=f"VirusTotal: {suspicious}/{total} engines flag as suspicious",
                description=(
                    f"{suspicious} engine(s) on VirusTotal flag this file as "
                    "suspicious, though none classify it outright malicious."
                ),
                severity=Severity.MEDIUM,
                category="reputation",
                suspicious=suspicious,
                total=total,
                permalink=permalink,
            )
        else:
            result.add(
                id="virustotal.clean",
                title=f"VirusTotal: 0/{total} engines flag this file",
                description=(
                    "No antivirus engine on VirusTotal currently flags this known "
                    "file. This is a positive reputation signal, though not an "
                    "absolute guarantee of safety."
                ),
                severity=Severity.INFO,
                category="reputation",
                total=total,
                permalink=permalink,
            )

        return result
