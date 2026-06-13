"""Content analyzer: entropy, indicators of compromise, and suspicious strings.

Works on *any* file. It extracts printable strings and scans them for
indicators (URLs, IPs, shell commands, suspicious API names, base64 blobs)
and measures byte-entropy to spot packed/encrypted regions.
"""
from __future__ import annotations

import re

from .base import Analyzer, AnalyzerResult, FileContext, Severity
from .utils import extract_strings, shannon_entropy

_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\\]{4,200}", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,18}\b", re.IGNORECASE
)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
# Same pattern over raw bytes, used to report the real file offset of each blob.
_BASE64_BYTES_RE = re.compile(rb"[A-Za-z0-9+/]{120,}={0,2}")

# Generous safety cap so a pathological file can't produce an unbounded report,
# while still being "complete" for any realistic sample.
_MAX_IOC = 2000

# Keywords grouped by what they suggest. Presence alone is not damning, but
# clusters of them raise suspicion and are surfaced as evidence.
_SUSPICIOUS_KEYWORDS: dict[str, tuple[str, Severity]] = {
    # Process injection / shellcode
    "VirtualAlloc": ("memory allocation for injected code", Severity.LOW),
    "VirtualProtect": ("changing memory protection (shellcode)", Severity.LOW),
    "WriteProcessMemory": ("writing into another process (injection)", Severity.MEDIUM),
    "CreateRemoteThread": ("remote thread creation (injection)", Severity.MEDIUM),
    "SetWindowsHookEx": ("global hooks (keylogging)", Severity.MEDIUM),
    "NtUnmapViewOfSection": ("process hollowing primitive", Severity.MEDIUM),
    # Persistence
    "CurrentVersion\\Run": ("registry run-key persistence", Severity.MEDIUM),
    "schtasks": ("scheduled-task persistence", Severity.LOW),
    "New-Service": ("service installation persistence", Severity.LOW),
    # Credential / system access
    "mimikatz": ("known credential-dumping tool", Severity.CRITICAL),
    "lsass": ("targeting the LSASS credential store", Severity.HIGH),
    "SeDebugPrivilege": ("privilege escalation token", Severity.MEDIUM),
    # Command execution / download
    "powershell -enc": ("encoded PowerShell command", Severity.HIGH),
    "-EncodedCommand": ("encoded PowerShell command", Severity.HIGH),
    "DownloadString": ("remote payload download", Severity.MEDIUM),
    "DownloadFile": ("remote payload download", Severity.MEDIUM),
    "Invoke-Expression": ("dynamic code execution", Severity.MEDIUM),
    "WScript.Shell": ("script-driven command execution", Severity.LOW),
    "cmd.exe /c": ("spawning a command shell", Severity.LOW),
    "/bin/sh": ("spawning a Unix shell", Severity.LOW),
    "base64 -d": ("decoding an embedded payload", Severity.LOW),
    "eval(": ("dynamic code evaluation", Severity.LOW),
    # Anti-analysis
    "IsDebuggerPresent": ("anti-debugging check", Severity.LOW),
    "CheckRemoteDebuggerPresent": ("anti-debugging check", Severity.LOW),
    "VMware": ("virtual-machine / sandbox evasion check", Severity.LOW),
    "VBoxGuest": ("virtual-machine / sandbox evasion check", Severity.LOW),
    # Ransomware-ish
    "vssadmin delete shadows": ("deleting shadow copies (ransomware)", Severity.HIGH),
    "bcdedit": ("tampering with boot configuration", Severity.MEDIUM),
    # Crypto wallets / clipboard
    "bitcoin": ("cryptocurrency reference", Severity.INFO),
}


class ContentAnalyzer(Analyzer):
    name = "content"

    def run(self, ctx: FileContext) -> AnalyzerResult:
        result = self._result()
        data = ctx.data

        overall_entropy = shannon_entropy(data)
        strings = extract_strings(data, min_len=5)
        blob = "\n".join(strings)

        urls = sorted(set(_URL_RE.findall(blob)))[:_MAX_IOC]
        ips = sorted({ip for ip in _IP_RE.findall(blob) if _plausible_ip(ip)})[:_MAX_IOC]
        # Domains excluding ones already covered by URLs to reduce noise.
        domains = sorted(
            {d for d in _DOMAIN_RE.findall(blob) if _interesting_domain(d)}
        )[:_MAX_IOC]

        # Inventory every large base64 blob with its real file offset and length.
        b64_inventory = [
            {
                "offset": m.start(),
                "length": len(m.group()),
                "preview": m.group()[:64].decode("ascii", "ignore"),
            }
            for m in list(_BASE64_BYTES_RE.finditer(data))[:_MAX_IOC]
        ]

        result.metadata = {
            "entropy": round(overall_entropy, 3),
            "string_count": len(strings),
            "url_count": len(urls),
            "ip_count": len(ips),
            "domain_count": len(domains),
            "urls": urls,
            "ips": ips,
            "domains": domains,
            "base64_blob_count": len(b64_inventory),
            "base64_blobs": b64_inventory,
        }

        # --- Entropy-based packing detection -------------------------------
        if overall_entropy >= 7.2 and ctx.size > 4096:
            result.add(
                id="content.high_entropy",
                title="High overall entropy (packed / encrypted)",
                description=(
                    f"The file's byte entropy is {overall_entropy:.2f}/8.0, which "
                    "indicates compressed, encrypted or packed content. Malware "
                    "commonly packs itself to hide its real code from inspection."
                ),
                severity=Severity.LOW if overall_entropy < 7.5 else Severity.MEDIUM,
                category="content",
                entropy=round(overall_entropy, 3),
            )

        # --- Network indicators --------------------------------------------
        if urls or ips or domains:
            result.add(
                id="content.network_indicators",
                title="Embedded network indicators",
                description=(
                    f"Found {len(urls)} URL(s), {len(ips)} IP address(es) and "
                    f"{len(domains)} domain(s) inside the file. These may be "
                    "command-and-control servers or download locations. The "
                    "complete list is included as evidence; review them and check "
                    "their reputation."
                ),
                severity=Severity.INFO if not ips else Severity.LOW,
                category="content",
                urls=urls,
                ips=ips,
                domains=domains,
            )

        # --- Large base64 blobs --------------------------------------------
        if b64_inventory:
            result.add(
                id="content.embedded_base64",
                title="Large base64-encoded blob(s) embedded",
                description=(
                    f"Detected {len(b64_inventory)} long base64 string(s). Encoded "
                    "blobs are frequently used to smuggle a hidden second-stage "
                    "payload past simple content inspection. Each blob's file "
                    "offset and length is listed as evidence."
                ),
                severity=Severity.LOW,
                category="content",
                count=len(b64_inventory),
                blobs=b64_inventory,
            )

        # --- Suspicious keyword clustering ---------------------------------
        hits: list[dict] = []
        max_sev = Severity.INFO
        lowered = blob.lower()
        for keyword, (meaning, sev) in _SUSPICIOUS_KEYWORDS.items():
            if keyword.lower() in lowered:
                hits.append({"keyword": keyword, "meaning": meaning, "severity": sev.label})
                max_sev = max(max_sev, sev)

        if hits:
            # A single low-severity keyword is informational; clusters escalate.
            informative = [h for h in hits if h["severity"] != "info"]
            cluster_sev = max_sev
            if len(informative) >= 4 and cluster_sev < Severity.HIGH:
                cluster_sev = Severity.HIGH
            result.add(
                id="content.suspicious_api",
                title=f"{len(hits)} suspicious capability indicator(s)",
                description=(
                    "The file references API names / commands associated with "
                    "malicious behaviour such as code injection, persistence, "
                    "anti-analysis or credential theft. See evidence for details."
                ),
                severity=cluster_sev,
                category="content",
                indicators=hits,
            )

        return result


def _plausible_ip(ip: str) -> bool:
    parts = ip.split(".")
    if any(int(p) > 255 for p in parts):
        return False
    # Skip obvious version-number noise like 1.2.3.4 inside very small ranges.
    if ip in {"0.0.0.0", "127.0.0.1", "255.255.255.255"}:
        return False
    return True


def _interesting_domain(domain: str) -> bool:
    boring_tlds = (".png", ".jpg", ".gif", ".dll", ".exe", ".sys")
    if domain.lower().endswith(boring_tlds):
        return False
    return "." in domain and len(domain) <= 100
