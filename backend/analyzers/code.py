"""Source-code / script analyzer.

Statically inspects human-readable script and source files — Python, Windows
batch, PowerShell, shell, JavaScript, VBScript, HTML, PHP, AppleScript and
macOS persistence plists — for dangerous constructs (dynamic code execution,
download-and-run, obfuscation, persistence, LOLBINs, reverse shells).

Unlike compiled-binary analysis this reads the actual source, so it can quote
the offending line. It is pattern-based and language-aware.
"""
from __future__ import annotations

import re

from .base import Analyzer, AnalyzerResult, FileContext, Severity

# Extension -> language.
_LANG_BY_EXT: dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".bat": "batch", ".cmd": "batch",
    ".ps1": "powershell", ".psm1": "powershell",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".command": "shell",
    ".js": "javascript", ".mjs": "javascript", ".jse": "javascript",
    ".vbs": "vbscript", ".vbe": "vbscript",
    ".html": "html", ".htm": "html", ".hta": "html",
    ".php": "php", ".php5": "php", ".phtml": "php",
    ".scpt": "applescript", ".applescript": "applescript",
    ".plist": "plist",
}

# Each pattern: (regex, title, severity, why).
_PATTERNS: dict[str, list[tuple[str, str, Severity, str]]] = {
    "python": [
        (r"\beval\s*\(", "eval()", Severity.HIGH, "executes a string as Python code"),
        (r"\bexec\s*\(", "exec()", Severity.HIGH, "executes arbitrary Python code"),
        (r"\bos\.system\s*\(", "os.system()", Severity.MEDIUM, "runs a shell command"),
        (r"\bsubprocess\.(?:Popen|call|run|check_output)", "subprocess", Severity.MEDIUM, "spawns an external process"),
        (r"\b__import__\s*\(", "__import__()", Severity.MEDIUM, "dynamic import, often used to obfuscate"),
        (r"\bmarshal\.loads", "marshal.loads", Severity.HIGH, "loads marshalled bytecode (obfuscation)"),
        (r"\bpickle\.loads", "pickle.loads", Severity.MEDIUM, "deserialises pickle data (code-exec risk)"),
        (r"base64\.b64decode", "base64 decode", Severity.LOW, "decodes a base64 payload"),
        (r"/dev/tcp/", "/dev/tcp", Severity.HIGH, "reverse-shell socket"),
        (r"\bpty\.spawn", "pty.spawn", Severity.HIGH, "spawns an interactive shell (reverse shell)"),
    ],
    "batch": [
        (r"\bpowershell\b", "powershell", Severity.MEDIUM, "invokes PowerShell from batch"),
        (r"certutil\b[^\n]*-(?:urlcache|decode)", "certutil", Severity.HIGH, "certutil download/decode (LOLBIN)"),
        (r"\bbitsadmin\b", "bitsadmin", Severity.MEDIUM, "BITS file download (LOLBIN)"),
        (r"\bmshta\b", "mshta", Severity.HIGH, "mshta script execution (LOLBIN)"),
        (r"\breg\s+add\b", "reg add", Severity.MEDIUM, "registry modification (persistence/config)"),
        (r"vssadmin\b[^\n]*delete", "vssadmin delete", Severity.HIGH, "deletes shadow copies (ransomware)"),
        (r"\bschtasks\b", "schtasks", Severity.MEDIUM, "scheduled-task persistence"),
        (r"\bdel\s+/[fqs]", "del /f", Severity.LOW, "force-deletes files"),
    ],
    "powershell": [
        (r"-enc(?:odedcommand)?\b", "-EncodedCommand", Severity.HIGH, "runs a base64-encoded command"),
        (r"\bIEX\b|Invoke-Expression", "Invoke-Expression", Severity.HIGH, "executes a string as code"),
        (r"DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|\biwr\b", "web download", Severity.MEDIUM, "downloads remote content"),
        (r"FromBase64String", "FromBase64String", Severity.MEDIUM, "decodes a base64 payload"),
        (r"-w(?:indowstyle)?\s+hidden", "hidden window", Severity.MEDIUM, "runs with a hidden window"),
        (r"-ExecutionPolicy\s+Bypass|-ep\s+bypass", "ExecutionPolicy Bypass", Severity.MEDIUM, "bypasses the execution policy"),
        (r"(?:Add|Set)-MpPreference", "Defender tampering", Severity.HIGH, "modifies Windows Defender settings"),
    ],
    "shell": [
        (r"(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh", "download | sh", Severity.HIGH, "downloads and runs a script in one line"),
        (r"\bnc\b[^\n]*-e\b", "nc -e", Severity.HIGH, "netcat reverse shell"),
        (r"/dev/tcp/", "/dev/tcp", Severity.HIGH, "bash reverse-shell socket"),
        (r"base64\s+-d[^\n|]*\|\s*(?:ba)?sh", "base64 -d | sh", Severity.HIGH, "decodes and runs a payload"),
        (r"\bchmod\s+\+x", "chmod +x", Severity.LOW, "makes a file executable"),
        (r"\brm\s+-rf\s+/(?:\s|$|\*)", "rm -rf /", Severity.HIGH, "destructive recursive delete"),
    ],
    "javascript": [
        (r"\beval\s*\(", "eval()", Severity.HIGH, "executes a string as code"),
        (r"new\s+Function\s*\(", "new Function()", Severity.MEDIUM, "builds code from a string"),
        (r"\bunescape\s*\(", "unescape()", Severity.MEDIUM, "common JS de-obfuscation step"),
        (r"String\.fromCharCode", "fromCharCode", Severity.MEDIUM, "char-code obfuscation"),
        (r"\batob\s*\(", "atob()", Severity.LOW, "decodes base64"),
        (r"document\.write\s*\(", "document.write", Severity.MEDIUM, "injects markup at runtime"),
        (r"ActiveXObject", "ActiveXObject", Severity.HIGH, "ActiveX (classic Windows script malware)"),
        (r"WScript\.Shell", "WScript.Shell", Severity.HIGH, "executes shell commands"),
        (r"require\(\s*['\"]child_process['\"]", "child_process", Severity.MEDIUM, "spawns processes (Node.js)"),
    ],
    "vbscript": [
        (r"CreateObject\s*\(", "CreateObject", Severity.MEDIUM, "instantiates a COM object"),
        (r"WScript\.Shell", "WScript.Shell", Severity.HIGH, "executes shell commands"),
        (r"\.Run\b|\.Exec\b", ".Run/.Exec", Severity.HIGH, "runs an external command"),
        (r"\bpowershell\b", "powershell", Severity.MEDIUM, "invokes PowerShell"),
        (r"GetObject\s*\(", "GetObject", Severity.MEDIUM, "binds to a COM object"),
    ],
    "html": [
        (r"<script", "<script>", Severity.LOW, "embedded script block"),
        (r"<iframe", "<iframe>", Severity.MEDIUM, "iframe (possible drive-by / redirect)"),
        (r"\beval\s*\(", "eval()", Severity.HIGH, "executes a string as code"),
        (r"\bunescape\s*\(", "unescape()", Severity.MEDIUM, "common de-obfuscation step"),
        (r"ActiveXObject", "ActiveXObject", Severity.HIGH, "ActiveX instantiation"),
        (r"<meta[^>]+http-equiv=['\"]?refresh", "meta refresh", Severity.LOW, "automatic page redirect"),
    ],
    "php": [
        (r"\beval\s*\(", "eval()", Severity.HIGH, "executes a string as PHP (webshell)"),
        (r"\bbase64_decode\s*\(", "base64_decode", Severity.HIGH, "decodes payload (webshell pattern)"),
        (r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(", "command exec", Severity.HIGH, "runs OS commands"),
        (r"\bassert\s*\(", "assert()", Severity.MEDIUM, "can execute code (webshell)"),
        (r"\bgzinflate\s*\(", "gzinflate", Severity.MEDIUM, "decompresses obfuscated code"),
        (r"\$_(?:GET|POST|REQUEST|COOKIE)\b", "request superglobal", Severity.LOW, "reads attacker-controllable input"),
    ],
    "applescript": [
        (r"do shell script", "do shell script", Severity.HIGH, "runs a shell command from AppleScript"),
        (r"\bosascript\b", "osascript", Severity.MEDIUM, "executes AppleScript/JXA"),
        (r"with administrator privileges", "admin privileges", Severity.MEDIUM, "requests elevated privileges"),
        (r"\bkeystroke\b", "keystroke", Severity.LOW, "synthesises keystrokes"),
    ],
}

# Download + execution indicators per language, for the combo escalation.
_DOWNLOAD_RE = re.compile(
    r"DownloadString|DownloadFile|Invoke-WebRequest|Net\.WebClient|urllib|requests\.|"
    r"\bcurl\b|\bwget\b|bitsadmin|certutil|XMLHTTP|fetch\(|\biwr\b",
    re.IGNORECASE,
)
_EXEC_RE = re.compile(
    r"\beval\b|\bexec\b|Invoke-Expression|\bIEX\b|os\.system|subprocess|\.Run\b|"
    r"shell_exec|WScript\.Shell|\|\s*(?:ba)?sh\b|do shell script",
    re.IGNORECASE,
)
# Obfuscation markers.
_ESCAPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}|%[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})")


class ScriptAnalyzer(Analyzer):
    name = "code"

    def applies(self, ctx: FileContext) -> bool:
        return self._detect_language(ctx) is not None and _is_texty(ctx.data)

    def run(self, ctx: FileContext) -> AnalyzerResult:
        result = self._result()
        language = self._detect_language(ctx)
        if language is None:
            return result

        text = ctx.data[:4_000_000].decode("utf-8", "ignore")
        result.metadata = {"language": language, "line_count": text.count("\n") + 1}

        if language == "plist":
            self._analyze_plist(text, result)
            return result

        indicators: list[dict] = []
        max_sev = Severity.INFO
        for regex, title, sev, why in _PATTERNS.get(language, []):
            m = re.search(regex, text, re.IGNORECASE)
            if m:
                line = text.count("\n", 0, m.start()) + 1
                indicators.append(
                    {"pattern": title, "severity": sev.label, "why": why, "line": line}
                )
                max_sev = max(max_sev, sev)

        result.metadata["indicators"] = indicators

        if indicators:
            cluster = max_sev
            strong = [i for i in indicators if i["severity"] in ("medium", "high", "critical")]
            if len(strong) >= 3 and cluster < Severity.HIGH:
                cluster = Severity.HIGH
            result.add(
                id="code.suspicious_constructs",
                title=f"{len(indicators)} suspicious {language} construct(s)",
                description=(
                    f"This {language} source contains constructs commonly used in "
                    "malicious scripts (dynamic execution, downloads, obfuscation, "
                    "persistence or LOLBINs). Each match and its line number is "
                    "listed as evidence."
                ),
                severity=cluster,
                category="code",
                language=language,
                indicators=indicators,
            )

        # Download + execute in the same file is a strong dropper signal.
        if _DOWNLOAD_RE.search(text) and _EXEC_RE.search(text):
            result.add(
                id="code.download_execute",
                title="Downloads and executes remote content",
                description=(
                    "The script both retrieves remote content and executes code/"
                    "commands. This download-and-run pattern is the core of most "
                    "script-based droppers and loaders."
                ),
                severity=Severity.HIGH,
                category="code",
                language=language,
            )

        # Obfuscation heuristic.
        escapes = len(_ESCAPE_RE.findall(text))
        longest_line = max((len(l) for l in text.splitlines()), default=0)
        if escapes > 60 or longest_line > 2000:
            result.add(
                id="code.obfuscation",
                title="Likely obfuscated code",
                description=(
                    f"The script shows signs of obfuscation ({escapes} escape "
                    f"sequences, longest line {longest_line} chars). Obfuscation is "
                    "used to hide a script's true behaviour from reviewers and tools."
                ),
                severity=Severity.MEDIUM,
                category="code",
                escape_sequences=escapes,
                longest_line=longest_line,
            )

        return result

    def _analyze_plist(self, text: str, result: AnalyzerResult) -> None:
        low = text.lower()
        if "plist" not in low:
            return
        run_at_load = "runatload" in low and "<true" in low
        keep_alive = "keepalive" in low and "<true" in low
        launches = re.search(
            r"(curl|wget|/bin/sh|/bin/bash|osascript|python|/tmp/|/users/shared|base64)",
            text, re.IGNORECASE,
        )
        result.metadata["plist_persistence"] = bool(run_at_load or keep_alive)
        if (run_at_load or keep_alive) and launches:
            result.add(
                id="code.launchd_persistence",
                title="macOS launchd persistence with suspicious command",
                description=(
                    "This property list registers a LaunchAgent/LaunchDaemon that "
                    "runs automatically (RunAtLoad/KeepAlive) and invokes a shell, "
                    "downloader or interpreter. This is a common macOS persistence "
                    "and execution mechanism."
                ),
                severity=Severity.HIGH,
                category="code",
            )
        elif run_at_load or keep_alive:
            result.add(
                id="code.launchd_autostart",
                title="macOS launchd auto-start entry",
                description=(
                    "This property list configures a launchd job to start "
                    "automatically (RunAtLoad/KeepAlive). Verify the program it "
                    "launches is expected."
                ),
                severity=Severity.LOW,
                category="code",
            )

    @staticmethod
    def _detect_language(ctx: FileContext) -> str | None:
        ext = ctx.metadata.get("extension", "")
        if ext in _LANG_BY_EXT:
            return _LANG_BY_EXT[ext]
        # Content sniffing for missing / unknown extensions.
        head = ctx.data[:512]
        try:
            text = head.decode("utf-8")
        except UnicodeDecodeError:
            return None
        low = text.lower()
        if text.startswith("#!"):
            if "python" in low:
                return "python"
            if any(s in low for s in ("bash", "/sh", "zsh", "/sh\n")):
                return "shell"
        if "<?php" in low:
            return "php"
        if "<html" in low or "<!doctype html" in low:
            return "html"
        if low.lstrip().startswith("<?xml") and "plist" in low:
            return "plist"
        return None


def _is_texty(data: bytes) -> bool:
    """True if the leading bytes look like text (printable + whitespace)."""
    sample = data[:4096]
    if not sample:
        return False
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126 or b >= 0x80)
    return printable / len(sample) >= 0.85
