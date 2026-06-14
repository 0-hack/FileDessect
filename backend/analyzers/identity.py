"""Identity analyzer: hashes, file type, MIME, and basic sanity checks.

This always runs first and seeds shared metadata that downstream analyzers
rely on (``mime``, ``file_type``, hashes, extension mismatch flags).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from .base import Analyzer, AnalyzerResult, FileContext, Severity
from .utils import detect_runtime

try:  # python-magic is backed by libmagic; degrade gracefully if absent.
    import magic  # type: ignore

    _HAVE_MAGIC = True
except Exception:  # pragma: no cover - import guard
    _HAVE_MAGIC = False


# Magic-byte signatures used to detect a file's *real* type, independent of
# its extension. Used to flag masquerading files.
_MAGIC_SIGNATURES: list[tuple[bytes, str, set[str]]] = [
    (b"MZ", "windows-executable", {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl"}),
    (b"\x7fELF", "linux-executable", {"", ".so", ".elf", ".bin", ".o"}),
    (b"\xca\xfe\xba\xbe", "macho-fat", {"", ".dylib", ".bundle"}),
    (b"\xcf\xfa\xed\xfe", "macho-64", {"", ".dylib", ".bundle"}),
    (b"PK\x03\x04", "zip-archive", {".zip", ".jar", ".apk", ".docx", ".xlsx",
                                     ".pptx", ".odt", ".epub", ".war"}),
    (b"\x1f\x8b", "gzip", {".gz", ".tgz"}),
    (b"Rar!\x1a\x07", "rar-archive", {".rar"}),
    (b"7z\xbc\xaf\x27\x1c", "7z-archive", {".7z"}),
    (b"%PDF", "pdf", {".pdf"}),
    (b"\xd0\xcf\x11\xe0", "ole-compound", {".doc", ".xls", ".ppt", ".msi", ".msg"}),
    (b"\x89PNG", "png-image", {".png"}),
    (b"\xff\xd8\xff", "jpeg-image", {".jpg", ".jpeg"}),
    (b"GIF8", "gif-image", {".gif"}),
    (b"#!", "script", {".sh", ".bash", ".py", ".pl", ".rb"}),
]


class IdentityAnalyzer(Analyzer):
    name = "identity"

    def run(self, ctx: FileContext) -> AnalyzerResult:
        result = self._result()
        data = ctx.data

        # Cryptographic hashes — the universal handle for reputation lookups.
        hashes = {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

        mime = self._detect_mime(data, ctx.path)
        magic_type = self._detect_magic_desc(data, ctx.path)
        signature, real_kind = self._match_signature(data)

        extension = Path(ctx.filename).suffix.lower()

        # Detect statically-linked managed runtimes (Go/Rust). Their embedded
        # runtime and large symbol/string tables otherwise trip heuristics in
        # downstream analyzers, so we flag the toolchain for them to consult.
        runtime = detect_runtime(data)

        # Share with downstream analyzers.
        ctx.metadata.update(
            {
                "hashes": hashes,
                "mime": mime,
                "magic": magic_type,
                "extension": extension,
                "file_kind": real_kind,
                "runtime": runtime,
            }
        )

        result.metadata = {
            "filename": ctx.filename,
            "size": ctx.size,
            "hashes": hashes,
            "mime": mime,
            "magic": magic_type,
            "extension": extension or "(none)",
            "detected_kind": real_kind or "unknown",
            "runtime": runtime,
        }

        if runtime:
            result.add(
                id=f"identity.runtime.{runtime}",
                title=f"Built with the {runtime.capitalize()} toolchain",
                description=(
                    f"This binary is a statically-linked {runtime.capitalize()} "
                    "executable. Its runtime imports (e.g. memory-management APIs) "
                    "and large embedded symbol/string tables are expected and are "
                    "down-weighted to avoid false positives."
                ),
                severity=Severity.INFO,
                category="identity",
                runtime=runtime,
            )

        # Extension / content-type mismatch — a classic masquerading trick.
        if signature is not None and extension and extension not in signature[2]:
            result.add(
                id="identity.extension_mismatch",
                title="File extension does not match its real content",
                description=(
                    f"The file is named with a '{extension}' extension but its "
                    f"binary signature identifies it as '{real_kind}'. Files that "
                    "disguise their true type this way are frequently used to "
                    "trick users into running executables."
                ),
                severity=Severity.MEDIUM,
                category="identity",
                claimed_extension=extension,
                actual_type=real_kind,
            )

        # Double extension (e.g. invoice.pdf.exe).
        name_parts = ctx.filename.lower().split(".")
        risky_exec = {"exe", "scr", "com", "bat", "cmd", "js", "vbs", "ps1"}
        doc_exts = {"pdf", "doc", "docx", "jpg", "png", "txt", "xls"}
        if len(name_parts) >= 3 and name_parts[-1] in risky_exec and name_parts[-2] in doc_exts:
            result.add(
                id="identity.double_extension",
                title="Deceptive double file extension",
                description=(
                    f"The filename '{ctx.filename}' uses a double extension that "
                    "makes an executable look like a document. This is a common "
                    "social-engineering technique in phishing attachments."
                ),
                severity=Severity.HIGH,
                category="identity",
                filename=ctx.filename,
            )

        return result

    @staticmethod
    def _detect_mime(data: bytes, path: str) -> str:
        if _HAVE_MAGIC:
            try:
                return magic.from_buffer(data, mime=True)
            except Exception:  # pragma: no cover
                pass
        return "application/octet-stream"

    @staticmethod
    def _detect_magic_desc(data: bytes, path: str) -> str:
        if _HAVE_MAGIC:
            try:
                return magic.from_buffer(data)
            except Exception:  # pragma: no cover
                pass
        return "data"

    @staticmethod
    def _match_signature(data: bytes):
        for sig in _MAGIC_SIGNATURES:
            if data.startswith(sig[0]):
                return sig, sig[1]
        return None, None
