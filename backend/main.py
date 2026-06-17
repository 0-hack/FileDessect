"""FileDessect FastAPI application.

Exposes a small JSON API plus a self-contained web UI:
  GET  /            -> upload UI
  GET  /api/health  -> liveness + feature availability
  POST /api/analyze -> upload a file, receive the full analysis report
"""
from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, rizin
from .config import get_settings
from .engine import Engine, scoring_model
from .sessions import SessionStore

settings = get_settings()
engine = Engine()

# Native-binary magics eligible for an interactive Rizin session.
_NATIVE_MAGICS = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa", b"\xce\xfa\xed\xfe",
                  b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")

# Session store is only instantiated when the opt-in feature is enabled.
_sessions: SessionStore | None = (
    SessionStore(settings.session_dir, settings.session_ttl_seconds)
    if settings.interactive_disasm
    else None
)


def _interactive_ready(data: bytes, size: int) -> bool:
    """Whether this upload can back an interactive Rizin session."""
    return (
        _sessions is not None
        and rizin.available()
        and size <= settings.max_interactive_bytes
        and any(data.startswith(m) for m in _NATIVE_MAGICS)
    )


def _require_session(sid: str) -> str:
    if _sessions is None:
        raise HTTPException(status_code=404, detail="Interactive sessions are disabled.")
    path = _sessions.path(sid)
    if not path:
        raise HTTPException(status_code=404, detail="Session not found or expired.")
    return path

app = FastAPI(
    title="FileDessect",
    version=__version__,
    description="Containerised file dissection & malware triage platform.",
)

_STATIC_DIR = Path(__file__).parent / "static"


@app.get("/api/health")
def health() -> dict:
    # Report which optional capabilities are actually available at runtime.
    def _have(module: str) -> bool:
        try:
            __import__(module)
            return True
        except Exception:
            return False

    return {
        "status": "ok",
        "version": __version__,
        "capabilities": {
            "file_type_detection": _have("magic"),
            "pe_analysis": _have("pefile"),
            "elf_analysis": _have("elftools"),
            "macho_analysis": True,
            "script_analysis": True,
            "disassembly": _have("capstone"),
            "rizin_engine": rizin.available(),
            "cutter_deep_analysis": rizin.available(),
            "interactive_disasm": _sessions is not None and rizin.available(),
            "yara_signatures": _have("yara"),
            "office_macros": _have("oletools"),
            "virustotal_live": bool(settings.vt_api_key),
        },
        "rizin_version": rizin.version(),
        "max_upload_mb": settings.max_upload_mb,
    }


@app.post("/api/analyze")
async def analyze(
    file: UploadFile = File(...),
    virustotal: bool = Form(True),
) -> JSONResponse:
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Empty file.")
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds the {settings.max_upload_mb} MB limit.",
        )

    filename = file.filename or "upload.bin"
    # Persist to an isolated, randomly named path. The file is only ever read,
    # never executed.
    stored = settings.upload_dir / f"{uuid.uuid4().hex}_{Path(filename).name}"
    try:
        stored.write_bytes(data)
        report = engine.analyze(
            path=str(stored),
            filename=filename,
            data=data,
            enable_virustotal=virustotal,
        )
    finally:
        # We do not retain samples by default.
        try:
            stored.unlink(missing_ok=True)
        except OSError:
            pass

    # Opt-in: keep a copy for a short TTL so the UI can drive Rizin on demand.
    if _interactive_ready(data, len(data)):
        sid = _sessions.create(data, filename)  # type: ignore[union-attr]
        report["session"] = {
            "id": sid,
            "ttl_seconds": _sessions.ttl_seconds,  # type: ignore[union-attr]
        }

    return JSONResponse(report)


# --------------------------------------------------------------------------- #
# Interactive disassembly session endpoints (only useful when enabled).
# --------------------------------------------------------------------------- #
@app.get("/api/session/{sid}/functions")
def session_functions(sid: str) -> dict:
    path = _require_session(sid)
    functions = rizin.function_list(path)
    if functions is None:
        raise HTTPException(status_code=503, detail="Rizin produced no function list.")
    return {"session": sid, "functions": functions}


@app.get("/api/session/{sid}/disasm")
def session_disasm(sid: str, target: str = Query(..., min_length=1, max_length=128)) -> dict:
    path = _require_session(sid)
    disasm = rizin.disassemble(path, target)
    if disasm is None:
        raise HTTPException(status_code=404, detail=f"No function disassembled at '{target}'.")
    return {"session": sid, "target": target, "disassembly": disasm}


@app.get("/api/session/{sid}/decompile")
def session_decompile(sid: str, target: str = Query(..., min_length=1, max_length=128)) -> dict:
    path = _require_session(sid)
    code = rizin.decompile(path, target)
    if code is None:
        raise HTTPException(
            status_code=404,
            detail="Decompilation unavailable (no rz-ghidra plugin, or invalid target).",
        )
    return {"session": sid, "target": target, "code": code}


@app.delete("/api/session/{sid}")
def session_delete(sid: str) -> dict:
    if _sessions is None:
        raise HTTPException(status_code=404, detail="Interactive sessions are disabled.")
    deleted = _sessions.delete(sid)
    return {"session": sid, "deleted": deleted}


@app.get("/api/scoring")
def scoring() -> dict:
    """The full scoring & verdict model used by the engine."""
    return scoring_model()


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")


@app.get("/scoring")
def scoring_page() -> FileResponse:
    return FileResponse(_STATIC_DIR / "scoring.html")


# Serve the rest of the static assets (style.css, app.js).
app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
