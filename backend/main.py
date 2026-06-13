"""FileDessect FastAPI application.

Exposes a small JSON API plus a self-contained web UI:
  GET  /            -> upload UI
  GET  /api/health  -> liveness + feature availability
  POST /api/analyze -> upload a file, receive the full analysis report
"""
from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import get_settings
from .engine import Engine, scoring_model

settings = get_settings()
engine = Engine()

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
            "yara_signatures": _have("yara"),
            "office_macros": _have("oletools"),
            "virustotal_live": bool(settings.vt_api_key),
        },
        "max_upload_mb": settings.max_upload_mb,
    }


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)) -> JSONResponse:
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
        report = engine.analyze(path=str(stored), filename=filename, data=data)
    finally:
        # We do not retain samples by default.
        try:
            stored.unlink(missing_ok=True)
        except OSError:
            pass

    return JSONResponse(report)


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
