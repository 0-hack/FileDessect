"""Interactive disassembly session store (opt-in).

When ``INTERACTIVE_DISASM`` is enabled, an analysed native binary is kept on
disk for a short TTL so the UI can drive the Rizin engine against it on demand
(disassemble or decompile any function) — a lightweight "Cutter in the browser".

This is deliberately simple and in-process: session metadata lives in a dict and
the sample bytes in an isolated file. That is sufficient for the default
single-worker deployment; a multi-worker setup would need a shared store. Every
access purges expired sessions, and samples are removed on expiry or on demand,
so retention stays bounded.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass
class _Session:
    path: Path
    filename: str
    expires_at: float


class SessionStore:
    def __init__(self, base_dir: Path, ttl_seconds: int) -> None:
        self._base = Path(base_dir)
        self._ttl = ttl_seconds
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.Lock()
        self._base.mkdir(parents=True, exist_ok=True)

    def create(self, data: bytes, filename: str) -> str:
        self.purge_expired()
        sid = uuid.uuid4().hex
        path = self._base / f"{sid}.bin"
        path.write_bytes(data)
        with self._lock:
            self._sessions[sid] = _Session(
                path=path,
                filename=filename,
                expires_at=time.time() + self._ttl,
            )
        return sid

    def get(self, sid: str) -> _Session | None:
        self.purge_expired()
        with self._lock:
            return self._sessions.get(sid)

    def path(self, sid: str) -> str | None:
        sess = self.get(sid)
        return str(sess.path) if sess else None

    def delete(self, sid: str) -> bool:
        with self._lock:
            sess = self._sessions.pop(sid, None)
        if not sess:
            return False
        self._unlink(sess.path)
        return True

    def purge_expired(self) -> None:
        now = time.time()
        with self._lock:
            expired = [sid for sid, s in self._sessions.items() if s.expires_at <= now]
            sessions = [self._sessions.pop(sid) for sid in expired]
        for sess in sessions:
            self._unlink(sess.path)

    @property
    def ttl_seconds(self) -> int:
        return self._ttl

    @staticmethod
    def _unlink(path: Path) -> None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
