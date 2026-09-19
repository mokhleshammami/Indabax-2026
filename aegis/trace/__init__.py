"""Lane C — the observability layer: trace emission, storage, and the viewer.

PUBLIC API (frozen — `aegis/defense.py` imports exactly these names):

    class TraceEmitter:
        def __init__(self, path: str | Path | None = None) -> None: ...
        def emit(self, record: TraceRecord) -> None: ...
        def close(self) -> None: ...

`emit` must never raise and must never block the decision path. Default sink is
`traces/<run_id>.jsonl`, one `TraceRecord` per line (see SCHEMA.md).

Lane C may add any modules under `aegis/trace/` plus everything in `viewer/`; it
must keep these three signatures stable.

The implementation below is a *placeholder* so the pipeline runs from day one.
Lane C replaces it.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from aegis.types import TraceRecord

DEFAULT_TRACE_DIR = Path(os.environ.get("AEGIS_TRACE_DIR", "traces"))


class TraceEmitter:
    """Minimal JSONL sink — replaced by Lane C with the full observability layer."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else None
        self._lock = threading.Lock()
        self._handles: dict[str, object] = {}

    def emit(self, record: TraceRecord) -> None:
        try:
            target = self._path or (DEFAULT_TRACE_DIR / f"{record.run_id}.jsonl")
            target.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps(record.to_json(), separators=(",", ":"), default=str)
            with self._lock, target.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except Exception:
            pass

    def close(self) -> None:
        return None


__all__ = ["DEFAULT_TRACE_DIR", "TraceEmitter"]
