"""Lane C — the observability layer: trace emission, storage, and the viewer.

PUBLIC API (frozen — `aegis/defense.py` imports exactly these names):

    class TraceEmitter:
        def __init__(self, path: str | Path | None = None) -> None: ...
        def emit(self, record: TraceRecord) -> None: ...
        def close(self) -> None: ...

`emit` must never raise and must never block the decision path. Default sink is
`traces/<run_id>.jsonl`, one `TraceRecord` per line (see SCHEMA.md).

Design notes
------------

*Non-blocking.* `emit` serializes nothing and touches no file. It hands the record
to an unbounded in-process queue that a daemon writer thread drains. The decision
path pays a queue append (order of microseconds) and nothing else. If the queue
ever grows past `_MAX_QUEUE`, records are dropped rather than allowed to consume
memory — the counter is visible in :meth:`TraceEmitter.stats`.

*Run identity.* The placeholder appended, so re-running a scenario stacked several
runs into one file and the viewer showed stale duplicates. Every write here belongs
to a **run instance**: a fresh instance starts when this process first writes to a
file, and again whenever a record arrives whose `step_id` does not advance the one
before it (a scenario restarted). Starting an instance truncates the file, so a
trace file always resolves to exactly one coherent run. Each line carries
`_instance` (an id shared by the lines of one instance) and `_seq`, so a consumer
can still split a file that was concatenated by other means — which is what
`aegis.trace.store` does for files written before this change.

Set ``AEGIS_TRACE_HISTORY=1`` to keep superseded instances: the previous file is
moved to ``<dir>/.history/<name>.<instance>.jsonl`` instead of being overwritten.

*Never raises.* Every public method is wrapped. A read-only directory, a vanished
mount, a record that will not serialize — all degrade to a dropped record.
"""

from __future__ import annotations

import atexit
import contextlib
import json
import os
import queue
import threading
import time
import uuid
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from aegis.types import TraceRecord

DEFAULT_TRACE_DIR = Path(os.environ.get("AEGIS_TRACE_DIR", "traces"))

#: Records queued but not yet written before we start dropping. Generous: a full
#: 19-scenario evaluation produces a couple of hundred records.
_MAX_QUEUE = 100_000

#: Sentinel pushed onto the queue by :meth:`TraceEmitter.close`.
_CLOSE = object()


def _keep_history() -> bool:
    return os.environ.get("AEGIS_TRACE_HISTORY", "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class _Sink:
    """One open trace file and the run instance currently being written to it."""

    path: Path
    handle: IO[str]
    instance: str
    seq: int = 0
    last_step: int | None = None


class TraceEmitter:
    """JSONL sink for :class:`~aegis.types.TraceRecord`.

    Parameters
    ----------
    path:
        Write every record to this single file. When omitted (the normal case)
        records are routed to ``<AEGIS_TRACE_DIR>/<run_id>.jsonl``, so one file
        holds one run.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._explicit_path: Path | None = None
        try:
            self._explicit_path = Path(path) if path is not None else None
        except Exception:  # pragma: no cover - Path() on something exotic
            self._explicit_path = None

        self._queue: queue.SimpleQueue[Any] = queue.SimpleQueue()
        self._thread: threading.Thread | None = None
        self._start_lock = threading.Lock()
        self._closed = False
        self._depth = 0  # approximate; incremented on emit, decremented on write
        self._depth_lock = threading.Lock()

        # Observability of the observability layer.
        self.emitted = 0
        self.written = 0
        self.dropped = 0

        self._sinks: dict[Path, _Sink] = {}
        self._keep_history = _keep_history()
        _register(self)

    # -- public API ---------------------------------------------------------
    def emit(self, record: TraceRecord) -> None:
        """Queue one record. Never raises, never touches the filesystem."""
        try:
            if self._closed:
                return
            if self._depth >= _MAX_QUEUE:
                self.dropped += 1
                return
            self._ensure_worker()
            with self._depth_lock:
                self._depth += 1
            self.emitted += 1
            self._queue.put(record)
        except Exception:
            with contextlib.suppress(Exception):
                self.dropped += 1

    def close(self) -> None:
        """Flush what is queued and close every open file. Never raises."""
        try:
            if self._closed:
                return
            self._closed = True
            thread = self._thread
            if thread is None:
                self._close_sinks()
                return
            self._queue.put(_CLOSE)
            thread.join(timeout=5.0)
            if thread.is_alive():  # pragma: no cover - writer wedged; do not hang the caller
                return
            self._close_sinks()
        except Exception:
            pass

    def flush(self, timeout: float = 2.0) -> bool:
        """Block until the queue drains. Test/CLI helper — not on the decision path."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._depth <= 0:
                return True
            time.sleep(0.002)
        return self._depth <= 0

    def stats(self) -> dict[str, int]:
        return {"emitted": self.emitted, "written": self.written, "dropped": self.dropped}

    @property
    def paths(self) -> list[Path]:
        """Files this emitter has written to, newest instance only."""
        return sorted(self._sinks)

    # -- worker -------------------------------------------------------------
    def _ensure_worker(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        with self._start_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            thread = threading.Thread(target=self._run, name="aegis-trace-writer", daemon=True)
            self._thread = thread
            thread.start()

    def _run(self) -> None:
        while True:
            try:
                item = self._queue.get()
            except Exception:  # pragma: no cover - interpreter teardown
                return
            if item is _CLOSE:
                return
            try:
                self._write(item)
            except Exception:
                self.dropped += 1
            finally:
                with self._depth_lock:
                    self._depth -= 1

    def _write(self, record: TraceRecord) -> None:
        payload = record.to_json()
        run_id = str(payload.get("run_id") or "unknown-run")
        step_id = payload.get("step_id")
        target = self._explicit_path or (DEFAULT_TRACE_DIR / f"{_safe_name(run_id)}.jsonl")

        sink = self._sinks.get(target)
        if sink is None or _is_new_instance(sink, step_id):
            sink = self._open_instance(target, previous=sink)
            if sink is None:
                self.dropped += 1
                return

        sink.seq += 1
        sink.last_step = step_id if isinstance(step_id, int) else sink.last_step
        payload["_instance"] = sink.instance
        payload["_seq"] = sink.seq
        line = json.dumps(payload, separators=(",", ":"), default=str, ensure_ascii=False)
        sink.handle.write(line + "\n")
        sink.handle.flush()
        self.written += 1

    def _open_instance(self, target: Path, previous: _Sink | None) -> _Sink | None:
        """Truncate (or rotate) `target` and open it for a fresh run instance."""
        if previous is not None:
            with contextlib.suppress(Exception):
                previous.handle.close()
            self._sinks.pop(target, None)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            if self._keep_history:
                self._archive(target)
            handle = target.open("w", encoding="utf-8")
        except Exception:
            return None
        sink = _Sink(path=target, handle=handle, instance=uuid.uuid4().hex[:12])
        self._sinks[target] = sink
        return sink

    def _archive(self, target: Path) -> None:
        if not target.exists() or target.stat().st_size == 0:
            return
        try:
            history = target.parent / ".history"
            history.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
            target.replace(history / f"{target.stem}.{stamp}.jsonl")
        except Exception:
            return

    def _close_sinks(self) -> None:
        for sink in list(self._sinks.values()):
            try:
                sink.handle.flush()
                sink.handle.close()
            except Exception:
                continue
        self._sinks.clear()

    # -- niceties -----------------------------------------------------------
    def __enter__(self) -> TraceEmitter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _is_new_instance(sink: _Sink, step_id: Any) -> bool:
    """A run restarted when its step counter stops advancing."""
    if not isinstance(step_id, int) or sink.last_step is None:
        return False
    return step_id <= sink.last_step


def _safe_name(run_id: str) -> str:
    keep = "-_.=+"
    cleaned = "".join(ch if (ch.isalnum() or ch in keep) else "_" for ch in run_id).strip("._")
    return cleaned or "unknown-run"


# -- process-exit flush ------------------------------------------------------
_live: weakref.WeakSet[TraceEmitter] = weakref.WeakSet()


def _register(emitter: TraceEmitter) -> None:
    with contextlib.suppress(Exception):  # pragma: no cover
        _live.add(emitter)


@atexit.register
def _close_all() -> None:  # pragma: no cover - exercised at interpreter exit
    for emitter in list(_live):
        with contextlib.suppress(Exception):
            emitter.close()


__all__ = ["DEFAULT_TRACE_DIR", "TraceEmitter"]
