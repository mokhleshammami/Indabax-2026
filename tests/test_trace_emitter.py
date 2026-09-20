"""Lane C — the emitter must never raise, never block, and never mix runs."""

from __future__ import annotations

import json
import os
import stat
import threading
import time
from pathlib import Path

import pytest

from aegis.trace import TraceEmitter
from aegis.types import SCHEMA_VERSION, TraceRecord


def make_record(step_id: int = 1, run_id: str = "run-x", **overrides) -> TraceRecord:
    payload = {
        "run_id": run_id,
        "step_id": step_id,
        "ts": "2026-09-20T00:00:00.000+00:00",
        "user_goal": "prepare a refund for officer review",
        "action": {"type": "tool_call", "tool": "payment_confirm", "arguments": {"payment_id": "PAY-1"}},
        "observation": None,
        "taint": {"action_taint": "untrusted_external", "chain": []},
        "authority": {"required": "commit", "available": "read", "satisfied": False},
        "signals": [],
        "risk_score": 0.9,
        "confidence": 0.8,
        "decision": "block",
        "reason_codes": ["AUTHORITY_EXCEEDS_PROVENANCE"],
        "explanation": "a letter has no authority to confirm a payment",
        "rewritten_action": None,
        "latency_ms": 1.5,
    }
    payload.update(overrides)
    return TraceRecord(**payload)


def read_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# -- basics -----------------------------------------------------------------


def test_emits_one_json_line_per_record(tmp_path: Path) -> None:
    target = tmp_path / "run.jsonl"
    emitter = TraceEmitter(target)
    for step in (1, 2, 3):
        emitter.emit(make_record(step))
    emitter.close()

    lines = read_lines(target)
    assert [line["step_id"] for line in lines] == [1, 2, 3]
    assert all(line["schema"] == SCHEMA_VERSION for line in lines)
    assert lines[0]["decision"] == "block"


def test_default_sink_is_one_file_per_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import aegis.trace as trace_module

    monkeypatch.setattr(trace_module, "DEFAULT_TRACE_DIR", tmp_path / "traces")
    emitter = TraceEmitter()
    emitter.emit(make_record(1, run_id="finance_case-aegis-s0"))
    emitter.emit(make_record(1, run_id="soc_case-aegis-s0"))
    emitter.close()

    names = sorted(p.name for p in (tmp_path / "traces").glob("*.jsonl"))
    assert names == ["finance_case-aegis-s0.jsonl", "soc_case-aegis-s0.jsonl"]


def test_run_id_is_sanitized_into_a_filename(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import aegis.trace as trace_module

    monkeypatch.setattr(trace_module, "DEFAULT_TRACE_DIR", tmp_path / "traces")
    emitter = TraceEmitter()
    emitter.emit(make_record(1, run_id="../../etc/passwd"))
    emitter.close()

    written = list((tmp_path / "traces").glob("*.jsonl"))
    assert len(written) == 1
    assert written[0].parent == tmp_path / "traces"
    assert "/" not in written[0].name


def test_records_carry_run_instance_metadata(tmp_path: Path) -> None:
    target = tmp_path / "run.jsonl"
    emitter = TraceEmitter(target)
    emitter.emit(make_record(1))
    emitter.emit(make_record(2))
    emitter.close()

    lines = read_lines(target)
    assert len({line["_instance"] for line in lines}) == 1
    assert [line["_seq"] for line in lines] == [1, 2]


# -- the bug this module exists to fix --------------------------------------


def test_second_process_truncates_rather_than_appending(tmp_path: Path) -> None:
    target = tmp_path / "run.jsonl"
    first = TraceEmitter(target)
    first.emit(make_record(1))
    first.emit(make_record(2))
    first.close()

    second = TraceEmitter(target)
    second.emit(make_record(1))
    second.close()

    lines = read_lines(target)
    assert [line["step_id"] for line in lines] == [1], "a re-run must not stack onto the old one"


def test_restarting_a_run_in_one_process_starts_a_new_instance(tmp_path: Path) -> None:
    target = tmp_path / "run.jsonl"
    emitter = TraceEmitter(target)
    for step in (1, 2, 3):
        emitter.emit(make_record(step))
    for step in (1, 2):  # the scenario ran again against the same live service
        emitter.emit(make_record(step))
    emitter.close()

    lines = read_lines(target)
    assert [line["step_id"] for line in lines] == [1, 2], "only the latest instance survives"
    assert len({line["_instance"] for line in lines}) == 1


def test_history_is_kept_when_asked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_TRACE_HISTORY", "1")
    target = tmp_path / "run.jsonl"
    first = TraceEmitter(target)
    first.emit(make_record(1))
    first.close()

    second = TraceEmitter(target)
    second.emit(make_record(1))
    second.close()

    archived = list((tmp_path / ".history").glob("run.*.jsonl"))
    assert archived, "the superseded instance should be archived, not lost"
    assert read_lines(target)[0]["step_id"] == 1


# -- never raises -----------------------------------------------------------


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="root ignores directory permissions, so the failure cannot be provoked",
)
def test_emit_survives_an_unwritable_directory(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(stat.S_IREAD | stat.S_IEXEC)
    try:
        emitter = TraceEmitter(locked / "run.jsonl")
        emitter.emit(make_record(1))  # must not raise
        emitter.close()
        assert emitter.stats()["written"] == 0
    finally:
        locked.chmod(stat.S_IRWXU)


@pytest.mark.skipif(os.name != "posix", reason="needs a POSIX device file")
def test_emit_survives_a_path_that_is_not_a_file() -> None:
    emitter = TraceEmitter("/dev/null/run.jsonl")  # ENOTDIR on open
    emitter.emit(make_record(1))
    emitter.close()
    assert emitter.stats()["written"] == 0


def test_emit_survives_an_unserializable_record(tmp_path: Path) -> None:
    class Exploding:
        def __repr__(self) -> str:  # json.dumps(default=str) calls this
            raise RuntimeError("boom")

    target = tmp_path / "run.jsonl"
    emitter = TraceEmitter(target)
    emitter.emit(make_record(1, action={"type": "tool_call", "tool": Exploding()}))
    emitter.emit(make_record(2))  # the sink keeps working afterwards
    emitter.close()

    steps = [line["step_id"] for line in read_lines(target)]
    assert steps == [2]
    assert emitter.stats()["dropped"] == 1


def test_emit_after_close_is_a_no_op(tmp_path: Path) -> None:
    target = tmp_path / "run.jsonl"
    emitter = TraceEmitter(target)
    emitter.emit(make_record(1))
    emitter.close()
    emitter.emit(make_record(2))  # must not raise, must not resurrect the file
    assert [line["step_id"] for line in read_lines(target)] == [1]


def test_close_is_idempotent(tmp_path: Path) -> None:
    emitter = TraceEmitter(tmp_path / "run.jsonl")
    emitter.emit(make_record(1))
    emitter.close()
    emitter.close()


def test_emitter_works_as_a_context_manager(tmp_path: Path) -> None:
    target = tmp_path / "run.jsonl"
    with TraceEmitter(target) as emitter:
        emitter.emit(make_record(1))
    assert len(read_lines(target)) == 1


# -- never blocks -----------------------------------------------------------


def test_emit_does_not_block_the_decision_path(tmp_path: Path) -> None:
    emitter = TraceEmitter(tmp_path / "run.jsonl")
    records = [make_record(i + 1) for i in range(200)]

    started = time.perf_counter()
    for record in records:
        emitter.emit(record)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    emitter.close()

    # 200 emits are a queue append each; anything near file-IO cost would be slower.
    assert elapsed_ms < 100.0, f"emit is on the critical path: {elapsed_ms:.1f} ms for 200 records"
    assert emitter.stats()["written"] == 200


def test_emit_drops_instead_of_growing_without_bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import aegis.trace as trace_module

    monkeypatch.setattr(trace_module, "_MAX_QUEUE", 0)
    emitter = TraceEmitter(tmp_path / "run.jsonl")
    emitter.emit(make_record(1))
    emitter.close()
    assert emitter.stats()["dropped"] == 1


def test_concurrent_emitters_do_not_interleave_lines(tmp_path: Path) -> None:
    target = tmp_path / "run.jsonl"
    emitter = TraceEmitter(target)

    def worker(offset: int) -> None:
        for step in range(1, 21):
            emitter.emit(make_record(offset + step, run_id="run-x"))

    threads = [threading.Thread(target=worker, args=(base,)) for base in (0, 100, 200)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    emitter.close()

    lines = target.read_text(encoding="utf-8").splitlines()
    assert all(json.loads(line)["run_id"] == "run-x" for line in lines), "a partial line would fail to parse"


def test_flush_reports_when_the_queue_is_drained(tmp_path: Path) -> None:
    emitter = TraceEmitter(tmp_path / "run.jsonl")
    for step in range(1, 25):
        emitter.emit(make_record(step))
    assert emitter.flush(timeout=5.0) is True
    assert emitter.stats()["written"] == 24
    emitter.close()
