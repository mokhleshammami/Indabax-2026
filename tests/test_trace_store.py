"""Lane C — the store: grouping, ordering, legacy splitting, and the outcome join."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegis.trace.store import CURRENT_SCHEMA, TraceStore, load_outcome_candidates, load_outcomes


def record(
    step_id: int,
    *,
    run_id: str = "finance_case-http_defense-s0",
    decision: str = "allow",
    risk: float = 0.1,
    reason_codes: list[str] | None = None,
    taint: dict[str, Any] | None = None,
    instance: str | None = "abc123",
    schema: str = CURRENT_SCHEMA,
    **extra: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": schema,
        "run_id": run_id,
        "step_id": step_id,
        "ts": f"2026-09-20T00:00:{step_id:02d}.000+00:00",
        "user_goal": "prepare the refund for review",
        "action": {"type": "tool_call", "tool": "payment_confirm", "arguments": {}},
        "observation": None,
        "taint": taint if taint is not None else {"action_taint": "authenticated_user", "chain": []},
        "authority": {"required": "commit", "available": "commit", "satisfied": True},
        "signals": [{"name": "plan_divergence", "score": 0.0, "reason_codes": [], "detail": {}}],
        "risk_score": risk,
        "confidence": 0.8,
        "decision": decision,
        "reason_codes": reason_codes if reason_codes is not None else ["USER_GOAL_ALIGNED"],
        "explanation": "fine",
        "rewritten_action": None,
        "latency_ms": 1.0 + step_id,
        "outcome": None,
        "monitor": None,
    }
    payload.update(extra)
    if instance is not None:
        payload["_instance"] = instance
        payload["_seq"] = step_id
    return payload


def write_trace(path: Path, records: list[dict[str, Any]]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


# -- loading ----------------------------------------------------------------


def test_groups_lines_into_runs_ordered_by_step(tmp_path: Path) -> None:
    write_trace(tmp_path / "a.jsonl", [record(3), record(1), record(2)])
    store = TraceStore.load(tmp_path)

    assert len(store) == 1
    run = store.runs[0]
    assert [step.step_id for step in run.steps] == [1, 2, 3]
    assert run.scenario_id == "finance_case"
    assert run.domain == "finance"
    assert run.user_goal.startswith("prepare the refund")


def test_legacy_file_with_several_appended_runs_resolves_to_the_latest(tmp_path: Path) -> None:
    """Files written by the placeholder emitter carry no instance tag."""
    old = [record(i, instance=None, decision="allow") for i in (1, 2, 3)]
    new = [record(i, instance=None, decision="block") for i in (1, 2)]
    write_trace(tmp_path / "a.jsonl", old + new)

    store = TraceStore.load(tmp_path)
    run = store.runs[0]
    assert [s.step_id for s in run.steps] == [1, 2]
    assert {s.decision for s in run.steps} == {"block"}


def test_all_instances_can_be_kept_when_asked(tmp_path: Path) -> None:
    write_trace(
        tmp_path / "a.jsonl",
        [record(1, instance="i1"), record(2, instance="i1"), record(1, instance="i2")],
    )
    store = TraceStore.load(tmp_path, keep_all_instances=True)
    assert len(store) == 2
    assert all("#" in run.run_id for run in store.runs)


def test_sub_directories_are_ignored_unless_recursive(tmp_path: Path) -> None:
    write_trace(tmp_path / "a.jsonl", [record(1)])
    write_trace(tmp_path / "ablations" / "no_taint.jsonl", [record(1, run_id="other-run-s0")])

    assert len(TraceStore.load(tmp_path)) == 1
    assert len(TraceStore.load(tmp_path, recursive=True)) == 2


def test_malformed_lines_and_empty_files_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    path.write_text(
        "\n".join(["not json", json.dumps(record(1)), "", json.dumps({"no": "run id"})]) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "empty.jsonl").write_text("", encoding="utf-8")

    store = TraceStore.load(tmp_path)
    assert len(store) == 1
    assert len(store.runs[0].steps) == 1


def test_missing_directory_yields_an_empty_store(tmp_path: Path) -> None:
    store = TraceStore.load(tmp_path / "nope")
    assert len(store) == 0
    assert store.summary()["runs"] == 0


def test_records_with_missing_optional_fields_still_load(tmp_path: Path) -> None:
    thin = {"schema": CURRENT_SCHEMA, "run_id": "r-x-s0", "step_id": 1, "decision": "allow"}
    write_trace(tmp_path / "a.jsonl", [thin])
    step = TraceStore.load(tmp_path).runs[0].steps[0]
    assert step.monitor is None and step.outcome is None
    assert step.signals == [] and step.taint == {} and step.risk == 0.0


# -- querying and aggregates ------------------------------------------------


def test_find_filters_by_decision_reason_and_domain(tmp_path: Path) -> None:
    write_trace(
        tmp_path / "a.jsonl",
        [
            record(1),
            record(2, decision="block", risk=0.9, reason_codes=["AUTHORITY_EXCEEDS_PROVENANCE"]),
        ],
    )
    store = TraceStore.load(tmp_path)

    assert len(store.find(decision="block")) == 1
    assert len(store.find(reason_code="AUTHORITY_EXCEEDS_PROVENANCE")) == 1
    assert len(store.find(domain="finance", min_risk=0.5)) == 1
    assert store.find(domain="soc") == []


def test_headline_step_is_the_riskiest_flagged_decision(tmp_path: Path) -> None:
    write_trace(
        tmp_path / "a.jsonl",
        [record(1), record(2, decision="escalate", risk=0.5), record(3, decision="block", risk=0.99)],
    )
    run = TraceStore.load(tmp_path).runs[0]
    assert run.headline_step is not None and run.headline_step.step_id == 3


def test_summary_counts_decisions_reasons_and_latency(tmp_path: Path) -> None:
    write_trace(
        tmp_path / "a.jsonl",
        [record(1), record(2, decision="block", risk=0.95, reason_codes=["X"])],
    )
    summary = TraceStore.load(tmp_path).summary()

    assert summary["steps"] == 2
    assert summary["decisions"]["block"] == 1
    assert dict(summary["reason_codes"])["X"] == 1
    assert summary["latency"]["p95"] >= summary["latency"]["median"]
    assert sum(bucket["count"] for bucket in summary["risk_histogram"]) == 2
    assert summary["by_domain"]["finance"]["allow"] == 1


# -- outcome join -----------------------------------------------------------


def write_artifact(
    directory: Path,
    run_id: str,
    *,
    decisions: list[tuple[int, str]],
    attack_success: bool = False,
    events: list[dict[str, Any]] | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    summary = {
        "run_id": run_id,
        "scenario_id": run_id.split("-")[0],
        "domain": "finance",
        "attack_present": True,
        "attack_family": "indirect_prompt_injection",
        "attack_success": attack_success,
        "task_success": True,
        "critical_violation": False,
        "termination": "completed",
        "grader_results": [{"condition": "no_effect(payment_execute)", "passed": True, "detail": ""}],
        "findings": [],
        "tool_executions": [{"step_id": 1, "tool": "payment_prepare", "succeeded": True, "legitimate": True}],
        "decisions": [
            {"step_id": sid, "decision": d, "legitimate": d == "allow", "consequential": d != "allow"}
            for sid, d in decisions
        ],
    }
    path = directory / f"{run_id}.summary.json"
    path.write_text(json.dumps(summary), encoding="utf-8")
    (directory / f"{run_id}.jsonl").write_text(
        "\n".join(json.dumps(e) for e in (events or [])) + "\n", encoding="utf-8"
    )
    return path


def test_join_attaches_run_and_step_outcomes(tmp_path: Path) -> None:
    run_id = "finance_case-http_defense-s0"
    write_trace(tmp_path / "traces" / "a.jsonl", [record(1), record(2, decision="block", risk=0.9)])
    write_artifact(
        tmp_path / "artifacts" / "eval-1",
        run_id,
        decisions=[(1, "allow"), (2, "block")],
        events=[
            {
                "type": "tool_result",
                "step_id": 1,
                "payload": {"effects": ["payment_prepare"], "succeeded": True, "result": {"id": "PAY-1"}},
            },
            {"type": "model_output", "step_id": 2, "payload": {"content": "Prepared for review."}},
        ],
    )

    store = TraceStore.load(tmp_path / "traces", artifacts=tmp_path / "artifacts")
    run = store.runs[0]
    assert run.outcome is not None and run.outcome["task_success"] is True
    assert run.attack_family == "indirect_prompt_injection"
    assert run.steps[0].outcome["effects"] == ["payment_prepare"]
    assert run.steps[0].outcome["executed"] is True
    assert run.steps[1].outcome["response"] == "Prepared for review."
    assert store.summary()["outcomes"]["asr"] == 0.0


def test_join_prefers_the_artifact_that_matches_this_trace(tmp_path: Path) -> None:
    """An ablation sweep writes artifacts under the same run id — newest must not win."""
    run_id = "finance_case-http_defense-s0"
    write_trace(tmp_path / "traces" / "a.jsonl", [record(1), record(2, decision="block", risk=0.9)])
    write_artifact(tmp_path / "artifacts" / "eval-real", run_id, decisions=[(1, "allow"), (2, "block")])
    later = write_artifact(
        tmp_path / "artifacts" / "eval-ablation",
        run_id,
        decisions=[(1, "allow"), (2, "allow")],
        attack_success=True,
    )
    import os

    os.utime(later, (2_000_000_000, 2_000_000_000))  # make the ablation the newest on disk

    store = TraceStore.load(tmp_path / "traces", artifacts=tmp_path / "artifacts")
    assert store.runs[0].outcome["attack_success"] is False, "joined the wrong run's outcome"
    assert "eval-real" in (store.runs[0].outcome_source or "")


def test_join_is_refused_when_no_artifact_agrees(tmp_path: Path) -> None:
    run_id = "finance_case-http_defense-s0"
    write_trace(tmp_path / "traces" / "a.jsonl", [record(i, decision="block") for i in (1, 2, 3)])
    write_artifact(
        tmp_path / "artifacts" / "eval-other",
        run_id,
        decisions=[(1, "allow"), (2, "allow"), (3, "allow")],
    )

    store = TraceStore.load(tmp_path / "traces", artifacts=tmp_path / "artifacts")
    assert store.runs[0].outcome is None
    assert store.health()["unjoined"] == [run_id]


def test_missing_artifacts_directory_is_not_fatal(tmp_path: Path) -> None:
    write_trace(tmp_path / "traces" / "a.jsonl", [record(1)])
    store = TraceStore.load(tmp_path / "traces", artifacts=tmp_path / "nowhere")
    assert store.runs[0].outcome is None
    assert load_outcomes(tmp_path / "nowhere") == {}


def test_outcome_candidates_are_grouped_by_run(tmp_path: Path) -> None:
    run_id = "finance_case-http_defense-s0"
    write_artifact(tmp_path / "a", run_id, decisions=[(1, "allow")])
    write_artifact(tmp_path / "b", run_id, decisions=[(1, "block")])
    candidates = load_outcome_candidates(tmp_path)
    assert len(candidates[run_id]) == 2


# -- data health ------------------------------------------------------------


def test_health_flags_legacy_and_stale_schema(tmp_path: Path) -> None:
    write_trace(tmp_path / "legacy.jsonl", [record(1, instance=None)])
    write_trace(tmp_path / "old.jsonl", [record(1, run_id="old-run-s0", schema="aegis.trace/v0")])

    health = TraceStore.load(tmp_path).health()
    codes = {
        problem["code"]
        for problems in health["runs_with_problems"].values()
        for problem in problems
    }
    assert {"NO_RUN_INSTANCE", "SCHEMA_MISMATCH"} <= codes
    assert health["errors"] >= 2


def test_health_is_clean_for_a_current_joined_run(tmp_path: Path) -> None:
    run_id = "finance_case-http_defense-s0"
    write_trace(tmp_path / "traces" / "a.jsonl", [record(1), record(2, decision="block")])
    write_artifact(tmp_path / "artifacts" / "eval-1", run_id, decisions=[(1, "allow"), (2, "block")])

    health = TraceStore.load(tmp_path / "traces", artifacts=tmp_path / "artifacts").health()
    assert health["errors"] == 0
    assert health["warnings"] == 0
    assert health["joined"] == 1
    assert health["emitted_first"] is not None
