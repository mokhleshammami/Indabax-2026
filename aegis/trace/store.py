"""Lane C — loading, indexing and querying AEGIS traces.

A trace directory is a pile of JSONL files, one decision per line (SCHEMA.md §4).
This module turns that pile into something a viewer or a report can ask questions
of:

* :class:`TraceStore` — load a directory, group lines into :class:`Run` objects,
  keep only the latest *run instance* of each run, order steps, and compute
  aggregate statistics.
* :class:`Run` / :class:`Step` — thin, read-only views over the raw records. The
  raw dict is always available as ``.record``; nothing is thrown away.
* :func:`load_outcomes` — optional join against the organizers' own simulator
  artifacts (``starter/artifacts/**``) so each run carries what actually happened
  (``task_success``, ``attack_success``, effects, findings) and each step carries
  what happened *next* (was the tool executed, with what effects).

Stdlib only.
"""

from __future__ import annotations

import json
import math
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DECISIONS = ("allow", "rewrite", "escalate", "block")

#: Schema this module reads. Mirrors `aegis.types.SCHEMA_VERSION`; kept literal so
#: the store stays importable with nothing but the standard library.
CURRENT_SCHEMA = "aegis.trace/v1"

#: Trust levels, most trusted first. Mirrors `aegis.types.TrustLevel` but kept
#: local so the store can read traces without importing the defense.
TRUST_ORDER = (
    "system_policy",
    "authenticated_user",
    "trusted_internal",
    "untrusted_internal",
    "untrusted_external",
    "adversary_controlled",
)

AUTHORITY_ORDER = ("none", "read", "prepare", "commit")

#: The rule the viewer exists to make visible.
TRUST_TO_MAX_AUTHORITY = {
    "system_policy": "commit",
    "authenticated_user": "commit",
    "trusted_internal": "prepare",
    "untrusted_internal": "prepare",
    "untrusted_external": "read",
    "adversary_controlled": "read",
}

DOMAINS = ("finance", "enterprise", "soc")


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Step:
    """One decision. `record` is the raw trace line; the rest is convenience."""

    record: dict[str, Any]

    @property
    def step_id(self) -> int:
        value = self.record.get("step_id")
        return value if isinstance(value, int) else 0

    @property
    def decision(self) -> str:
        return str(self.record.get("decision") or "unknown")

    @property
    def risk(self) -> float:
        return _as_float(self.record.get("risk_score"))

    @property
    def confidence(self) -> float:
        return _as_float(self.record.get("confidence"))

    @property
    def latency_ms(self) -> float:
        return _as_float(self.record.get("latency_ms"))

    @property
    def action(self) -> dict[str, Any]:
        value = self.record.get("action")
        return value if isinstance(value, dict) else {}

    @property
    def tool(self) -> str | None:
        tool = self.action.get("tool")
        return str(tool) if tool else None

    @property
    def action_type(self) -> str:
        return str(self.action.get("type") or "unknown")

    @property
    def taint(self) -> dict[str, Any]:
        value = self.record.get("taint")
        return value if isinstance(value, dict) else {}

    @property
    def authority(self) -> dict[str, Any]:
        value = self.record.get("authority")
        return value if isinstance(value, dict) else {}

    @property
    def signals(self) -> list[dict[str, Any]]:
        value = self.record.get("signals")
        return [s for s in value if isinstance(s, dict)] if isinstance(value, list) else []

    @property
    def monitor(self) -> dict[str, Any] | None:
        value = self.record.get("monitor")
        return value if isinstance(value, dict) else None

    @property
    def outcome(self) -> dict[str, Any] | None:
        value = self.record.get("outcome")
        return value if isinstance(value, dict) else None

    @property
    def reason_codes(self) -> list[str]:
        value = self.record.get("reason_codes")
        return [str(c) for c in value] if isinstance(value, list) else []

    @property
    def action_taint(self) -> str | None:
        value = self.taint.get("action_taint")
        return str(value) if value else None

    @property
    def is_interesting(self) -> bool:
        """Steps a presenter should jump to: anything that was not a plain allow."""
        return self.decision in {"block", "escalate", "rewrite"}


@dataclass
class Run:
    """All decisions for one scenario run, ordered by step."""

    run_id: str
    steps: list[Step] = field(default_factory=list)
    source: Path | None = None
    instance: str | None = None
    outcome: dict[str, Any] | None = None
    #: Where the joined simulator artifact came from, and how well it matched.
    outcome_source: str | None = None
    outcome_match: float | None = None

    # -- identity ----------------------------------------------------------
    @property
    def scenario_id(self) -> str:
        if isinstance(self.outcome, dict) and self.outcome.get("scenario_id"):
            return str(self.outcome["scenario_id"])
        # run ids look like "<scenario>-<defense>-s<seed>"
        parts = self.run_id.rsplit("-", 2)
        return parts[0] if len(parts) == 3 else self.run_id

    @property
    def domain(self) -> str:
        if isinstance(self.outcome, dict) and self.outcome.get("domain"):
            return str(self.outcome["domain"])
        head = self.scenario_id.split("_", 1)[0]
        return head if head in DOMAINS else "other"

    @property
    def user_goal(self) -> str:
        for step in self.steps:
            goal = step.record.get("user_goal")
            if goal:
                return str(goal)
        return ""

    # -- shape -------------------------------------------------------------
    @property
    def decision_counts(self) -> dict[str, int]:
        counts = dict.fromkeys(DECISIONS, 0)
        for step in self.steps:
            counts[step.decision] = counts.get(step.decision, 0) + 1
        return counts

    @property
    def max_risk(self) -> float:
        return max((s.risk for s in self.steps), default=0.0)

    @property
    def worst_trust(self) -> str | None:
        """Least-trusted level seen anywhere in the run's influence chains."""
        worst: int | None = None
        for step in self.steps:
            for level in (step.taint.get("action_taint"), step.taint.get("context_taint")):
                if isinstance(level, str) and level in TRUST_ORDER:
                    rank = TRUST_ORDER.index(level)
                    worst = rank if worst is None else max(worst, rank)
        return TRUST_ORDER[worst] if worst is not None else None

    @property
    def headline_step(self) -> Step | None:
        """The step a presenter should land on: the riskiest non-allow decision."""
        blocked = [s for s in self.steps if s.is_interesting]
        if blocked:
            return max(blocked, key=lambda s: (s.decision == "block", s.risk))
        return max(self.steps, key=lambda s: s.risk, default=None)

    @property
    def reason_codes(self) -> Counter[str]:
        counter: Counter[str] = Counter()
        for step in self.steps:
            counter.update(step.reason_codes)
        return counter

    @property
    def attack_family(self) -> str:
        if isinstance(self.outcome, dict):
            if self.outcome.get("attack_present") is False:
                return "benign"
            family = self.outcome.get("attack_family")
            if family and str(family) != "none":
                return str(family)
            if self.outcome.get("attack_present"):
                return "attack"
        return "unknown"

    @property
    def latency_p95(self) -> float:
        return _percentile([s.latency_ms for s in self.steps], 95)

    def step(self, step_id: int) -> Step | None:
        for step in self.steps:
            if step.step_id == step_id:
                return step
        return None

    # -- provenance of the trace itself ------------------------------------
    @property
    def schema_versions(self) -> list[str]:
        return sorted({str(s.record.get("schema") or "missing") for s in self.steps})

    @property
    def emitted_range(self) -> tuple[str | None, str | None]:
        stamps = sorted(str(s.record.get("ts")) for s in self.steps if s.record.get("ts"))
        return (stamps[0], stamps[-1]) if stamps else (None, None)

    @property
    def has_instance_metadata(self) -> bool:
        """False for files written by the pre-`_instance` emitter — i.e. possibly stale."""
        return bool(self.steps) and all(s.record.get("_instance") for s in self.steps)

    def health(self, *, expected_schema: str = CURRENT_SCHEMA) -> list[dict[str, str]]:
        """Everything about this run's data that a viewer should not hide."""
        problems: list[dict[str, str]] = []
        versions = [v for v in self.schema_versions if v != expected_schema]
        if versions:
            problems.append({
                "level": "error",
                "code": "SCHEMA_MISMATCH",
                "message": f"records carry schema {', '.join(versions)}; this build expects {expected_schema}",
            })
        if not self.has_instance_metadata:
            problems.append({
                "level": "error",
                "code": "NO_RUN_INSTANCE",
                "message": "written by an emitter without run-instance tagging — the file may mix several runs",
            })
        if self.outcome is None:
            problems.append({
                "level": "warning",
                "code": "NO_OUTCOME",
                "message": "no simulator artifact matched this run, so 'what happened next' is unknown",
            })
        elif self.outcome_match is not None and self.outcome_match < 0.95:
            problems.append({
                "level": "warning",
                "code": "OUTCOME_PARTIAL_MATCH",
                "message": (
                    f"the matched simulator artifact agrees with only "
                    f"{round(self.outcome_match * 100)}% of this run's decisions"
                ),
            })
        return problems


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class TraceStore:
    """A directory (or a set of files) of AEGIS traces, indexed by run."""

    def __init__(self, runs: Iterable[Run] | None = None) -> None:
        self.runs: list[Run] = list(runs or [])
        self._by_id: dict[str, Run] = {run.run_id: run for run in self.runs}

    # -- loading -----------------------------------------------------------
    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        artifacts: str | Path | None = None,
        keep_all_instances: bool = False,
        recursive: bool = False,
    ) -> TraceStore:
        """Load every ``*.jsonl`` in `path` (a file or a directory).

        Only the **latest run instance** of each run survives, so a file that was
        appended to across several runs resolves to one coherent run. Pass
        ``keep_all_instances=True`` to get every instance as its own :class:`Run`
        (ids get a ``#<instance>`` suffix). Sub-directories are ignored unless
        `recursive` — an ablation sweep pointed at ``traces/ablations/...`` must
        not silently overwrite the full system's runs.
        """
        root = Path(path)
        files = _trace_files(root, recursive=recursive)
        runs: list[Run] = []
        for file in files:
            runs.extend(_runs_from_file(file, keep_all_instances=keep_all_instances))

        # A run id can legitimately appear in more than one file; last write wins.
        merged: dict[str, Run] = {}
        for run in runs:
            existing = merged.get(run.run_id)
            if existing is None or _mtime(run.source) >= _mtime(existing.source):
                merged[run.run_id] = run

        ordered = sorted(merged.values(), key=lambda r: (r.domain, r.scenario_id, r.run_id))
        store = cls(ordered)
        if artifacts is not None:
            store.attach_outcomes(artifacts)
        return store

    def attach_outcomes(self, artifacts: str | Path) -> int:
        """Join the simulator's own artifacts in. Returns the number of runs joined.

        A scenario is usually replayed many times while a team iterates — and an
        ablation sweep writes artifacts under the same run id as the full system.
        So the candidate artifact chosen for a run is the one whose recorded
        decisions **agree with this trace**, not simply the newest one.
        """
        candidates = load_outcome_candidates(artifacts)
        joined = 0
        for run in self.runs:
            outcome = _best_candidate(run, candidates.get(run.run_id, []))
            if outcome is None:
                continue
            run.outcome = outcome["run"]
            run.outcome_source = outcome.get("source")
            run.outcome_match = outcome.get("_match")
            per_step = outcome["steps"]
            for step in run.steps:
                detail = per_step.get(step.step_id)
                if detail:
                    step.record["outcome"] = detail
            joined += 1
        return joined

    def health(self, *, expected_schema: str = CURRENT_SCHEMA) -> dict[str, Any]:
        """Problems with the *data* — stale traces, unjoined runs, wrong schema.

        The viewer shows this on its face. A build that silently renders a trace
        from an earlier era of the defense is worse than no build at all.
        """
        per_run: dict[str, list[dict[str, str]]] = {}
        errors = 0
        warnings = 0
        for run in self.runs:
            problems = run.health(expected_schema=expected_schema)
            if problems:
                per_run[run.run_id] = problems
            errors += sum(1 for p in problems if p["level"] == "error")
            warnings += sum(1 for p in problems if p["level"] == "warning")
        stamps = sorted(
            str(step.record.get("ts")) for step in self.steps() if step.record.get("ts")
        )
        return {
            "expected_schema": expected_schema,
            "errors": errors,
            "warnings": warnings,
            "runs_with_problems": per_run,
            "emitted_first": stamps[0] if stamps else None,
            "emitted_last": stamps[-1] if stamps else None,
            "joined": sum(1 for run in self.runs if run.outcome is not None),
            "unjoined": [run.run_id for run in self.runs if run.outcome is None],
        }

    # -- querying ----------------------------------------------------------
    def __len__(self) -> int:
        return len(self.runs)

    def __iter__(self) -> Iterator[Run]:
        return iter(self.runs)

    def get(self, run_id: str) -> Run | None:
        return self._by_id.get(run_id)

    def by_domain(self) -> dict[str, list[Run]]:
        grouped: dict[str, list[Run]] = defaultdict(list)
        for run in self.runs:
            grouped[run.domain].append(run)
        return dict(grouped)

    def steps(self) -> Iterator[Step]:
        for run in self.runs:
            yield from run.steps

    def find(
        self,
        *,
        decision: str | None = None,
        reason_code: str | None = None,
        domain: str | None = None,
        tool: str | None = None,
        min_risk: float | None = None,
    ) -> list[tuple[Run, Step]]:
        """Every (run, step) matching all of the given filters."""
        hits: list[tuple[Run, Step]] = []
        for run in self.runs:
            if domain and run.domain != domain:
                continue
            for step in run.steps:
                if decision and step.decision != decision:
                    continue
                if reason_code and reason_code not in step.reason_codes:
                    continue
                if tool and step.tool != tool:
                    continue
                if min_risk is not None and step.risk < min_risk:
                    continue
                hits.append((run, step))
        return hits

    # -- aggregates --------------------------------------------------------
    def summary(self) -> dict[str, Any]:
        steps = list(self.steps())
        decisions: Counter[str] = Counter(s.decision for s in steps)
        reason_codes: Counter[str] = Counter()
        for step in steps:
            reason_codes.update(step.reason_codes)

        latencies = [s.latency_ms for s in steps]
        risks = [s.risk for s in steps]

        by_family: dict[str, Counter[str]] = defaultdict(Counter)
        by_domain: dict[str, Counter[str]] = defaultdict(Counter)
        for run in self.runs:
            for step in run.steps:
                by_family[run.attack_family][step.decision] += 1
                by_domain[run.domain][step.decision] += 1

        joined = [r for r in self.runs if isinstance(r.outcome, dict)]
        benign = [r for r in joined if r.outcome and not r.outcome.get("attack_present")]
        attacks = [r for r in joined if r.outcome and r.outcome.get("attack_present")]

        escalations = decisions.get("escalate", 0)
        total = len(steps) or 1

        return {
            "runs": len(self.runs),
            "steps": len(steps),
            "decisions": {d: decisions.get(d, 0) for d in DECISIONS},
            "decision_other": sum(v for k, v in decisions.items() if k not in DECISIONS),
            "reason_codes": reason_codes.most_common(),
            "risk_histogram": _histogram(risks, bins=10),
            "risk_by_decision": {
                d: _describe([s.risk for s in steps if s.decision == d]) for d in DECISIONS
            },
            "latency": {
                "median": _percentile(latencies, 50),
                "p95": _percentile(latencies, 95),
                "max": max(latencies, default=0.0),
            },
            "escalation_rate": round(escalations / total, 4),
            "block_rate": round(decisions.get("block", 0) / total, 4),
            "by_attack_family": {k: dict(v) for k, v in sorted(by_family.items())},
            "by_domain": {k: dict(v) for k, v in sorted(by_domain.items())},
            "outcomes": {
                "joined": len(joined),
                "benign": len(benign),
                "attacks": len(attacks),
                "task_success": sum(1 for r in joined if r.outcome and r.outcome.get("task_success")),
                "attack_success": sum(1 for r in attacks if r.outcome and r.outcome.get("attack_success")),
                "critical_violation": sum(
                    1 for r in joined if r.outcome and r.outcome.get("critical_violation")
                ),
                "btu": _ratio(
                    sum(1 for r in benign if r.outcome and r.outcome.get("task_success")), len(benign)
                ),
                "asr": _ratio(
                    sum(1 for r in attacks if r.outcome and r.outcome.get("attack_success")), len(attacks)
                ),
                "cvr": _ratio(
                    sum(1 for r in joined if r.outcome and r.outcome.get("critical_violation")), len(joined)
                ),
            },
        }


# ---------------------------------------------------------------------------
# Loading helpers
# ---------------------------------------------------------------------------


def _trace_files(root: Path, *, recursive: bool = False) -> list[Path]:
    if root.is_file():
        return [root]
    if not root.is_dir():
        return []
    found = root.rglob("*.jsonl") if recursive else root.glob("*.jsonl")
    return [p for p in sorted(found) if not _hidden(p, root)]


def _hidden(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:  # pragma: no cover
        return False
    return any(part.startswith(".") for part in rel.parts)


def _runs_from_file(file: Path, *, keep_all_instances: bool) -> list[Run]:
    """Split one file into run instances.

    Boundaries come from the emitter's `_instance` annotation when present; for
    files written before that existed, a step counter that fails to advance marks
    a new instance.
    """
    records: list[dict[str, Any]] = []
    try:
        with file.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if isinstance(record, dict) and record.get("run_id"):
                    records.append(record)
    except OSError:
        return []

    if not records:
        return []

    groups: list[tuple[str | None, list[dict[str, Any]]]] = []
    last_key: tuple[str, Any] | None = None
    last_step: int | None = None
    for record in records:
        instance = record.get("_instance")
        run_id = str(record.get("run_id"))
        step_id = record.get("step_id")
        key = (run_id, instance)
        boundary = (
            last_key is None
            or key != last_key
            or (
                instance is None
                and isinstance(step_id, int)
                and isinstance(last_step, int)
                and step_id <= last_step
            )
        )
        if boundary:
            groups.append((instance if isinstance(instance, str) else None, []))
        groups[-1][1].append(record)
        last_key = key
        last_step = step_id if isinstance(step_id, int) else last_step

    if not keep_all_instances:
        # Keep the last instance of each run id — that is "the latest run".
        latest: dict[str, tuple[str | None, list[dict[str, Any]]]] = {}
        for instance, group in groups:
            latest[str(group[0].get("run_id"))] = (instance, group)
        groups = list(latest.values())

    runs: list[Run] = []
    for index, (instance, group) in enumerate(groups):
        run_id = str(group[0].get("run_id"))
        label = run_id
        if keep_all_instances and len(groups) > 1:
            label = f"{run_id}#{instance or index + 1}"
        steps = [Step(record=record) for record in group]
        steps.sort(key=lambda s: (s.step_id, _as_int(s.record.get("_seq"))))
        runs.append(Run(run_id=label, steps=steps, source=file, instance=instance))
    return runs


# ---------------------------------------------------------------------------
# Outcome join — the simulator's own artifacts
# ---------------------------------------------------------------------------

#: Event types in the simulator's run JSONL that describe what happened after a
#: decision. See `starter/src/sentinel/evaluator/replay.py`.
_EFFECT_EVENTS = {"tool_result", "retrieval_result", "memory_write_result"}


def load_outcomes(artifacts: str | Path) -> dict[str, dict[str, Any]]:
    """Read the simulator's artifacts into ``{run_id: {run, steps}}``, newest wins.

    Prefer :func:`load_outcome_candidates` when a trace is available to match
    against: several artifacts can share a run id (re-runs, ablation sweeps).
    """
    return {
        run_id: candidates[-1]
        for run_id, candidates in load_outcome_candidates(artifacts).items()
        if candidates
    }


def load_outcome_candidates(artifacts: str | Path) -> dict[str, list[dict[str, Any]]]:
    """Every simulator artifact found, grouped by run id and ordered oldest first.

    `artifacts` may be the ``artifacts/`` root (every evaluation directory under
    it is scanned) or a single evaluation directory. Missing, partial or malformed
    artifacts are skipped — the viewer must still build without them.
    """
    root = Path(artifacts)
    if not root.exists():
        return {}

    summaries = sorted(root.rglob("*.summary.json"), key=_mtime)
    outcomes: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for summary_path in summaries:  # oldest first
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(summary, dict):
            continue
        run_id = summary.get("run_id")
        if not run_id:
            continue
        events_path = summary_path.with_name(summary_path.name.replace(".summary.json", ".jsonl"))
        per_step = _steps_from_events(events_path)
        for decision in summary.get("decisions") or []:
            if not isinstance(decision, dict):
                continue
            step_id = decision.get("step_id")
            if not isinstance(step_id, int):
                continue
            detail = per_step.setdefault(step_id, {})
            detail.update(
                {
                    "legitimate": decision.get("legitimate"),
                    "consequential": decision.get("consequential"),
                    "human_approved": decision.get("human_approved"),
                    "sim_decision": decision.get("decision"),
                    "defense_error": decision.get("defense_error"),
                }
            )
        for execution in summary.get("tool_executions") or []:
            if not isinstance(execution, dict):
                continue
            step_id = execution.get("step_id")
            if isinstance(step_id, int):
                detail = per_step.setdefault(step_id, {})
                detail["executed"] = True
                detail["execution"] = {
                    "tool": execution.get("tool"),
                    "succeeded": execution.get("succeeded"),
                    "legitimate": execution.get("legitimate"),
                    "violated": execution.get("violated"),
                }
        for finding in summary.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            step_id = finding.get("step_id")
            if isinstance(step_id, int):
                per_step.setdefault(step_id, {}).setdefault("findings", []).append(finding)

        outcomes[str(run_id)].append({
            "run": {
                key: summary.get(key)
                for key in (
                    "scenario_id",
                    "domain",
                    "split",
                    "difficulty",
                    "defense",
                    "seed",
                    "steps",
                    "attack_family",
                    "attack_present",
                    "attack_success",
                    "critical_violation",
                    "data_flow_violation",
                    "hard_negative",
                    "task_success",
                    "termination",
                    "grader_results",
                    "findings",
                    "mutations",
                    "tool_executions",
                )
                if key in summary
            },
            "steps": per_step,
            "decisions": {
                d.get("step_id"): d.get("decision")
                for d in (summary.get("decisions") or [])
                if isinstance(d, dict) and isinstance(d.get("step_id"), int)
            },
            "source": str(summary_path),
            "mtime": _mtime(summary_path),
        })
    return dict(outcomes)


def _best_candidate(run: Run, candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The artifact that actually corresponds to this trace.

    Agreement on the recorded decision sequence decides; recency breaks ties. A
    candidate that contradicts the trace on more than a third of its steps is
    rejected outright — better no outcome than someone else's run.
    """
    if not candidates:
        return None
    mine = {step.step_id: step.decision for step in run.steps}
    best: tuple[float, float, dict[str, Any]] | None = None
    for candidate in candidates:
        theirs = candidate.get("decisions") or {}
        shared = [sid for sid in mine if sid in theirs]
        if shared:
            agree = sum(1 for sid in shared if mine[sid] == theirs[sid]) / len(shared)
            coverage = len(shared) / max(len(mine), len(theirs))
            score = agree * 0.85 + coverage * 0.15
        else:
            score = 0.0
        if best is None or score > best[0] or (score == best[0] and candidate.get("mtime", 0.0) > best[1]):
            best = (score, float(candidate.get("mtime", 0.0)), candidate)
    if best is None or best[0] < 0.6:
        return None
    chosen = dict(best[2])
    chosen["_match"] = round(best[0], 4)
    return chosen


def _steps_from_events(events_path: Path) -> dict[int, dict[str, Any]]:
    """What the simulator did after each decision, keyed by step id."""
    if not events_path.exists():
        return {}
    per_step: dict[int, dict[str, Any]] = {}
    try:
        with events_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if not isinstance(event, dict):
                    continue
                step_id = event.get("step_id")
                if not isinstance(step_id, int):
                    continue
                kind = event.get("type")
                payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
                detail = per_step.setdefault(step_id, {})
                if kind == "tool_request":
                    detail["requested"] = {
                        "tool": payload.get("tool"),
                        "confirmed": payload.get("confirmed"),
                    }
                elif kind in _EFFECT_EVENTS:
                    detail["executed"] = True
                    detail.setdefault("effects", [])
                    for effect in payload.get("effects") or []:
                        if effect not in detail["effects"]:
                            detail["effects"].append(effect)
                    detail["succeeded"] = payload.get("succeeded")
                    detail["error"] = payload.get("error")
                    detail["result_excerpt"] = _excerpt(payload.get("result"))
                elif kind == "model_output":
                    detail["response"] = _excerpt(payload.get("content"), limit=400)
                elif kind == "task_success":
                    detail["termination"] = payload.get("termination")
                    detail["task_summary"] = payload.get("summary")
    except OSError:
        return per_step
    return per_step


def _excerpt(value: Any, limit: int = 240) -> str:
    if value is None:
        return ""
    text = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"), default=str)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Small numeric helpers
# ---------------------------------------------------------------------------


def _as_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return 0.0 if math.isnan(number) or math.isinf(number) else number


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _mtime(path: Path | None) -> float:
    if path is None:
        return 0.0
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _percentile(values: list[float], pct: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return round(ordered[rank - 1], 3)


def _describe(values: list[float]) -> dict[str, float]:
    if not values:
        return {"n": 0, "min": 0.0, "median": 0.0, "max": 0.0}
    ordered = sorted(values)
    return {
        "n": len(ordered),
        "min": round(ordered[0], 4),
        "median": _percentile(ordered, 50),
        "max": round(ordered[-1], 4),
    }


def _histogram(values: list[float], bins: int = 10) -> list[dict[str, float]]:
    counts = [0] * bins
    for value in values:
        index = min(bins - 1, max(0, int(value * bins)))
        counts[index] += 1
    return [
        {"lo": round(i / bins, 2), "hi": round((i + 1) / bins, 2), "count": counts[i]} for i in range(bins)
    ]


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


__all__ = [
    "AUTHORITY_ORDER",
    "CURRENT_SCHEMA",
    "DECISIONS",
    "DOMAINS",
    "Run",
    "Step",
    "TRUST_ORDER",
    "TRUST_TO_MAX_AUTHORITY",
    "TraceStore",
    "load_outcome_candidates",
    "load_outcomes",
]
