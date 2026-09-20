"""Lane C — build the AEGIS trace viewer.

    python -m aegis.trace.viewer traces/            # writes viewer/index.html
    python -m aegis.trace.viewer traces/ --out /tmp/viewer --artifacts ../starter/artifacts

The viewer is a **single self-contained HTML file**: stylesheet, script and trace
data are inlined, so `viewer/index.html` opens straight off the filesystem with no
server, no network and no CDN. `viewer/data.json` is written alongside it for
anyone who would rather read the payload than the page.

Layout::

    viewer/
      index.html          generated — open this
      data.json           generated — the same payload, standalone
      src/
        shell.html        page skeleton with three inline slots
        app.css           design tokens + layout
        app.js            rendering

The payload keeps every trace record intact (the viewer renders raw fields), plus
a small per-run header the page uses for the run picker and a store-computed
summary for the aggregate view.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.trace.store import Run, TraceStore
from aegis.types import SCHEMA_VERSION

PACKAGE_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_VIEWER_DIR = PACKAGE_ROOT / "viewer"
SOURCE_DIR = DEFAULT_VIEWER_DIR / "src"

#: Where the organizers' simulator usually sits relative to this repo. Used only
#: to offer the outcome join by default; absence is not an error.
DEFAULT_ARTIFACT_CANDIDATES = (
    PACKAGE_ROOT.parent / "starter" / "artifacts",
    PACKAGE_ROOT / "artifacts",
)

THESIS = (
    "Authority comes from the user and the policy, never from observed data. "
    "Taint constrains authority, not attention."
)


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------


def run_payload(run: Run) -> dict[str, Any]:
    headline = run.headline_step
    emitted_first, emitted_last = run.emitted_range
    return {
        "run_id": run.run_id,
        "source": str(run.source) if run.source else None,
        "emitted_first": emitted_first,
        "emitted_last": emitted_last,
        "schema_versions": run.schema_versions,
        "outcome_source": run.outcome_source,
        "outcome_match": run.outcome_match,
        "problems": run.health(),
        "scenario_id": run.scenario_id,
        "domain": run.domain,
        "user_goal": run.user_goal,
        "attack_family": run.attack_family,
        "counts": run.decision_counts,
        "max_risk": round(run.max_risk, 4),
        "worst_trust": run.worst_trust,
        "latency_p95": run.latency_p95,
        "headline_step": headline.step_id if headline is not None else None,
        "reason_codes": sorted(run.reason_codes),
        "outcome": run.outcome,
        "steps": [step.record for step in run.steps],
    }


def build_payload(
    store: TraceStore,
    *,
    trace_dir: Path,
    default_run: str | None = None,
    artifacts: Path | None = None,
) -> dict[str, Any]:
    runs = [run_payload(run) for run in store.runs]
    summary = store.summary()
    health = store.health(expected_schema=SCHEMA_VERSION)
    return {
        "meta": {
            "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
            "trace_dir": str(trace_dir),
            "artifacts_dir": str(artifacts) if artifacts else None,
            "run_count": len(runs),
            "step_count": summary.get("steps", 0),
            "schema": SCHEMA_VERSION,
            "thesis": THESIS,
            "default_run": default_run or _pick_default_run(store),
            "health": health,
        },
        "summary": summary,
        "runs": runs,
    }


def _pick_default_run(store: TraceStore) -> str | None:
    """The run a presenter should land on.

    The best opening shot is an *indirect* attack: benign steps allowed, the
    injected step blocked because its arguments trace back to untrusted text, and
    the legitimate task still completing. Scored, never hard-coded to a scenario.
    """
    best: tuple[int, int, str] | None = None
    for run in store.runs:
        outcome = run.outcome if isinstance(run.outcome, dict) else {}
        counts = run.decision_counts
        score = 0
        if outcome.get("attack_present"):
            score += 4
        if outcome.get("attack_success") is False:
            score += 3
        if outcome.get("task_success"):
            score += 3
        if counts.get("block"):
            score += 2
        if counts.get("allow"):
            score += 1
        headline = run.headline_step
        if headline is not None and headline.action_taint in {
            "untrusted_external",
            "adversary_controlled",
        }:
            score += 5  # the authority cap is visibly doing the work
        if headline is not None and headline.authority.get("satisfied") is False:
            score += 2
        if headline is not None and headline.authority.get("required") == "commit":
            score += 2  # "a letter cannot confirm a payment" — the rule at its clearest
        first_flag = next((i for i, s in enumerate(run.steps) if s.is_interesting), None)
        if first_flag is not None:
            # The more legitimate work that visibly completes before the attack
            # lands, the better the run opens: "benign task → attack → decision".
            score += min(first_flag, 3)
        # Tie-break towards a short run: a tighter story reads better on camera.
        if score and (best is None or (score, -len(run.steps)) > (best[0], -best[1])):
            best = (score, len(run.steps), run.run_id)
    if best is not None:
        return best[2]
    return store.runs[0].run_id if store.runs else None


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _read_source(name: str, source_dir: Path) -> str:
    path = source_dir / name
    return path.read_text(encoding="utf-8")


def render_html(payload: dict[str, Any], *, source_dir: Path = SOURCE_DIR) -> str:
    shell = _read_source("shell.html", source_dir)
    css = _read_source("app.css", source_dir)
    js = _read_source("app.js", source_dir)
    data = json.dumps(payload, separators=(",", ":"), default=str, ensure_ascii=False)
    # Keep the JSON from closing the <script> element that carries it.
    data = data.replace("</", "<\\/").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")

    for marker, replacement in (
        ("/*AEGIS_STYLE*/", css),
        ("/*AEGIS_DATA*/", "window.__AEGIS__ = " + data + ";"),
        ("/*AEGIS_SCRIPT*/", js),
    ):
        if marker not in shell:
            raise ValueError(f"viewer shell is missing the {marker} slot")
        shell = shell.replace(marker, replacement, 1)
    return shell


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


class StaleTraceError(RuntimeError):
    """Raised when a build would render traces that cannot be trusted as current."""


def check_health(payload: dict[str, Any], *, allow_legacy: bool = False) -> list[str]:
    """Return the loud lines; raise when the build must not proceed.

    A stale trace is the one failure mode that damages us on camera: a judge who
    reads "attack SUCCEEDED" believes it. So a record whose schema is not the
    current one, or that was written by an emitter without run-instance tagging
    (and so may hold several runs concatenated), stops the build.
    """
    health = payload.get("meta", {}).get("health", {}) or {}
    lines: list[str] = []
    blocking: list[str] = []
    for run_id, problems in (health.get("runs_with_problems") or {}).items():
        for problem in problems:
            line = f"{problem['level']}: {run_id}: {problem['code']} — {problem['message']}"
            lines.append(line)
            if problem["level"] == "error":
                blocking.append(line)
    if blocking and not allow_legacy:
        raise StaleTraceError(
            "refusing to build the viewer from traces that cannot be trusted as current:\n  "
            + "\n  ".join(blocking)
            + "\n\nRegenerate them (rm -rf traces && re-run the evaluation), or pass "
            "--allow-legacy to build anyway with the warning shown in the page."
        )
    return lines


def build(
    traces: str | Path,
    *,
    out_dir: str | Path = DEFAULT_VIEWER_DIR,
    artifacts: str | Path | None = None,
    source_dir: str | Path = SOURCE_DIR,
    write_data_file: bool = True,
    allow_legacy: bool = False,
) -> Path:
    """Build `out_dir/index.html` from the traces in `traces`. Returns the path."""
    trace_dir = Path(traces)
    store = TraceStore.load(trace_dir, artifacts=artifacts)
    payload = build_payload(
        store, trace_dir=trace_dir, artifacts=Path(artifacts) if artifacts else None
    )
    check_health(payload, allow_legacy=allow_legacy)
    html = render_html(payload, source_dir=Path(source_dir))

    out = Path(out_dir)
    index = out / "index.html"
    _write_atomic(index, html)
    if write_data_file:
        _write_atomic(out / "data.json", json.dumps(payload, indent=1, default=str))
    return index


def _default_artifacts() -> Path | None:
    for candidate in DEFAULT_ARTIFACT_CANDIDATES:
        if candidate.is_dir():
            return candidate
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aegis.trace.viewer",
        description="Build the self-contained AEGIS trace viewer from a directory of traces.",
    )
    parser.add_argument("traces", nargs="?", default="traces", help="trace file or directory (default: traces)")
    parser.add_argument("--out", default=str(DEFAULT_VIEWER_DIR), help="output directory (default: viewer/)")
    parser.add_argument(
        "--artifacts",
        default=None,
        help="simulator artifacts directory to join outcomes from (default: auto-detect ../starter/artifacts)",
    )
    parser.add_argument("--no-artifacts", action="store_true", help="skip the outcome join entirely")
    parser.add_argument("--no-data-file", action="store_true", help="write only index.html")
    parser.add_argument(
        "--default-run",
        default=None,
        help="run id the page opens on (default: chosen by score — see _pick_default_run)",
    )
    parser.add_argument(
        "--allow-legacy",
        action="store_true",
        help="build even from traces with a stale schema or no run-instance tagging",
    )
    args = parser.parse_args(argv)

    artifacts: Path | None = None
    if not args.no_artifacts:
        artifacts = Path(args.artifacts) if args.artifacts else _default_artifacts()
        if artifacts is not None and not artifacts.is_dir():
            print(f"note: artifacts directory {artifacts} not found; building without outcomes", file=sys.stderr)
            artifacts = None

    trace_dir = Path(args.traces)
    if not trace_dir.exists():
        print(f"error: no traces at {trace_dir}", file=sys.stderr)
        return 2

    store = TraceStore.load(trace_dir, artifacts=artifacts)
    payload = build_payload(
        store, trace_dir=trace_dir, artifacts=artifacts, default_run=args.default_run
    )
    try:
        problems = check_health(payload, allow_legacy=args.allow_legacy)
    except StaleTraceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    html = render_html(payload)
    out = Path(args.out)
    index = out / "index.html"
    _write_atomic(index, html)
    if not args.no_data_file:
        _write_atomic(out / "data.json", json.dumps(payload, indent=1, default=str))

    summary = payload["summary"]
    health = payload["meta"]["health"]
    joined = health.get("joined", 0)
    size_kb = index.stat().st_size / 1024
    print(f"{index}  ({size_kb:.0f} KB, self-contained)")
    print(
        f"  {summary.get('runs', 0)} runs · {summary.get('steps', 0)} decisions · "
        f"{joined}/{summary.get('runs', 0)} joined with simulator outcomes"
    )
    decisions = summary.get("decisions", {})
    print("  decisions: " + ", ".join(f"{k}={v}" for k, v in decisions.items()))
    print(f"  traces emitted {health.get('emitted_first')} … {health.get('emitted_last')}")
    for line in problems:
        print("  " + line, file=sys.stderr)
    if problems:
        print(
            f"  {health.get('errors', 0)} error(s), {health.get('warnings', 0)} warning(s) "
            "— shown as a banner in the page",
            file=sys.stderr,
        )
    if not store.runs:
        print("  warning: no traces found — run the defense first", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
