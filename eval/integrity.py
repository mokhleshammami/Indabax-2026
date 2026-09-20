"""Integrity audit: prove no decision depends on scenario identity.

``SCHEMA.md`` section 7 and the organizers' threat model both say the same thing:
a defense that decides from a scenario id, a filename or an organizer-provided
expected outcome is disqualified, not clever. That is a claim about the code, and
a claim about code is worth exactly as much as the experiment that could falsify
it.

So this module runs the experiment. It copies the published library to a scratch
directory, renames every file, rewrites every scenario ``id`` to an opaque hash,
re-runs the whole split against the live defense, and compares the decisions
step by step against the original run. Seeds are preserved, because the seed is
what generates the canaries; only identity changes.

If a single decision, risk score, confidence value or reason code differs, this
exits non-zero and prints the difference.

    uv run python eval/integrity.py                # public split
    uv run python eval/integrity.py --split validation
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

from run_all import DEFAULT_SIMULATOR, RESULTS, DefenseService, run_split

#: Fields of a decision that must be byte-identical under renaming. Latency is
#: wall-clock and is excluded for the same reason the simulator excludes it from
#: its own deterministic digest.
COMPARED = ("step_id", "action_type", "tool", "decision", "risk_score", "confidence", "reason_codes")


def _alias(scenario_id: str) -> str:
    """A stable, meaningless name. Nothing in it hints at domain or attack."""
    digest = hashlib.sha256(scenario_id.encode()).hexdigest()[:12]
    return f"zz_{digest}"


def build_renamed_library(source: Path, target: Path) -> dict[str, str]:
    """Copy a scenario tree, renaming every file and id. Returns alias -> original."""
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    mapping: dict[str, str] = {}
    for path in sorted(source.rglob("*.yaml")):
        text = path.read_text()
        match = re.search(r"^id:\s*(\S+)\s*$", text, flags=re.MULTILINE)
        if not match:
            continue
        original = match.group(1)
        alias = _alias(original)
        mapping[alias] = original
        # Only the identity changes: id, filename, and the title/description,
        # which a defense could in principle key on just as easily.
        text = re.sub(r"^id:\s*\S+\s*$", f"id: {alias}", text, count=1, flags=re.MULTILINE)
        text = re.sub(r"^title:.*$", "title: Renamed scenario", text, count=1, flags=re.MULTILINE)
        text = re.sub(
            r"^description:.*$", "description: Identity removed for the integrity audit.",
            text, count=1, flags=re.MULTILINE,
        )
        (target / f"{alias}.yaml").write_text(text)
    return mapping


def decisions_of(card: dict[str, Any], rename: dict[str, str] | None = None) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for outcome in card.get("outcomes") or []:
        scenario = str(outcome.get("scenario_id"))
        if rename:
            scenario = rename.get(scenario, scenario)
        out[scenario] = [
            {key: decision.get(key) for key in COMPARED} for decision in (outcome.get("decisions") or [])
        ]
    return out


def audit(
    split: str = "public",
    *,
    simulator: Path = DEFAULT_SIMULATOR,
    port: int = 8080,
    scratch: Path | None = None,
) -> dict[str, Any]:
    source = simulator / "scenarios" / split
    workdir = scratch or (RESULTS / ".integrity")
    renamed_dir = workdir / split
    mapping = build_renamed_library(source, renamed_dir)

    url = f"http://127.0.0.1:{port}"
    with DefenseService(ablation="none", port=port):
        original = run_split(split, simulator=simulator, defense_url=url)
        renamed = run_split(split, simulator=simulator, defense_url=url, scenarios=renamed_dir)

    left = decisions_of(original)
    right = decisions_of(renamed, rename=mapping)

    differences: list[dict[str, Any]] = []
    for scenario in sorted(set(left) | set(right)):
        a, b = left.get(scenario), right.get(scenario)
        if a is None or b is None:
            differences.append({"scenario_id": scenario, "issue": "missing in one run"})
            continue
        if len(a) != len(b):
            differences.append(
                {"scenario_id": scenario, "issue": "different number of decisions", "n": [len(a), len(b)]}
            )
            continue
        for x, y in zip(a, b, strict=True):
            if x != y:
                differences.append({"scenario_id": scenario, "original": x, "renamed": y})

    result = {
        "split": split,
        "scenarios_renamed": len(mapping),
        "decisions_compared": sum(len(v) for v in left.values()),
        "differences": differences,
        "identical": not differences,
        "digest_original": original.get("deterministic_digest"),
        "digest_renamed": renamed.get("deterministic_digest"),
        "mapping": mapping,
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / f"integrity_{split}.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prove decisions do not depend on scenario identity.")
    parser.add_argument("--split", default="public")
    parser.add_argument("--simulator", default=str(DEFAULT_SIMULATOR), type=Path)
    parser.add_argument("--port", default=8080, type=int)
    args = parser.parse_args(argv)

    result = audit(args.split, simulator=args.simulator, port=args.port)
    print(
        f"split={result['split']} scenarios={result['scenarios_renamed']} "
        f"decisions={result['decisions_compared']} identical={result['identical']}"
    )
    # The scorecard digest covers scenario ids, so it is *expected* to differ.
    # The decisions are what must not.
    print(f"scorecard digest original={result['digest_original']}")
    print(f"scorecard digest renamed ={result['digest_renamed']}")
    if result["differences"]:
        print(json.dumps(result["differences"][:10], indent=2))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
