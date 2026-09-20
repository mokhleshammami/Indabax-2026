#!/usr/bin/env python3
"""Regenerate `docs/*.md` from the authoritative sections of `report/report.md`.

The report is the single source of truth. These extracts exist so a reader
browsing the repository finds the threat model, method, failure analysis and
responsible-AI statement where they expect them, without us maintaining two
copies that drift apart.

    python3 scripts/split_docs.py [--check]

`--check` exits non-zero if any doc is stale, for CI.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "report" / "report.md"
DOCS = ROOT / "docs"

#: filename -> (title, report section number, one-line blurb)
SECTIONS: dict[str, tuple[str, int, str]] = {
    "threat-model.md": (
        "Threat model",
        2,
        "The adversary model AEGIS is built against, and what it explicitly concedes.",
    ),
    "method.md": (
        "Method",
        4,
        "How AEGIS decides: the authority lattice, taint propagation, signals and arbitration.",
    ),
    "failure-analysis.md": (
        "Failure analysis",
        8,
        "Where and why AEGIS breaks. Written to be falsifiable, not reassuring.",
    ),
    "responsible-ai.md": (
        "Responsible AI and security considerations",
        10,
        "What AEGIS protects against, how it fails, what it observes, and when a human must decide.",
    ),
}


def extract(lines: list[str], number: int) -> str:
    """Return the body of `## <number>. ...` up to the next top-level section."""
    start: int | None = None
    body: list[str] = []
    for index, line in enumerate(lines):
        if re.match(rf"^## {number}\. ", line):
            start = index
            continue
        if start is not None:
            if re.match(r"^## \d+\. ", line):
                break
            body.append(line)
    return "\n".join(body).strip()


def render(title: str, number: int, blurb: str, body: str) -> str:
    return (
        f"# {title}\n\n{blurb}\n\n"
        f"> Extracted verbatim from [`report/report.md`](../report/report.md) §{number}, "
        f"which is the authoritative version. Edit the report, then regenerate with "
        f"`python3 scripts/split_docs.py`.\n\n---\n\n{body}\n"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if any doc is stale")
    args = parser.parse_args()

    if not REPORT.is_file():
        print(f"error: {REPORT} not found", file=sys.stderr)
        return 2

    lines = REPORT.read_text(encoding="utf-8").split("\n")
    DOCS.mkdir(exist_ok=True)
    stale: list[str] = []

    for filename, (title, number, blurb) in SECTIONS.items():
        body = extract(lines, number)
        if not body:
            print(f"error: report section {number} is empty", file=sys.stderr)
            return 2
        text = render(title, number, blurb, body)
        target = DOCS / filename
        current = target.read_text(encoding="utf-8") if target.is_file() else None
        if current == text:
            print(f"  ok     docs/{filename}")
            continue
        if args.check:
            stale.append(filename)
            print(f"  STALE  docs/{filename}")
            continue
        target.write_text(text, encoding="utf-8")
        print(f"  wrote  docs/{filename}  ({len(text)} chars)")

    if stale:
        print(f"\n{len(stale)} doc(s) stale; run: python3 scripts/split_docs.py", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
