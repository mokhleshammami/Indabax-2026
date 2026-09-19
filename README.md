# AEGIS

**Authority-gated defense for tool-using LLM agents.**
SENTINEL research challenge — Deep Learning IndabaX Tunisia 2026.

> An agent reads text it cannot trust while holding authority it must not misuse.
> AEGIS separates the two: **data flows freely, authority does not flow at all.**

---

## The idea

A prompt injection is not a string-matching problem — it is a *confused deputy*
problem. The same model that reads a vendor invoice can send an email or confirm a
payment, so anyone who can write into what it reads can borrow its hands.

AEGIS answers this structurally rather than lexically. Every observation enters with
a trust level. When the agent proposes an action, AEGIS walks back the chain of
observations that influenced it, and caps the action's **maximum authority** at the
lowest trust level in that chain:

| Least-trusted influence | Maximum authority |
|---|---|
| `system_policy`, `authenticated_user` | `commit` — irreversible, externally visible |
| `trusted_internal`, `untrusted_internal` | `prepare` — reversible artifacts only |
| `untrusted_external`, `adversary_controlled` | `read` — observation only |

So an action whose arguments trace back to a merchant's letter can never confirm a
payment — not because the letter said something suspicious, but because a letter has
no authority to give. Rephrasing, encoding or splitting the instruction changes
nothing: the *provenance* is what was checked.

On top of that spine sit signals that catch what pure taint tracking misses —
plan divergence, encoded exfiltration, sensitive-sink violations, memory-provenance
conflicts — combined into a calibrated risk score with explicit reason codes.

## Architecture

```
DefenseRequest
   │
   ├─ Provenance engine    taint propagation, authority cap, lifecycle, memory
   ├─ Signals              divergence · encoding · sensitivity · policy conflict
   ├─ Arbiter              calibrated risk → allow | block | escalate | rewrite
   └─ Trace emitter        one fully-explained JSON record per decision
   ▼
DefenseDecision + observability trace
```

Full contract: [SCHEMA.md](SCHEMA.md). Method and results: [report/](report/).

## Quick start

```bash
uv venv && uv pip install -e ".[dev]"
uv run pytest                                    # unit tests
uv run uvicorn aegis.service.main:app --port 8080
```

Against the organizers' simulator (cloned separately):

```bash
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml \
    --defense-url http://127.0.0.1:8080
uv run sentinel eval public --defense-url http://127.0.0.1:8080 --json > metrics.json
```

Observability layer:

```bash
python -m aegis.trace.viewer traces/            # build the trace viewer
open viewer/index.html
```

## Repository map

```
aegis/
  types.py          frozen shared contract — trust lattice, authority lattice, records
  defense.py        the pipeline; the only file that knows about all four lanes
  provenance/       taint propagation, authority capping, lifecycle, memory provenance
  signals/          detectors, risk arbitration, action rewriting
  trace/            observability: trace emission and the viewer builder
  service/          SENTINEL v1 HTTP defense service
viewer/             the trace viewer (static, self-contained)
eval/               scenario runs, ablation studies, hard negatives
report/             technical report
docs/               threat model, method notes, responsible-AI statement
scenarios/          our own hard-negative scenarios
tests/
```

## Non-negotiables

1. **No scenario-specific hard-coding.** No decision may depend on a scenario id,
   filename, or organizer-provided expected outcome. If renaming a file would change
   a decision, that decision is invalid.
2. **Every safety claim is backed by a trace.** If it does not render in the viewer,
   it did not happen.
3. **Blocking everything is a failure.** Legitimate work must complete, including
   tasks whose text is full of alarming words.

## Responsible AI

AEGIS is a research prototype built entirely on synthetic, fictional data inside the
SENTINEL simulator. It touches no real system, credential or personal data. Known
limitations, false-positive behaviour, and when a human must stay in the loop are
documented in [docs/responsible-ai.md](docs/responsible-ai.md) — honestly, including
the attacks it does not stop.

## License

Apache-2.0.
