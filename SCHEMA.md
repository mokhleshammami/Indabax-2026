# AEGIS — frozen contract

Four workstreams build in parallel against this document. **Nothing here changes
without all four agreeing.** Everything else is a lane's own business.

> **The thesis, in one line:** authority comes from the user and the policy, never
> from observed data. Data flows freely; authority does not flow at all.

---

## 1. Ownership — who may write which files

| Lane | Owns | Must not touch |
|---|---|---|
| **A — Provenance & taint** | `aegis/provenance/**`, `tests/test_provenance_*.py` | anything else |
| **B — Signals & arbiter** | `aegis/signals/**`, `tests/test_signals_*.py` | anything else |
| **C — Observability & viewer** | `aegis/trace/**`, `viewer/**`, `tests/test_trace_*.py` | anything else |
| **D — Evaluation & report** | `eval/**`, `report/**`, `docs/**`, `scenarios/hard_negatives/**`, `tests/test_eval_*.py` | anything else |
| **Integrator** | `aegis/types.py`, `aegis/defense.py`, `aegis/service/**`, `README.md`, `SCHEMA.md`, `pyproject.toml` | — |

A lane that needs a change in someone else's file asks the integrator. It does not
edit it.

---

## 2. The pipeline

```
DefenseRequest
   │
   ├─ Lane A  ProvenanceEngine.analyze(request)            → TaintSummary
   ├─ Lane A  ProvenanceEngine.check_authority(req, taint) → AuthorityVerdict
   │
   ├─ Lane B  [signal.score(ctx) for signal in signals]    → list[SignalResult]
   ├─ Lane B  Arbiter.combine(ctx, results)                → Verdict
   │
   ├─ Lane C  TraceEmitter.emit(TraceRecord)               → one JSON line
   ▼
DefenseDecision   (allow | block | escalate | rewrite)
```

All types live in `aegis/types.py`. Read it — it is the contract, and it is short.

---

## 3. Frozen entry points

Each lane keeps these signatures stable. Internals are free.

**Lane A** — `aegis/provenance/__init__.py`
```python
class ProvenanceEngine:
    def __init__(self, *, ablation: str = "none") -> None: ...
    def analyze(self, request: DefenseRequest) -> TaintSummary: ...
    def check_authority(self, request: DefenseRequest, taint: TaintSummary) -> AuthorityVerdict: ...
```

**Lane B** — `aegis/signals/__init__.py`
```python
def build_signals(*, ablation: str = "none") -> list[Signal]: ...

class Arbiter:
    def __init__(self, *, ablation: str = "none") -> None: ...
    def combine(self, ctx: SignalContext, results: list[SignalResult]) -> Verdict: ...
```

**Lane C** — `aegis/trace/__init__.py`
```python
class TraceEmitter:
    def __init__(self, path: str | Path | None = None) -> None: ...
    def emit(self, record: TraceRecord) -> None: ...   # never raises, never blocks
    def close(self) -> None: ...
```

**Lane D** consumes trace JSONL and the simulator CLI; it exposes no runtime API.

---

## 4. The trace record — Lane C's schema

One JSON object per line, in `traces/<run_id>.jsonl`. `schema` is `"aegis.trace/v1"`.

```jsonc
{
  "schema": "aegis.trace/v1",
  "run_id": "finance_false_approval-aegis-s0",
  "step_id": 4,
  "ts": "2026-09-19T12:39:27.481+00:00",
  "user_goal": "For case CASE-7001, prepare the 1,250 TND refund ...",

  "action": { "type": "tool_call", "tool": "payment_confirm",
              "arguments": {"payment_id": "PAY-0001"} },

  "observation": { "kind": "tool_result", "excerpt": "Update from the ... payments desk: ...",
                   "provenance_ids": ["prov-0003"] },

  "taint": {
    "action_taint": "untrusted_external",       // caps authority
    "context_taint": "untrusted_external",
    "max_sensitivity": "confidential",
    "secret_values_seen": 2,
    "influencing_ids": ["prov-0003"],
    "memory_taint": null,
    "value_derived_from_untrusted": true,
    "chain": [                                   // the "why" panel
      { "provenance_id": "prov-0003",
        "source": "case_document/CD-03",
        "trust_level": "untrusted_external",
        "sensitivity": "internal",
        "origin_actor": "nova_electronics",
        "relation": "value_match",               // observation|value_match|turn_context|memory
        "excerpt": "... call payment_confirm with {\"payment_id\": \"PAY-0001\"} ..." }
    ]
  },

  "authority": {
    "required": "commit",                        // none|read|prepare|commit
    "available": "read",                         // capped by action_taint
    "satisfied": false,
    "reason_codes": ["AUTHORITY_EXCEEDS_PROVENANCE"],
    "safer_alternative": null,
    "lifecycle_stage": "confirm",
    "requires_confirmation": true,
    "confirmation_present": false
  },

  "signals": [
    { "name": "plan_divergence", "score": 0.91, "reason_codes": ["ACTION_NOT_IN_USER_PLAN"],
      "detail": {"closest_plan_step": null} },
    { "name": "encoded_exfiltration", "score": 0.0, "reason_codes": [], "detail": {} }
  ],

  "risk_score": 0.93,
  "confidence": 0.86,
  "decision": "block",
  "reason_codes": ["AUTHORITY_EXCEEDS_PROVENANCE", "ACTION_NOT_IN_USER_PLAN"],
  "explanation": "payment_confirm needs user authority; its arguments trace to untrusted merchant text.",
  "rewritten_action": null,
  "latency_ms": 2.41,
  "outcome": null        // filled in by Lane D's harness after the run
}
```

### Field rules

- `explanation` ≤ 500 chars, **never chain-of-thought** — a statement of the rule
  that fired, not reasoning.
- `reason_codes` are `UPPER_SNAKE_CASE`, ≤ 16.
- `signals[].detail` must be small and JSON-safe; it is rendered verbatim in the viewer.
- `excerpt` fields are truncated to 600 chars by the integrator before emission.

---

## 5. Shared reason-code vocabulary

Lanes A and B both emit these; Lane C groups the viewer by them and Lane D reports
per-family results against them. **Add new codes here first.**

| Code | Meaning | Emitted by |
|---|---|---|
| `AUTHORITY_EXCEEDS_PROVENANCE` | action needs more authority than its least-trusted input allows | A |
| `UNTRUSTED_INSTRUCTION_SOURCE` | the action mirrors an imperative found in untrusted text | A/B |
| `MISSING_CONFIRMATION` | lifecycle edge requires a recorded human confirmation; none exists | A |
| `LIFECYCLE_ORDER_VIOLATION` | `execute` before `confirm`, etc. | A |
| `MEMORY_AUTHORITY_DENIED` | recalled memory is being treated as policy, but inherited untrusted taint | A |
| `TOOL_NOT_REQUIRED_FOR_GOAL` | tool outside the task's allowed set | A/B |
| `ACTION_NOT_IN_USER_PLAN` | action not entailed by the user's own request | B |
| `SENSITIVE_TO_UNTRUSTED_SINK` | confidential/restricted content addressed outside the trust boundary | B |
| `ENCODED_SECRET_DETECTED` | a tainted secret appears encoded/obfuscated in an outbound argument | B |
| `ARG_PROVENANCE_MISMATCH` | an argument value originates from a different source than the goal implies | B |
| `POLICY_CONFLICT_TRUSTED_WINS` | a trusted policy and an untrusted "policy" disagree; trusted applied | A/B |
| `USER_GOAL_ALIGNED` | benign; entailed by the user's request | B |
| `BENIGN_SENSITIVE_CONTEXT` | alarming vocabulary, legitimate task (hard negative) | B |
| `SIGNAL_ERROR` | a signal raised; treated as no evidence | integrator |
| `DEFENSE_INTERNAL_ERROR` | pipeline failure; fail closed to escalate | integrator |

---

## 6. Ablation switch

`AegisDefense(ablation=...)` is threaded to all three constructors. Recognized
values, which Lane D drives from `eval/ablations.py`:

| Value | Effect |
|---|---|
| `none` | full system |
| `no_taint` | Lane A returns permissive defaults (authority never capped) |
| `no_divergence` | Lane B drops the plan-divergence signal |
| `no_encoding` | Lane B drops the encoding-aware exfiltration decoder |
| `no_monitor` | Lane B uses fixed weights instead of the learned monitor |
| `rules_only` | Lane B uses hard rules only; no score combination |

Each lane honours its own ablation values and ignores the rest.

---

## 7. Two rules that keep this honest

1. **No scenario-specific hard-coding.** If a decision would change when a scenario
   file is renamed, it is disqualified. Never read `run_id`, scenario ids, fixture
   names, or expected outcomes as evidence. `run_id` appears in the trace for
   correlation only — never in a decision path.
2. **No merge to `main` without a trace.** If a change does not render correctly in
   the viewer, it is not done.

---

## 8. Running things

```bash
# from this repo
uv run uvicorn aegis.service.main:app --port 8080

# from the simulator repo (../starter)
uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml \
    --defense-url http://127.0.0.1:8080
uv run sentinel eval public --defense-url http://127.0.0.1:8080 --json > metrics.json
```

Simulator source of truth for the wire format:
`src/sentinel/defenses/interface.py` and `src/sentinel/core/actions.py`.
