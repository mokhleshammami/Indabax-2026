"""AEGIS integration point.

This file wires the four workstreams together and is the **only** place that knows
about all of them. It is owned by the integrator; lanes change their own modules,
not this one.

Pipeline, once per candidate action::

    request
      -> ProvenanceEngine.analyze()        (Lane A) -> TaintSummary
      -> ProvenanceEngine.check_authority()(Lane A) -> AuthorityVerdict
      -> [signal.score(ctx) for signal in signals]  (Lane B) -> [SignalResult]
      -> Arbiter.combine()                 (Lane B) -> Verdict
      -> TraceEmitter.emit()               (Lane C) -> one JSON line
      -> DefenseDecision

Fail-closed: any unexpected exception yields ESCALATE, never a silent allow.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from aegis.provenance import ProvenanceEngine
from aegis.signals import Arbiter, build_signals
from aegis.trace import TraceEmitter
from aegis.types import (
    DefenseDecision,
    DefenseRequest,
    SignalContext,
    SignalResult,
    TraceRecord,
    Verdict,
)


class AegisDefense:
    """The defense. Construct once, call `decide` per candidate action."""

    name = "aegis"

    def __init__(
        self,
        engine: ProvenanceEngine | None = None,
        signals: list[Any] | None = None,
        arbiter: Arbiter | None = None,
        tracer: TraceEmitter | None = None,
        *,
        enabled_signals: set[str] | None = None,
        ablation: str | None = None,
    ) -> None:
        #: `ablation` names a component to disable, for the report's ablation study.
        #: Recognized: "no_taint", "no_divergence", "no_encoding", "no_monitor",
        #: "rules_only", "none".
        self.ablation = ablation or "none"
        self.engine = engine or ProvenanceEngine(ablation=self.ablation)
        self.signals = signals if signals is not None else build_signals(ablation=self.ablation)
        if enabled_signals is not None:
            self.signals = [s for s in self.signals if s.name in enabled_signals]
        self.arbiter = arbiter or Arbiter(ablation=self.ablation)
        self.tracer = tracer or TraceEmitter()

    # -- main entry point ---------------------------------------------------
    def decide(self, request: DefenseRequest) -> DefenseDecision:
        started = time.perf_counter()
        try:
            taint = self.engine.analyze(request)
            authority = self.engine.check_authority(request, taint)
            ctx = SignalContext(request=request, taint=taint, authority=authority)

            results: list[SignalResult] = []
            for signal in self.signals:
                try:
                    results.append(signal.score(ctx))
                except Exception as exc:  # a broken signal must not open the gate
                    results.append(
                        SignalResult(
                            name=getattr(signal, "name", "unknown"),
                            score=0.0,
                            reason_codes=("SIGNAL_ERROR",),
                            detail={"error": type(exc).__name__},
                        )
                    )

            verdict = self.arbiter.combine(ctx, results)
        except Exception as exc:
            verdict = Verdict(
                decision="escalate",
                risk_score=0.75,
                confidence=0.2,
                reason_codes=("DEFENSE_INTERNAL_ERROR",),
                explanation=f"AEGIS could not evaluate this action ({type(exc).__name__}); asking a human.",
            )
            taint = None  # type: ignore[assignment]
            authority = None  # type: ignore[assignment]
            results = []

        latency_ms = (time.perf_counter() - started) * 1000.0
        decision = verdict.to_decision(metadata={"ablation": self.ablation})

        try:
            self.tracer.emit(self._record(request, taint, authority, results, verdict, latency_ms))
        except Exception:
            pass  # observability must never break the decision path

        return decision

    # -- trace assembly -----------------------------------------------------
    def _record(
        self,
        request: DefenseRequest,
        taint: Any,
        authority: Any,
        results: list[SignalResult],
        verdict: Verdict,
        latency_ms: float,
    ) -> TraceRecord:
        action = request.target_action()
        return TraceRecord(
            run_id=request.run_id,
            step_id=request.step_id,
            ts=datetime.now(UTC).isoformat(timespec="milliseconds"),
            user_goal=request.user_goal,
            action=action.model_dump(mode="json", exclude_none=True),
            observation=(
                {
                    "kind": request.observation.kind,
                    "excerpt": request.observation.content[:600],
                    "provenance_ids": list(request.observation.provenance_ids),
                }
                if request.observation is not None
                else None
            ),
            taint=taint.to_json() if taint is not None else {},
            authority=authority.to_json() if authority is not None else {},
            signals=[r.to_json() for r in results],
            risk_score=decision_float(verdict.risk_score),
            confidence=decision_float(verdict.confidence),
            decision=verdict.decision,
            reason_codes=list(verdict.reason_codes),
            explanation=verdict.explanation,
            rewritten_action=(
                verdict.rewritten_action.model_dump(mode="json", exclude_none=True)
                if verdict.rewritten_action is not None
                else None
            ),
            latency_ms=round(latency_ms, 3),
        )

    def close(self) -> None:
        self.tracer.close()


def decision_float(value: float) -> float:
    return round(min(1.0, max(0.0, float(value))), 4)


__all__ = ["AegisDefense"]
