"""Lane B — detection signals, risk arbitration, action rewriting.

PUBLIC API (frozen — `aegis/defense.py` imports exactly these names):

    def build_signals(*, ablation: str = "none") -> list[Signal]: ...

    class Arbiter:
        def __init__(self, *, ablation: str = "none") -> None: ...
        def combine(self, ctx: SignalContext, results: list[SignalResult]) -> Verdict: ...

Every signal satisfies the `Signal` protocol in `aegis.types`: a `name` attribute
and a pure `score(ctx) -> SignalResult`. Lane B may add any modules under
`aegis/signals/`; it must keep these two entry points stable.

The implementation below is a *placeholder* so the pipeline runs from day one.
Lane B replaces it.
"""

from __future__ import annotations

from aegis.types import Signal, SignalContext, SignalResult, Verdict


def build_signals(*, ablation: str = "none") -> list[Signal]:
    """Placeholder — replaced by Lane B."""
    return []


class Arbiter:
    """Placeholder implementation — replaced by Lane B."""

    def __init__(self, *, ablation: str = "none") -> None:
        self.ablation = ablation

    def combine(self, ctx: SignalContext, results: list[SignalResult]) -> Verdict:
        return Verdict(
            decision="allow",
            risk_score=0.0,
            confidence=0.1,
            reason_codes=("PLACEHOLDER_ARBITER",),
            explanation="Arbiter not yet implemented.",
        )


__all__ = ["Arbiter", "build_signals"]
