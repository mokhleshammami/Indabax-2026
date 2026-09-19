"""Lane B — detection signals, risk arbitration, action rewriting.

PUBLIC API (frozen — `aegis/defense.py` imports exactly these names):

    def build_signals(*, ablation: str = "none") -> list[Signal]: ...

    class Arbiter:
        def __init__(self, *, ablation: str = "none") -> None: ...
        def combine(self, ctx: SignalContext, results: list[SignalResult]) -> Verdict: ...

Every signal satisfies the `Signal` protocol in `aegis.types`: a `name` attribute
and a pure `score(ctx) -> SignalResult`. A score is *risk in [0, 1]*, where 0
means "this detector saw no evidence" — never "this action is safe".

The set, and what each one catches:

===========================  =================================================
``plan_divergence``          an action the user's own goal does not entail, or
                             that it explicitly excludes, or whose steering
                             arguments trace only to untrusted text
``benign_context``           the inverse: a fully aligned action in alarming
                             surroundings. Scores 0 and publishes a damping
                             factor, so hard negatives stay cheap
``encoded_exfiltration``     a provenance-marked secret reconstructable from an
                             outbound argument through any layered encoding
``sensitive_sink``           confidential content addressed outside the trust
                             boundary the policy declares
``imperative_mirroring``     the action enacts an order found in untrusted
                             content, including split and encoded orders
``policy_conflict``          untrusted text claiming an authorisation the
                             trusted record does not support
===========================  =================================================

Ablations honoured here: ``no_divergence``, ``no_encoding``. ``no_monitor`` and
``rules_only`` are honoured by :class:`~aegis.signals.arbiter.Arbiter`.
"""

from __future__ import annotations

from aegis.signals.arbiter import BLOCK_AT, ESCALATE_AT, Arbiter
from aegis.signals.divergence import BenignContextSignal, PlanDivergenceSignal
from aegis.signals.encoding import EncodedExfiltrationSignal
from aegis.signals.imperative import ImperativeMirroringSignal
from aegis.signals.monitor import RiskMonitor
from aegis.signals.policy_conflict import PolicyConflictSignal
from aegis.signals.rewrite import propose_rewrite
from aegis.signals.sensitivity import SensitiveSinkSignal
from aegis.types import Signal

#: Signals dropped for a given ablation value.
ABLATION_DROPS: dict[str, frozenset[str]] = {
    "no_divergence": frozenset({"plan_divergence"}),
    "no_encoding": frozenset({"encoded_exfiltration"}),
}


def build_signals(*, ablation: str = "none") -> list[Signal]:
    """The full signal set, minus whatever this ablation removes."""
    signals: list[Signal] = [
        PlanDivergenceSignal(),
        EncodedExfiltrationSignal(),
        SensitiveSinkSignal(),
        ImperativeMirroringSignal(),
        PolicyConflictSignal(),
        BenignContextSignal(),
    ]
    dropped = ABLATION_DROPS.get(ablation, frozenset())
    if not dropped:
        return signals
    return [s for s in signals if s.name not in dropped]


__all__ = [
    "ABLATION_DROPS",
    "BLOCK_AT",
    "ESCALATE_AT",
    "Arbiter",
    "BenignContextSignal",
    "EncodedExfiltrationSignal",
    "ImperativeMirroringSignal",
    "PlanDivergenceSignal",
    "PolicyConflictSignal",
    "RiskMonitor",
    "SensitiveSinkSignal",
    "build_signals",
    "propose_rewrite",
]
