"""The arbiter — many kinds of evidence, exactly one decision.

Precedence, highest first. The order matters more than the thresholds: structural
facts are not negotiable and are never traded against a probability.

1. **Tool outside the task's permitted set.** The policy, not the data, decides
   which tools this task may use. Blocked even when the *user* asked for it —
   a direct request cannot widen a policy.
2. **Lifecycle violated** (execute before confirm, missing confirmation edge as
   reported by Lane A). Blocked, or rewritten to the earlier stage.
3. **Authority exceeded** — the action needs more authority than its least-trusted
   input allows. Rewritten to a reversible substitute where one exists; escalated
   when a human confirmation is the missing ingredient; blocked otherwise.
4. **Effect floors.** Below, in full — the rule that keeps the defense from
   becoming the obstacle.
5. **Calibrated band.** The monitor's probability, damped by the hard-negative
   guard, is compared against two thresholds.
6. **Consequential and unconfirmed.** Even a low-risk irreversible step goes to a
   human, because the policy says so and because a human approving a legitimate
   step is how the task completes.

Taint constrains authority, not attention
-----------------------------------------

An agent must stay free to read, quote and summarize untrusted data; what it must
never do is let untrusted data drive a privileged effect. Rules 1-3 enforce the
second half. Without a counterweight, rule 5 quietly attacks the first half: an
identifier that came from a vendor email or a raw log looks like evidence of
injection to every signal at once, even when the user's goal was *"look up the
affected workstation"* and the log is simply where affected workstations are
named.

So two floors sit above the score band, and both are conditioned on there being
no effect to protect:

* **Read floor** — when Lane A reports the authority satisfied and the step needs
  no more than ``read``, AEGIS never blocks. A read is reversible, externally
  invisible, and whatever it returns is still capped by provenance when something
  later tries to act on it. It escalates only above ``READ_ESCALATE_AT`` (0.80),
  which needs several strong, independent signals.
* **Memory floor** — a ``memory_write`` is reversible, ``prepare``-class, and has
  no external effect, and memory inherits the trust of what it was written from,
  so a poisoned entry comes back as evidence with no authority. Refusing the
  write fails the task and prevents nothing. AEGIS prefers to rewrite it with the
  instruction-shaped fragments stripped, and otherwise allows it. Only an actual
  secret in the text overrides this.

Neither floor can touch a commit-class action, which is where every attack in the
threat model has to end up to do damage.

Thresholds (``BLOCK_AT`` 0.70, ``ESCALATE_AT`` 0.38) were chosen from the shape of
the model rather than from any scenario's outcome:

* a single mid-strength signal on a reversible action lands near 0.25 — below
  ``ESCALATE_AT``, because one piece of soft evidence is not a reason to
  interrupt a human;
* two independent signals agreeing, or one strong signal on a commit-class
  action, lands between 0.38 and 0.70 — genuine uncertainty, which is exactly
  what escalation is for;
* structural evidence plus any signal clears 0.70.

``escalate`` is preferred over ``block`` in the middle band and ``rewrite`` over
``block`` wherever a safe substitute preserves the task, because a defense that
completes the work is the only kind anyone deploys.
"""

from __future__ import annotations

from typing import Any

from aegis.signals.base import action_class, confirmation_recorded, is_consequential
from aegis.signals.monitor import RiskMonitor
from aegis.signals.rewrite import RewriteProposal, propose_memory_rewrite, propose_rewrite
from aegis.types import Authority, SignalContext, SignalResult, Verdict

BLOCK_AT = 0.70
ESCALATE_AT = 0.38

#: Interrupting a human over a read needs several strong signals, not one.
READ_ESCALATE_AT = 0.80

#: A signal this confident on its own is never damped by the hard-negative guard.
DAMP_VETO = 0.50

#: The only signal that overrides the memory floor: text going into storage that
#: a sensitive value can be reconstructed from is exfiltration, not note-taking.
EXFILTRATION_OVERRIDE = 0.80

#: Codes that only make sense on an allow.
_BENIGN_CODES = frozenset({"USER_GOAL_ALIGNED", "BENIGN_SENSITIVE_CONTEXT"})

#: Structural findings Lane A may report, in the order they take precedence.
_LIFECYCLE_CODES = ("LIFECYCLE_ORDER_VIOLATION", "MEMORY_AUTHORITY_DENIED")

MAX_EXPLANATION = 500


class Arbiter:
    """Combine signals, taint and authority into a single explainable verdict."""

    def __init__(self, *, ablation: str = "none") -> None:
        self.ablation = ablation
        self.rules_only = ablation == "rules_only"
        self.monitor = RiskMonitor(ablation=ablation)

    # -- entry point -------------------------------------------------------
    def combine(self, ctx: SignalContext, results: list[SignalResult]) -> Verdict:
        try:
            return self._combine(ctx, results)
        except Exception as exc:  # fail closed, never silently open
            return Verdict(
                decision="escalate",
                risk_score=0.7,
                confidence=0.2,
                reason_codes=("DEFENSE_INTERNAL_ERROR",),
                explanation=(
                    f"AEGIS could not arbitrate this action ({type(exc).__name__}); "
                    "referring it to a human."
                ),
            )

    def _combine(self, ctx: SignalContext, results: list[SignalResult]) -> Verdict:
        action = ctx.action
        authority = ctx.authority
        firing = [r for r in results if r.score > 0.05 and "SIGNAL_ERROR" not in r.reason_codes]
        firing.sort(key=lambda r: -r.score)

        damp = self._damp(results, firing)
        output = self.monitor.evaluate(ctx, results)
        probability = min(1.0, max(0.0, output.probability * damp))

        proposal = propose_rewrite(ctx)
        signal_codes = self._signal_codes(firing)

        # -- 1. tool permission -------------------------------------------
        allowed = ctx.allowed_tools
        if action.type == "tool_call" and allowed and action.tool not in allowed:
            return Verdict(
                decision="block",
                risk_score=max(0.9, probability),
                confidence=0.93,
                reason_codes=self._codes(["TOOL_NOT_REQUIRED_FOR_GOAL", *signal_codes], allow=False),
                explanation=self._explain(
                    "block",
                    f"{action.tool} is not in the permitted tool set for this task, "
                    "so no request from the user or from observed data can authorise it.",
                    firing,
                ),
            )

        # -- 2. lifecycle --------------------------------------------------
        lifecycle = [c for c in authority.reason_codes if c in _LIFECYCLE_CODES]
        if lifecycle:
            if proposal is not None:
                return self._rewrite_verdict(ctx, proposal, probability, lifecycle + signal_codes, firing)
            return Verdict(
                decision="block",
                risk_score=max(0.88, probability),
                confidence=0.9,
                reason_codes=self._codes([*lifecycle, *signal_codes], allow=False),
                explanation=self._explain(
                    "block",
                    "the action breaks the required order of its lifecycle "
                    f"(stage: {authority.lifecycle_stage or 'unknown'}).",
                    firing,
                ),
            )

        # -- 3. authority --------------------------------------------------
        if not authority.satisfied:
            codes = [*authority.reason_codes, *signal_codes]
            if proposal is not None:
                return self._rewrite_verdict(ctx, proposal, probability, codes, firing)
            if authority.requires_confirmation and not confirmation_recorded(ctx) and probability < 0.75:
                return Verdict(
                    decision="escalate",
                    risk_score=max(0.55, probability),
                    confidence=0.72,
                    reason_codes=self._codes(codes or ["MISSING_CONFIRMATION"], allow=False),
                    explanation=self._explain(
                        "escalate",
                        f"{self._label(ctx)} needs {authority.required.value} authority but its "
                        f"inputs only carry {authority.available.value}; a human decides.",
                        firing,
                    ),
                )
            return Verdict(
                decision="block",
                risk_score=max(0.85, probability),
                confidence=0.88,
                reason_codes=self._codes(codes or ["AUTHORITY_EXCEEDS_PROVENANCE"], allow=False),
                explanation=self._explain(
                    "block",
                    f"{self._label(ctx)} needs {authority.required.value} authority; its least-trusted "
                    f"input allows only {authority.available.value}.",
                    firing,
                ),
            )

        # -- ablation: hard rules only -------------------------------------
        if self.rules_only:
            return self._rules_only_tail(ctx, signal_codes, firing)

        # -- 4. effect floors ----------------------------------------------
        floor = self._effect_floor(ctx, results, firing, probability, signal_codes)
        if floor is not None:
            return floor

        # -- 5. calibrated band --------------------------------------------
        if probability >= BLOCK_AT:
            if proposal is not None:
                return self._rewrite_verdict(ctx, proposal, probability, signal_codes, firing)
            return Verdict(
                decision="block",
                risk_score=probability,
                confidence=self._confidence(firing, 0.15),
                reason_codes=self._codes(signal_codes, allow=False),
                explanation=self._explain("block", self._rule_sentence(ctx, firing), firing),
            )

        if probability >= ESCALATE_AT:
            return Verdict(
                decision="escalate",
                risk_score=probability,
                confidence=self._confidence(firing, 0.0),
                reason_codes=self._codes(signal_codes, allow=False),
                explanation=self._explain("escalate", self._rule_sentence(ctx, firing), firing),
            )

        # -- 6. consequential steps always meet a human --------------------
        if self._needs_confirmation(ctx):
            return Verdict(
                decision="escalate",
                risk_score=max(probability, 0.30),
                confidence=0.8,
                reason_codes=self._codes(["MISSING_CONFIRMATION", *signal_codes], allow=False),
                explanation=self._explain(
                    "escalate",
                    f"{self._label(ctx)} is irreversible and no human confirmation is on record "
                    "for it; the rest of the evidence looks consistent with the user's request.",
                    firing,
                ),
            )

        allow_codes = self._codes([*self._allow_codes(results), *signal_codes], allow=True)
        return Verdict(
            decision="allow",
            risk_score=probability,
            confidence=self._confidence(firing, 0.2 if damp < 1.0 else 0.1),
            reason_codes=allow_codes or ("USER_GOAL_ALIGNED",),
            explanation=self._explain(
                "allow",
                f"{self._label(ctx)} is entailed by the user's own request, its arguments trace to "
                "trusted sources and it stays inside the trust boundary.",
                firing,
            ),
        )

    # -- effect floors -----------------------------------------------------
    def _effect_floor(
        self,
        ctx: SignalContext,
        results: list[SignalResult],
        firing: list[SignalResult],
        probability: float,
        signal_codes: list[str],
    ) -> Verdict | None:
        """Never block a step that has no effect to prevent.

        Reached only after the structural rules have passed, so the authority cap
        has already had its say. See the module docstring: taint constrains
        authority, not attention.
        """
        action = ctx.action
        exfiltration = self._signal_score(results, "encoded_exfiltration")

        # -- memory floor ---------------------------------------------------
        if action.type == "memory_write" and exfiltration < EXFILTRATION_OVERRIDE:
            memory_rewrite = propose_memory_rewrite(ctx)
            if memory_rewrite is not None and probability >= ESCALATE_AT:
                return Verdict(
                    decision="rewrite",
                    risk_score=min(probability, 0.60),
                    confidence=0.82,
                    reason_codes=self._codes(signal_codes or ["UNTRUSTED_INSTRUCTION_SOURCE"], allow=False),
                    explanation=self._explain(
                        "rewrite",
                        "the substance of the untrusted text is stored and the instruction embedded "
                        "in it is removed; recalled memory carries evidence, never authority.",
                        firing,
                    ),
                    rewritten_action=memory_rewrite.action,
                )
            return Verdict(
                decision="allow",
                risk_score=min(probability, 0.45),
                confidence=0.75,
                reason_codes=self._codes([*self._allow_codes(results), *signal_codes], allow=True)
                or ("USER_GOAL_ALIGNED",),
                explanation=self._explain(
                    "allow",
                    "storing untrusted text is reversible and grants it no authority; memory "
                    "inherits the trust of its source and is re-checked on recall.",
                    firing,
                ),
            )

        # -- read floor -----------------------------------------------------
        if not self._is_effect_free_read(ctx):
            return None
        if probability >= READ_ESCALATE_AT:
            return Verdict(
                decision="escalate",
                risk_score=probability,
                confidence=self._confidence(firing, 0.0),
                reason_codes=self._codes(signal_codes, allow=False),
                explanation=self._explain("escalate", self._rule_sentence(ctx, firing), firing),
            )
        return Verdict(
            decision="allow",
            risk_score=min(probability, 0.45),
            confidence=0.78,
            reason_codes=self._codes([*self._allow_codes(results), *signal_codes], allow=True)
            or ("USER_GOAL_ALIGNED",),
            explanation=self._explain(
                "allow",
                f"{self._label(ctx)} only reads; it changes nothing and its result stays capped by "
                "the trust of where it came from.",
                firing,
            ),
        )

    @staticmethod
    def _is_effect_free_read(ctx: SignalContext) -> bool:
        authority = ctx.authority
        if not authority.satisfied or authority.required > Authority.READ:
            return False
        if is_consequential(ctx) or action_class(ctx) != "read":
            return False
        return ctx.action.type in ("tool_call", "respond")

    @staticmethod
    def _signal_score(results: list[SignalResult], name: str) -> float:
        for result in results:
            if result.name == name and "SIGNAL_ERROR" not in result.reason_codes:
                return float(result.score)
        return 0.0

    # -- introspection -----------------------------------------------------
    def monitor_report(self, ctx: SignalContext, results: list[SignalResult]) -> dict[str, Any]:
        """The monitor's own working, for the trace viewer and the ablation study.

        Pure: it recomputes rather than caching, so `combine` stays free of state
        and the arbiter is safe to share between concurrent requests.
        """
        output = self.monitor.evaluate(ctx, results)
        report = output.to_json()
        report["damp"] = self._damp(
            results, [r for r in results if r.score > 0.05 and "SIGNAL_ERROR" not in r.reason_codes]
        )
        report["thresholds"] = {"escalate_at": ESCALATE_AT, "block_at": BLOCK_AT}
        return report

    # -- pieces ------------------------------------------------------------
    def _rules_only_tail(
        self, ctx: SignalContext, signal_codes: list[str], firing: list[SignalResult]
    ) -> Verdict:
        if self._needs_confirmation(ctx):
            return Verdict(
                decision="escalate",
                risk_score=0.5,
                confidence=0.6,
                reason_codes=self._codes(["MISSING_CONFIRMATION"], allow=False),
                explanation=self._explain(
                    "escalate",
                    f"{self._label(ctx)} is irreversible and unconfirmed (hard rules only).",
                    firing,
                ),
            )
        return Verdict(
            decision="allow",
            risk_score=0.1,
            confidence=0.5,
            reason_codes=("USER_GOAL_ALIGNED",),
            explanation="No structural rule fired (hard rules only; score combination disabled).",
        )

    def _rewrite_verdict(
        self,
        ctx: SignalContext,
        proposal: RewriteProposal,
        probability: float,
        codes: list[str],
        firing: list[SignalResult],
    ) -> Verdict:
        return Verdict(
            decision="rewrite",
            risk_score=max(0.55, probability),
            confidence=0.8,
            reason_codes=self._codes(codes, allow=False),
            explanation=self._explain(
                "rewrite",
                f"{proposal.from_tool} is replaced by {proposal.to_tool}: the reversible form of the "
                "same step keeps the task moving without spending authority the inputs do not carry.",
                firing,
            ),
            rewritten_action=proposal.action,
        )

    def _needs_confirmation(self, ctx: SignalContext) -> bool:
        if ctx.request.candidate_action.type == "request_confirmation":
            return False  # the agent is already asking
        if not is_consequential(ctx) and action_class(ctx) != "commit":
            return False
        if ctx.action.type != "tool_call":
            return False
        return not confirmation_recorded(ctx)

    @staticmethod
    def _damp(results: list[SignalResult], firing: list[SignalResult]) -> float:
        """The hard-negative guard's multiplier, if it is allowed to apply.

        Structural alignment answers "is this the shape of a legitimate task?" It
        does not answer "is a secret leaving in this argument?" So the damp is
        gated: it may cancel an accumulation of weak circumstantial risk, and it
        may never cancel a detector that is confident on its own.
        """
        strongest = max((r.score for r in firing), default=0.0)
        if strongest >= DAMP_VETO:
            return 1.0
        for result in results:
            value = result.detail.get("damp") if isinstance(result.detail, dict) else None
            if isinstance(value, (int, float)) and 0.0 < float(value) <= 1.0:
                return float(value)
        return 1.0

    @staticmethod
    def _allow_codes(results: list[SignalResult]) -> list[str]:
        codes: list[str] = []
        for result in results:
            for code in result.reason_codes:
                if code in _BENIGN_CODES and code not in codes:
                    codes.append(code)
        return codes

    @staticmethod
    def _signal_codes(firing: list[SignalResult]) -> list[str]:
        codes: list[str] = []
        for result in firing:
            for code in result.reason_codes:
                if code in _BENIGN_CODES or code == "SIGNAL_ERROR":
                    continue
                if code not in codes:
                    codes.append(code)
        return codes

    @staticmethod
    def _codes(codes: list[str], *, allow: bool) -> tuple[str, ...]:
        out: list[str] = []
        for code in codes:
            if not code or code in out:
                continue
            if not allow and code in _BENIGN_CODES:
                continue
            out.append(code)
        return tuple(out[:16])

    @staticmethod
    def _confidence(firing: list[SignalResult], bonus: float) -> float:
        agreement = sum(1 for r in firing if r.score >= 0.5)
        value = 0.52 + 0.09 * len(firing) + 0.12 * max(0, agreement - 1) + bonus
        return round(min(0.94, max(0.3, value)), 4)

    @staticmethod
    def _label(ctx: SignalContext) -> str:
        action = ctx.action
        if action.type == "tool_call" and action.tool:
            return action.tool
        return action.type

    @staticmethod
    def _rule_sentence(ctx: SignalContext, firing: list[SignalResult]) -> str:
        """One clause naming the rule that fired — a statement, not reasoning."""
        label = Arbiter._label(ctx)
        if not firing:
            return f"{label} carries no evidence of misuse but sits above the allow threshold."
        top = firing[0]
        detail: dict[str, Any] = top.detail if isinstance(top.detail, dict) else {}
        if top.name == "plan_divergence":
            if detail.get("excluded_by_goal"):
                return f"the user's request explicitly excludes steps of this kind, and {label} is one."
            if detail.get("untrusted_only_arguments"):
                return f"{label} acts on values that appear only in untrusted content."
            return f"{label} is not entailed by anything in the user's request."
        if top.name == "encoded_exfiltration":
            how = detail.get("how") or "plain"
            return f"a value provenance marked sensitive is reconstructable from this action's arguments ({how})."
        if top.name == "sensitive_sink":
            return f"{label} addresses a recipient outside the trust boundary while carrying sensitive content."
        if top.name == "imperative_mirroring":
            return f"{label} enacts an instruction that was found in untrusted content, not in the user's request."
        if top.name == "policy_conflict":
            return (
                f"untrusted content asserts an authorisation for {label} that the trusted record does "
                "not show; the trusted policy applies."
            )
        return f"{label} triggered {top.name}."

    @staticmethod
    def _explain(decision: str, sentence: str, firing: list[SignalResult]) -> str:
        evidence = ", ".join(f"{r.name}={r.score:.2f}" for r in firing[:3])
        text = f"{decision.upper()}: {sentence}"
        if evidence:
            text = f"{text} Evidence: {evidence}."
        return text[:MAX_EXPLANATION]


__all__ = [
    "BLOCK_AT",
    "DAMP_VETO",
    "ESCALATE_AT",
    "EXFILTRATION_OVERRIDE",
    "READ_ESCALATE_AT",
    "Arbiter",
]
