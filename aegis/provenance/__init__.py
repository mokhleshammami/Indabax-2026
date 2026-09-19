"""Lane A — provenance, taint propagation, authority capping, lifecycle, memory.

PUBLIC API (frozen — `aegis/defense.py` imports exactly these names):

    class ProvenanceEngine:
        def __init__(self, *, ablation: str = "none") -> None: ...
        def analyze(self, request: DefenseRequest) -> TaintSummary: ...
        def check_authority(self, request: DefenseRequest, taint: TaintSummary) -> AuthorityVerdict: ...

--------------------------------------------------------------------------
The method
--------------------------------------------------------------------------

Authority comes from the user and the policy; never from observed data. Data is
allowed to flow anywhere — quoting a scam message into a case note is the job —
but authority does not flow at all. So the engine answers three questions and
refuses to answer a fourth:

1. **What influenced this action?** (`taint.py`) Every value the action carries
   is matched against every span of content the agent has seen, generalizing
   past wording: squashed text, alphanumeric-only forms that survive JSON
   quoting and punctuation, numeric equality across thousands separators, and
   stem overlap for paraphrase. A value the *user* named is anchored and keeps
   its authority; a value only untrusted text named is the causal signal.
2. **What does this action need?** (`authority.py`) Derived from the policy's
   consequential/confirmation lists and the tool's verb morphology, never from a
   list of scenario tool names.
3. **Where is it in its object's lifecycle?** (`lifecycle.py`) Ordering comes
   from the policy's own `prerequisite` rules; confirmation exists only when the
   history digest says so, matched by the simulator's exact action digest.

The fourth question — *"does the content say this was approved?"* — is never
asked. A document claiming an approval is a document.

`memory.py` extends all of this across turns: a memory entry written after
reading untrusted content stays untrusted when recalled, and a recalled
"policy" loses to a trusted one.

--------------------------------------------------------------------------
Contract notes for Lane B
--------------------------------------------------------------------------

* `TaintSummary.chain` excerpts are prefixed `[arg:<name>]` for a *control*
  argument (identifier, recipient, status, amount — these steer the effect) and
  `[content:<name>]` for payload text (note, body, summary). `(user-named)`
  marks a value the user's own goal already contained. Only unanchored control
  matches raise `action_taint`.
* `value_derived_from_untrusted` is True only for unanchored **control** values
  traced to untrusted text — the strong, causal signal.
* `secret_values` is deliberately generous: identifier- and key-shaped tokens
  seen in confidential/restricted content. They are candidates to match against
  outbound arguments (including encoded), not things to block on sight.
* `AuthorityVerdict.satisfied is False` with `AUTHORITY_EXCEEDS_PROVENANCE`
  means untrusted data is driving a privileged action — block-worthy. With only
  `MISSING_CONFIRMATION` it means a legitimate consequential step needs a human
  — escalate, do not block; the simulator's human approves plan-legitimate
  actions and denies the rest.

--------------------------------------------------------------------------
Honest limits
--------------------------------------------------------------------------

Attribution is per conversation item. One tool result can carry several
provenance ids (a trusted alert plus the untrusted raw logs inside it); we
attribute the whole item's text to each of them, which over-taints rather than
under-taints. Matching is lexical, so a value the attacker only *implies* —
never writes — is invisible here and must be caught by Lane B.
"""

from __future__ import annotations

from aegis.provenance import authority, lifecycle, memory, taint
from aegis.provenance.lifecycle import action_digest
from aegis.provenance.taint import TaintAnalysis
from aegis.types import AuthorityVerdict, DefenseRequest, TaintSummary

#: Ablation values this lane answers to. Everything else is another lane's.
ABLATION_NO_TAINT = "no_taint"


class ProvenanceEngine:
    """Taint propagation and authority capping for one candidate action."""

    def __init__(self, *, ablation: str = "none") -> None:
        self.ablation = ablation or "none"
        #: One-entry memo so `analyze` and `check_authority` share the same work
        #: for the same request. Deterministic either way — it only saves time.
        self._memo_key: tuple[int, str, int] | None = None
        self._memo: tuple[TaintAnalysis, lifecycle.LifecycleState, memory.MemoryState] | None = None

    # -- Lane A entry points -------------------------------------------------
    def analyze(self, request: DefenseRequest) -> TaintSummary:
        """Which observations influenced this action, and how far they are trusted."""
        if self.ablation == ABLATION_NO_TAINT:
            return TaintSummary()
        try:
            analysis, _, _ = self._analysis(request)
        except Exception:
            return _fail_closed_summary()
        return TaintSummary(
            action_taint=analysis.action_taint,
            context_taint=analysis.context_taint,
            max_sensitivity=analysis.max_sensitivity,
            tainted_spans=analysis.tainted_spans,
            sensitive_spans=analysis.sensitive_spans,
            secret_values=analysis.secret_values,
            influencing_ids=analysis.influencing_ids,
            chain=analysis.chain,
            memory_taint=analysis.memory_taint,
            value_derived_from_untrusted=analysis.value_derived_from_untrusted,
        )

    def check_authority(self, request: DefenseRequest, taint_summary: TaintSummary) -> AuthorityVerdict:
        """Does this action have the authority its effect requires?"""
        if self.ablation == ABLATION_NO_TAINT:
            return AuthorityVerdict()
        try:
            analysis, life, mem = self._analysis(request)
            return authority.check(request, analysis, life, mem)
        except Exception:
            # Never raise into the pipeline: report an unsatisfiable step so the
            # arbiter escalates rather than silently allowing.
            return AuthorityVerdict(
                required=authority.Authority.COMMIT,
                available=authority.Authority.NONE,
                satisfied=False,
                reason_codes=("AUTHORITY_EXCEEDS_PROVENANCE",),
            )

    # -- internals -----------------------------------------------------------
    def _analysis(
        self, request: DefenseRequest
    ) -> tuple[TaintAnalysis, lifecycle.LifecycleState, memory.MemoryState]:
        key = (id(request), str(request.run_id), int(request.step_id))
        if self._memo_key == key and self._memo is not None:
            return self._memo
        analysis = taint.summarize(request)
        life = lifecycle.evaluate(request)
        mem = memory.evaluate(request, analysis)
        analysis = _fold_memory(analysis, mem)
        self._memo_key = key
        self._memo = (analysis, life, mem)
        return self._memo


def _fold_memory(analysis: TaintAnalysis, mem: memory.MemoryState) -> TaintAnalysis:
    """Recalled memory that is being *acted on* caps authority like any source.

    A memory entry written after reading untrusted content carries that trust
    forward; if a control argument of this action came out of such an entry, the
    action's taint is the memory's taint.
    """
    if not mem.recalled or mem.taint is None:
        return analysis
    if not mem.value_from_memory:
        return analysis
    if mem.taint.rank <= analysis.action_taint.rank:
        return analysis
    return TaintAnalysis(
        spans=analysis.spans,
        matches=analysis.matches,
        action_taint=mem.taint,
        context_taint=analysis.context_taint,
        max_sensitivity=analysis.max_sensitivity,
        value_derived_from_untrusted=analysis.value_derived_from_untrusted
        or mem.taint.rank >= taint.UNTRUSTED_RANK,
        instructed_from_untrusted=analysis.instructed_from_untrusted,
        memory_taint=analysis.memory_taint,
        chain=analysis.chain,
        tainted_spans=analysis.tainted_spans,
        sensitive_spans=analysis.sensitive_spans,
        secret_values=analysis.secret_values,
        influencing_ids=analysis.influencing_ids,
    )


def _fail_closed_summary() -> TaintSummary:
    """If analysis fails, assume the worst about provenance rather than the best."""
    from aegis.types import TrustLevel

    return TaintSummary(
        action_taint=TrustLevel.UNTRUSTED_EXTERNAL,
        context_taint=TrustLevel.UNTRUSTED_EXTERNAL,
    )


__all__ = ["ProvenanceEngine", "action_digest", "authority", "lifecycle", "memory", "taint"]
