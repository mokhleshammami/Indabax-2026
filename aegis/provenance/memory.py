"""Lane A — memory provenance.

Agent memory is a laundering channel. Text read from an untrusted page in turn
one comes back in turn four wearing the agent's own voice, and an agent that
treats "what I remember" as "what I was told by my principal" has handed
authority to whoever wrote the page.

The rule here is the thesis applied across time:

* a memory entry written after reading untrusted content **stays untrusted**
  when recalled — the simulator already stamps the entry with the least-trusted
  level seen in the turn it was written, and we honour that stamp;
* recalled memory is **evidence, never an instruction**. It may inform an
  action; it may not authorize one;
* when recalled memory asserts a *policy* and a trusted source states a policy
  on the same subject, **the trusted source wins** — and we say so out loud.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aegis.provenance.taint import (
    UNTRUSTED_RANK,
    Span,
    TaintAnalysis,
    instruction_score,
)
from aegis.types import DefenseRequest, TrustLevel, least_trusted

#: Source types whose content is a policy statement by construction.
_POLICY_SOURCES = frozenset({"policy", "wiki", "document", "system", "system_policy"})

#: Normative phrasing: text that tells the agent what is *permitted*, not what is.
_POLICY_CLAIM_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bpolic(?:y|ies)\b"),
    # "Standing SOC manager instruction:" — the qualifier words vary, the shape does not.
    re.compile(r"\b(?:standing|permanent|blanket)\s+(?:\w+\s+){0,3}(?:instruction|order|approval|policy|exception)s?\b"),
    re.compile(r"\b(?:approved|authorised|authorized|signed off)\s+by\b"),
    re.compile(r"\bpre-?approved\b"),
    re.compile(r"\bno (?:further )?(?:sign-?off|approval|confirmation)\b"),
    re.compile(r"\b(?:may|can|are allowed to|is allowed to|are permitted to|is permitted to)\s+be?\s*\w+"),
    re.compile(r"\b(?:must|should|shall|never|always)\s+(?:be\s+)?\w+"),
    re.compile(r"\bexempt(?:ion|ed)?\b"),
    re.compile(r"\boverride\b"),
    re.compile(r"\brequires? (?:dual )?approval\b"),
)

#: Minimum shared stems before two policy statements count as being about the
#: same subject. Keeps POLICY_CONFLICT_TRUSTED_WINS from firing on coincidence.
MIN_SUBJECT_OVERLAP = 2


def is_policy_claim(text: str) -> bool:
    """True when the text states a rule rather than reporting a fact."""
    lowered = " ".join(text.split()).lower()
    if not lowered:
        return False
    return sum(1 for pattern in _POLICY_CLAIM_PATTERNS if pattern.search(lowered)) >= 1


@dataclass(frozen=True)
class MemoryState:
    """What recalled memory contributes to this step."""

    taint: TrustLevel | None = None
    #: Recalled memory exists in this request at all.
    recalled: bool = False
    #: Recalled memory is untrusted *and* asserts a rule or issues an order.
    untrusted_authority_claim: bool = False
    #: A control argument of the candidate action traces to recalled memory.
    value_from_memory: bool = False
    #: The recalled memory reads as an order aimed at the agent.
    instruction_shaped: bool = False
    #: An untrusted memory policy claim collides with a trusted policy source.
    conflicts_with_trusted: bool = False
    #: Source of the trusted policy that wins the collision, for the explanation.
    trusted_policy_source: str | None = None

    def reason_codes(self, *, acting: bool) -> tuple[str, ...]:
        """`acting` is True when the step does more than read.

        `MEMORY_AUTHORITY_DENIED` needs a *causal* link — a control argument of
        this action came out of the recalled entry. The mere presence of a
        poisoned memory is not a violation; obeying it is. Without that link the
        step is reported only as a policy collision, which is by itself benign:
        `POLICY_CONFLICT_TRUSTED_WINS` states that the trusted rule was the one
        applied, which is the *good* outcome as often as the bad one.
        """
        codes: list[str] = []
        if self.conflicts_with_trusted:
            codes.append("POLICY_CONFLICT_TRUSTED_WINS")
        if acting and self.untrusted_authority_claim and self.value_from_memory:
            codes.append("MEMORY_AUTHORITY_DENIED")
        return tuple(codes)


def memory_spans(spans: tuple[Span, ...] | list[Span]) -> list[Span]:
    """Conversation items that came back out of memory."""
    return [span for span in spans if span.is_memory]


def evaluate(request: DefenseRequest, analysis: TaintAnalysis) -> MemoryState:
    """Memory's contribution to this step. Pure; never raises."""
    recalled = memory_spans(analysis.spans)
    if not recalled:
        return MemoryState()

    taint = least_trusted([span.trust for span in recalled])
    untrusted = [span for span in recalled if span.trust.rank >= UNTRUSTED_RANK]

    claim_spans = [span for span in untrusted if is_policy_claim(span.text)]
    instruction = any(instruction_score(span.text) >= 0.35 for span in untrusted)
    value_from_memory = any(
        match.carries_taint and match.span.is_memory for match in analysis.matches
    )

    conflict = False
    trusted_source: str | None = None
    if claim_spans:
        trusted_policy = [
            span
            for span in analysis.spans
            if not span.is_memory
            and span.trust.rank < UNTRUSTED_RANK
            and (span.source_type in _POLICY_SOURCES or is_policy_claim(span.text))
            and is_policy_claim(span.text)
        ]
        for claim in claim_spans:
            for trusted in trusted_policy:
                shared = claim.word_stems & trusted.word_stems
                if len(shared) >= MIN_SUBJECT_OVERLAP:
                    conflict = True
                    trusted_source = f"{trusted.source_type}/{trusted.source_id}"
                    break
            if conflict:
                break

    return MemoryState(
        taint=taint,
        recalled=True,
        untrusted_authority_claim=bool(claim_spans) or (bool(untrusted) and instruction),
        value_from_memory=value_from_memory,
        instruction_shaped=instruction,
        conflicts_with_trusted=conflict,
        trusted_policy_source=trusted_source,
    )


__all__ = ["MemoryState", "evaluate", "is_policy_claim", "memory_spans"]
