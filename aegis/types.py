"""AEGIS frozen contract.

Everything four parallel workstreams share lives here. **Do not change this file
without team agreement** — Lanes A, B, C and D all compile against it.

Layout of the contract:

* `SENTINEL v1 wire schemas` — mirrored from the organizers' starter kit so AEGIS
  runs as a standalone HTTP service with no import of `sentinel`.
* `Trust / Sensitivity` — ordered lattices used by the taint engine.
* `Lane A -> Lane B` — `TaintSummary`, `AuthorityVerdict`, `ProvenanceLink`.
* `Lane B internals` — `SignalContext`, `SignalResult`, `Signal`, `Verdict`.
* `Lane C` — `TraceRecord`, the observability record (see SCHEMA.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION = "aegis.trace/v1"

# ---------------------------------------------------------------------------
# SENTINEL v1 wire schemas (mirrored — requests lenient, responses strict)
# ---------------------------------------------------------------------------


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore")


class CandidateAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["respond", "tool_call", "memory_write", "request_confirmation"]
    tool: str | None = None
    arguments: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    content: str | None = None
    final: bool = False
    confirmation_for: CandidateAction | None = None

    def text_payload(self) -> str:
        """All free text the action carries, for taint and leak checks."""
        parts: list[str] = []
        if self.content:
            parts.append(self.content)
        parts.extend(str(v) for v in self.arguments.values() if v is not None)
        if self.confirmation_for is not None:
            parts.append(self.confirmation_for.text_payload())
        return "\n".join(parts)


class Provenance(_Lenient):
    source_type: str
    source_id: str
    trust_level: Literal[
        "system_policy",
        "authenticated_user",
        "trusted_internal",
        "untrusted_internal",
        "untrusted_external",
        "adversary_controlled",
    ]
    origin_actor: str
    retrieved_via: str
    sensitivity: Literal["public", "internal", "confidential", "restricted"] = "internal"


class ProvenanceRecord(_Lenient):
    id: str
    provenance: Provenance


class ConversationItem(_Lenient):
    role: str
    kind: str
    content: str
    provenance_ids: list[str] = Field(default_factory=list)


class ObservationView(_Lenient):
    kind: str
    content: str
    provenance_ids: list[str] = Field(default_factory=list)


class HistoryDigest(_Lenient):
    steps_taken: int = 0
    turn_index: int = 0
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    confirmations_granted: list[str] = Field(default_factory=list)
    blocked_count: int = 0
    escalated_count: int = 0
    least_trusted_seen: str | None = None
    most_sensitive_seen: str | None = None


class DefenseRequest(_Lenient):
    run_id: str
    step_id: int
    user_goal: str
    conversation: list[ConversationItem] = Field(default_factory=list)
    observation: ObservationView | None = None
    candidate_action: CandidateAction
    policy_context: dict[str, Any] = Field(default_factory=dict)
    provenance: list[ProvenanceRecord] = Field(default_factory=list)
    history_digest: HistoryDigest = Field(default_factory=HistoryDigest)

    def provenance_map(self) -> dict[str, Provenance]:
        return {record.id: record.provenance for record in self.provenance}

    def target_action(self) -> CandidateAction:
        """The action actually under review (unwraps request_confirmation)."""
        action = self.candidate_action
        if action.type == "request_confirmation" and action.confirmation_for is not None:
            return action.confirmation_for
        return action


class DefenseDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["allow", "block", "escalate", "rewrite"]
    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reason_codes: list[str] = Field(default_factory=list, max_length=16)
    explanation: str | None = Field(default=None, max_length=500)
    rewritten_action: CandidateAction | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _rewrite_needs_action(self) -> DefenseDecision:
        if (self.decision == "rewrite") != (self.rewritten_action is not None):
            raise ValueError("rewritten_action is required for, and only for, decision 'rewrite'")
        return self


# ---------------------------------------------------------------------------
# Trust and sensitivity lattices
# ---------------------------------------------------------------------------


class TrustLevel(StrEnum):
    """Ordered most to least trusted. `rank` 0 is most trusted."""

    SYSTEM_POLICY = "system_policy"
    AUTHENTICATED_USER = "authenticated_user"
    TRUSTED_INTERNAL = "trusted_internal"
    UNTRUSTED_INTERNAL = "untrusted_internal"
    UNTRUSTED_EXTERNAL = "untrusted_external"
    ADVERSARY_CONTROLLED = "adversary_controlled"

    @property
    def rank(self) -> int:
        return _TRUST_ORDER[self]

    @property
    def is_trusted(self) -> bool:
        return self.rank <= TrustLevel.TRUSTED_INTERNAL.rank

    @property
    def carries_authority(self) -> bool:
        """Only these levels may *command*. Everything else is evidence."""
        return self.rank <= TrustLevel.AUTHENTICATED_USER.rank


_TRUST_ORDER: dict[TrustLevel, int] = {level: i for i, level in enumerate(TrustLevel)}


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

    @property
    def rank(self) -> int:
        return _SENSITIVITY_ORDER[self]

    @property
    def is_sensitive(self) -> bool:
        return self.rank >= Sensitivity.CONFIDENTIAL.rank


_SENSITIVITY_ORDER: dict[Sensitivity, int] = {level: i for i, level in enumerate(Sensitivity)}


def least_trusted(levels: list[TrustLevel]) -> TrustLevel:
    """Join on the trust lattice. Empty means nothing untrusted touched it."""
    if not levels:
        return TrustLevel.AUTHENTICATED_USER
    return max(levels, key=lambda lvl: lvl.rank)


def most_sensitive(levels: list[Sensitivity]) -> Sensitivity:
    if not levels:
        return Sensitivity.PUBLIC
    return max(levels, key=lambda lvl: lvl.rank)


# ---------------------------------------------------------------------------
# Authority lattice — the heart of the method
# ---------------------------------------------------------------------------


class Authority(StrEnum):
    """What a step is permitted to do, independent of what it says it wants.

    NONE     - inert
    READ     - observe the world, no state change
    PREPARE  - create a reversible artifact (draft, prepared payment, note)
    COMMIT   - irreversible / externally visible state change
    """

    NONE = "none"
    READ = "read"
    PREPARE = "prepare"
    COMMIT = "commit"

    @property
    def rank(self) -> int:
        return _AUTHORITY_ORDER[self]

    def __ge__(self, other: Authority) -> bool:  # type: ignore[override]
        return self.rank >= other.rank

    def __le__(self, other: Authority) -> bool:  # type: ignore[override]
        return self.rank <= other.rank


_AUTHORITY_ORDER: dict[Authority, int] = {level: i for i, level in enumerate(Authority)}


#: The central rule. Authority available to a step, given the least-trusted
#: input that influenced it. Data never grants authority; it only removes it.
TRUST_TO_MAX_AUTHORITY: dict[TrustLevel, Authority] = {
    TrustLevel.SYSTEM_POLICY: Authority.COMMIT,
    TrustLevel.AUTHENTICATED_USER: Authority.COMMIT,
    TrustLevel.TRUSTED_INTERNAL: Authority.PREPARE,
    TrustLevel.UNTRUSTED_INTERNAL: Authority.PREPARE,
    TrustLevel.UNTRUSTED_EXTERNAL: Authority.READ,
    TrustLevel.ADVERSARY_CONTROLLED: Authority.READ,
}


# ---------------------------------------------------------------------------
# Lane A -> Lane B contract
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProvenanceLink:
    """One hop in the chain of influence behind a candidate action.

    Rendered by the trace viewer as a row in the "why" panel, so `excerpt` must
    be short and human-readable.
    """

    provenance_id: str
    source_type: str
    source_id: str
    trust_level: TrustLevel
    sensitivity: Sensitivity
    origin_actor: str
    relation: str  # "observation" | "value_match" | "turn_context" | "memory"
    excerpt: str = ""


@dataclass(frozen=True)
class TaintSummary:
    """Lane A's output. Everything Lane B needs about provenance for one step."""

    #: Least-trusted level in the action's chain of influence. Caps authority.
    action_taint: TrustLevel = TrustLevel.AUTHENTICATED_USER
    #: Least-trusted level anywhere in the turn (context, not necessarily causal).
    context_taint: TrustLevel = TrustLevel.AUTHENTICATED_USER
    #: Most sensitive content the agent has seen this turn.
    max_sensitivity: Sensitivity = Sensitivity.PUBLIC
    #: Text drawn from untrusted sources, squashed and lowercased.
    tainted_spans: tuple[str, ...] = ()
    #: Text drawn from confidential/restricted sources.
    sensitive_spans: tuple[str, ...] = ()
    #: Candidate secret tokens observed (identifiers, keys, account numbers).
    secret_values: tuple[str, ...] = ()
    #: Provenance ids judged to have influenced this action.
    influencing_ids: tuple[str, ...] = ()
    #: Full explanation chain, for the trace.
    chain: tuple[ProvenanceLink, ...] = ()
    #: Trust of memory content recalled into this step, if any.
    memory_taint: TrustLevel | None = None
    #: True when the action's own arguments contain text traceable to untrusted input.
    value_derived_from_untrusted: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "action_taint": self.action_taint.value,
            "context_taint": self.context_taint.value,
            "max_sensitivity": self.max_sensitivity.value,
            "secret_values_seen": len(self.secret_values),
            "influencing_ids": list(self.influencing_ids),
            "memory_taint": self.memory_taint.value if self.memory_taint else None,
            "value_derived_from_untrusted": self.value_derived_from_untrusted,
            "chain": [
                {
                    "provenance_id": link.provenance_id,
                    "source": f"{link.source_type}/{link.source_id}",
                    "trust_level": link.trust_level.value,
                    "sensitivity": link.sensitivity.value,
                    "origin_actor": link.origin_actor,
                    "relation": link.relation,
                    "excerpt": link.excerpt,
                }
                for link in self.chain
            ],
        }


@dataclass(frozen=True)
class AuthorityVerdict:
    """Lane A's capability check for one candidate action."""

    required: Authority = Authority.NONE
    available: Authority = Authority.COMMIT
    satisfied: bool = True
    reason_codes: tuple[str, ...] = ()
    #: A lower-authority tool that achieves the legitimate part of the intent.
    safer_alternative: str | None = None
    #: Lifecycle position, e.g. "prepare" -> "confirm" -> "execute".
    lifecycle_stage: str | None = None
    #: True when the lifecycle edge requires a recorded human confirmation.
    requires_confirmation: bool = False
    #: True when such a confirmation exists in the history digest.
    confirmation_present: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "required": self.required.value,
            "available": self.available.value,
            "satisfied": self.satisfied,
            "reason_codes": list(self.reason_codes),
            "safer_alternative": self.safer_alternative,
            "lifecycle_stage": self.lifecycle_stage,
            "requires_confirmation": self.requires_confirmation,
            "confirmation_present": self.confirmation_present,
        }


# ---------------------------------------------------------------------------
# Lane B internals
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SignalContext:
    """Read-only bundle handed to every signal. Signals must be pure functions."""

    request: DefenseRequest
    taint: TaintSummary
    authority: AuthorityVerdict

    @property
    def action(self) -> CandidateAction:
        return self.request.target_action()

    @property
    def policy(self) -> dict[str, Any]:
        return self.request.policy_context

    @property
    def allowed_tools(self) -> list[str]:
        return list(self.request.policy_context.get("allowed_tools", []))


@dataclass(frozen=True)
class SignalResult:
    """One signal's contribution. `score` is risk in [0, 1]; 0 means 'nothing seen'."""

    name: str
    score: float
    reason_codes: tuple[str, ...] = ()
    #: Small, JSON-safe evidence dict rendered in the trace viewer.
    detail: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "score": round(float(self.score), 4),
            "reason_codes": list(self.reason_codes),
            "detail": self.detail,
        }


@runtime_checkable
class Signal(Protocol):
    """Every detector implements this. Pure, side-effect free, never raises."""

    name: str

    def score(self, ctx: SignalContext) -> SignalResult: ...


@dataclass(frozen=True)
class Verdict:
    """Arbiter output, converted to a `DefenseDecision` at the boundary."""

    decision: Literal["allow", "block", "escalate", "rewrite"]
    risk_score: float
    confidence: float
    reason_codes: tuple[str, ...] = ()
    explanation: str | None = None
    rewritten_action: CandidateAction | None = None

    def to_decision(self, metadata: dict[str, Any] | None = None) -> DefenseDecision:
        return DefenseDecision(
            decision=self.decision,
            risk_score=round(min(1.0, max(0.0, float(self.risk_score))), 4),
            confidence=round(min(1.0, max(0.0, float(self.confidence))), 4),
            reason_codes=list(self.reason_codes)[:16],
            explanation=(self.explanation or None),
            rewritten_action=self.rewritten_action,
            metadata=metadata or {},
        )


# ---------------------------------------------------------------------------
# Lane C — the observability record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TraceRecord:
    """One decision, fully explained. Serialized as one JSON line. See SCHEMA.md."""

    run_id: str
    step_id: int
    ts: str
    user_goal: str
    action: dict[str, Any]
    observation: dict[str, Any] | None
    taint: dict[str, Any]
    authority: dict[str, Any]
    signals: list[dict[str, Any]]
    risk_score: float
    confidence: float
    decision: str
    reason_codes: list[str]
    explanation: str | None
    rewritten_action: dict[str, Any] | None
    latency_ms: float
    schema: str = SCHEMA_VERSION
    #: Populated by the eval harness after the run: what the sim actually did.
    outcome: dict[str, Any] | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "ts": self.ts,
            "user_goal": self.user_goal,
            "action": self.action,
            "observation": self.observation,
            "taint": self.taint,
            "authority": self.authority,
            "signals": self.signals,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "decision": self.decision,
            "reason_codes": self.reason_codes,
            "explanation": self.explanation,
            "rewritten_action": self.rewritten_action,
            "latency_ms": self.latency_ms,
            "outcome": self.outcome,
        }


# ---------------------------------------------------------------------------
# Shared text helpers (used by several lanes — keep tiny and dependency-free)
# ---------------------------------------------------------------------------


def squash(text: str) -> str:
    """Whitespace-normalized, lowercased text. The canonical form for matching."""
    return " ".join(text.split()).lower()


__all__ = [
    "SCHEMA_VERSION",
    "Authority",
    "AuthorityVerdict",
    "CandidateAction",
    "ConversationItem",
    "DefenseDecision",
    "DefenseRequest",
    "HistoryDigest",
    "ObservationView",
    "Provenance",
    "ProvenanceLink",
    "ProvenanceRecord",
    "Sensitivity",
    "Signal",
    "SignalContext",
    "SignalResult",
    "TRUST_TO_MAX_AUTHORITY",
    "TaintSummary",
    "TraceRecord",
    "TrustLevel",
    "Verdict",
    "least_trusted",
    "most_sensitive",
    "squash",
]
