"""Lane A — the authority model.

One rule, stated twice:

* **Authority comes from the user and the policy, never from observed data.**
* Data flows freely; authority does not flow at all.

Mechanically: every action *requires* an authority level, derived from what it
does to the world. Every action *has available* an authority level, which is the
ceiling its least-trusted causal input allows (``TRUST_TO_MAX_AUTHORITY``),
raised only by a recorded human confirmation over that exact action. When
required exceeds available, the action is not permitted — however the text that
suggested it was phrased, encoded or split.

Requirements are derived at runtime from the policy context and from the tool's
own verb morphology. There is no table of scenario tool names anywhere in this
file; renaming a scenario cannot change a decision.
"""

from __future__ import annotations

from typing import Any

from aegis.provenance.lifecycle import LifecycleState, stage_for_tool, tool_parts
from aegis.provenance.memory import MemoryState
from aegis.provenance.taint import UNTRUSTED_RANK, TaintAnalysis, instruction_score
from aegis.types import (
    TRUST_TO_MAX_AUTHORITY,
    Authority,
    AuthorityVerdict,
    CandidateAction,
    DefenseRequest,
)

#: Lifecycle stage -> the authority that stage needs.
STAGE_AUTHORITY: dict[str, Authority] = {
    "read": Authority.READ,
    "prepare": Authority.PREPARE,
    "confirm": Authority.COMMIT,
    "execute": Authority.COMMIT,
}

#: Verb downgrades that preserve the action's arguments. `email_send` and
#: `email_draft` take the same payload, so proposing the draft keeps the
#: legitimate part of the intent. `payment_execute` has no such sibling — the
#: honest answer there is "no safer alternative", and we say so.
_ARGUMENT_PRESERVING_DOWNGRADES: dict[str, tuple[str, ...]] = {
    "send": ("draft", "prepare", "compose", "save"),
    "publish": ("draft", "prepare"),
    "post": ("draft", "prepare"),
    "share": ("draft", "prepare"),
    "deploy": ("prepare", "stage"),
    "transmit": ("draft", "prepare"),
}

MAX_REASON_CODES = 16


def allowed_tools(policy: dict[str, Any]) -> list[str]:
    tools = policy.get("allowed_tools")
    return [str(t) for t in tools] if isinstance(tools, list) else []


def required_authority(action: CandidateAction, policy: dict[str, Any]) -> Authority:
    """What this action needs in order to be legitimate.

    Derived from the policy's own consequential/confirmation lists first, then
    from the tool's verb and arguments. Never from a hard-coded tool list.
    """
    kind = str(action.type)
    if kind == "respond":
        return Authority.NONE
    if kind == "memory_write":
        # Writing to memory creates a durable, reversible artifact.
        return Authority.PREPARE
    if kind != "tool_call" or not action.tool:
        return Authority.READ

    tool = str(action.tool)
    consequential = {str(t) for t in policy.get("consequential_tools", []) or []}
    confirming = {str(t) for t in policy.get("confirmation_required_tools", []) or []}
    if tool in consequential or tool in confirming:
        return Authority.COMMIT
    return STAGE_AUTHORITY.get(stage_for_tool(tool, action), Authority.PREPARE)


def available_authority(
    analysis: TaintAnalysis,
    lifecycle: LifecycleState,
    *,
    tool_permitted: bool,
    required: Authority,
) -> Authority:
    """The ceiling this action's provenance allows.

    A recorded confirmation is the user speaking about *this exact action*
    (matched by the simulator's own digest), so it restores COMMIT. Nothing else
    does: not a claim in a document that approval was granted, not a memory
    entry, not an urgent-sounding sentence.

    One asymmetry: *asking* for a confirmation is not acting. A
    `request_confirmation` puts the decision in front of a human, which is the
    behaviour we want from an agent that has hit its ceiling — so the ask itself
    is permitted. It is permitted only while the underlying action is not
    untrusted-derived: inviting a human to rubber-stamp an injected instruction
    is how authority gets laundered, and the answer to that is still no.
    """
    if not tool_permitted:
        return Authority.NONE
    ceiling = TRUST_TO_MAX_AUTHORITY.get(analysis.action_taint, Authority.READ)
    if lifecycle.confirmation_present:
        return Authority.COMMIT
    if lifecycle.is_confirmation_request and analysis.action_taint.rank < UNTRUSTED_RANK:
        return required
    if required == Authority.COMMIT and lifecycle.requires_confirmation:
        # Commit authority is not inferable; it must be granted per action.
        return min(ceiling, Authority.PREPARE, key=lambda level: level.rank)
    return ceiling


def safer_alternative(
    action: CandidateAction,
    policy: dict[str, Any],
    available: Authority,
) -> str | None:
    """A permitted, lower-authority tool that keeps the legitimate intent.

    Only argument-preserving verb downgrades qualify. If there is none, we
    return ``None`` rather than inventing a plausible-looking substitute.
    """
    if str(action.type) != "tool_call" or not action.tool:
        return None
    tool = str(action.tool)
    permitted = allowed_tools(policy)
    if not permitted:
        return None
    family, tokens = tool_parts(tool)
    downgrades: set[str] = set()
    for token in tokens:
        downgrades.update(_ARGUMENT_PRESERVING_DOWNGRADES.get(token, ()))
    if not downgrades:
        return None

    best: tuple[int, str] | None = None
    for name in permitted:
        if name == tool:
            continue
        other_family, other_tokens = tool_parts(name)
        if other_family != family:
            continue
        if not downgrades.intersection(other_tokens):
            continue
        needed = required_authority(
            CandidateAction(type="tool_call", tool=name, arguments=dict(action.arguments)),
            policy,
        )
        if needed.rank > available.rank:
            continue
        rank = needed.rank
        if best is None or rank > best[0]:
            best = (rank, name)
    return best[1] if best else None


def _persists_untrusted_instruction(action: CandidateAction, analysis: TaintAnalysis) -> bool:
    """Is the action about to *persist* an untrusted order into the agent's own context?

    Restricted to `memory_write`, and that restriction is the whole point.
    Memory is re-injected into the agent's context on a later turn, so copying
    an order into it launders that order into something that will look like the
    agent's own knowledge. A case note or a ticket comment is read by people,
    not by the agent — quoting a scam message into one is the task, not an
    attack, and must not be flagged.

    Scored on the text the action carries, not on the whole source span: one
    tool result can bundle a trusted record with a poisoned one, and a faithful
    summary of the trusted half must not be condemned by proximity.
    """
    if str(action.type) != "memory_write":
        return False
    for match in analysis.matches:
        if match.control or not match.span.is_untrusted:
            continue
        if instruction_score(match.value) >= 0.5:
            return True
    return False


def check(
    request: DefenseRequest,
    analysis: TaintAnalysis,
    lifecycle: LifecycleState,
    memory: MemoryState,
) -> AuthorityVerdict:
    """The capability check for one candidate action. Pure; never raises."""
    action = request.target_action()
    policy = request.policy_context or {}
    permitted = allowed_tools(policy)

    is_tool_call = str(action.type) == "tool_call" and bool(action.tool)
    tool_permitted = not (is_tool_call and permitted and str(action.tool) not in permitted)

    required = required_authority(action, policy)
    available = available_authority(
        analysis, lifecycle, tool_permitted=tool_permitted, required=required
    )
    satisfied = required.rank <= available.rank

    ceiling = TRUST_TO_MAX_AUTHORITY.get(analysis.action_taint, Authority.READ)
    acting = required.rank > Authority.READ.rank

    codes: list[str] = []
    if not tool_permitted:
        codes.append("TOOL_NOT_REQUIRED_FOR_GOAL")
    if not satisfied and tool_permitted and analysis.action_taint.rank >= UNTRUSTED_RANK and ceiling.rank < required.rank:
        codes.append("AUTHORITY_EXCEEDS_PROVENANCE")
    codes.extend(lifecycle.reason_codes)
    # Reading is not obeying. An agent that opens the document a poisoned note
    # pointed at has learned something, not done something — and whatever it
    # does next is judged on that action's own provenance. Accusing the read
    # costs real tasks (the legitimate lookup an attacker also happens to want)
    # and buys nothing the later check does not already cover.
    if (acting and analysis.instructed_from_untrusted) or _persists_untrusted_instruction(action, analysis):
        codes.append("UNTRUSTED_INSTRUCTION_SOURCE")
    codes.extend(memory.reason_codes(acting=acting))

    ordered: list[str] = []
    for code in codes:
        if code not in ordered:
            ordered.append(code)

    alternative = None
    if not satisfied and tool_permitted:
        alternative = safer_alternative(action, policy, available)

    return AuthorityVerdict(
        required=required,
        available=available,
        satisfied=satisfied,
        reason_codes=tuple(ordered[:MAX_REASON_CODES]),
        safer_alternative=alternative,
        lifecycle_stage=lifecycle.stage,
        requires_confirmation=lifecycle.requires_confirmation,
        confirmation_present=lifecycle.confirmation_present,
    )


__all__ = [
    "STAGE_AUTHORITY",
    "allowed_tools",
    "available_authority",
    "check",
    "required_authority",
    "safer_alternative",
]
