"""Lane A — lifecycle state machine.

Consequential work in every one of these domains is staged:
``read -> prepare -> confirm -> execute``. Finance spells it out
(``prepare -> confirm -> execute``), the SOC spells out a shorter version
(``prepare`` before ``execute``), and enterprise ticketing expresses the same
idea as a terminal status transition.

Nothing here is keyed to a tool name or a scenario. A stage comes from the
tool's own verb morphology; whether an ordering is *enforced* comes from the
policy's ``prerequisite`` rules; whether a confirmation is *required* comes from
the policy's ``requires_confirmation`` rules plus the consequential tool list.

The one absolute: a confirmation exists only when the **history digest** says a
human granted it, matched by the simulator's own action digest. A claim inside
observed content that "approval was already granted" is content, not authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from aegis.types import CandidateAction, DefenseRequest

# --------------------------------------------------------------------------
# Action digest — byte-for-byte the simulator's `CandidateAction.digest`
# (sentinel/core/actions.py; mirrored in starter-kits/python-defense).
# --------------------------------------------------------------------------


def _canonical(value: Any) -> Any:
    if isinstance(value, str):
        return " ".join(value.split())
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def action_digest(action: CandidateAction) -> str:
    """Stable identity used for confirmations. Must match the simulator exactly."""
    payload: dict[str, Any] = {
        "type": str(action.type),
        "tool": action.tool,
        "arguments": {k: _canonical(v) for k, v in sorted(action.arguments.items())},
        "content": action.content if str(action.type) != "tool_call" else None,
    }
    if action.confirmation_for is not None:
        payload["confirmation_for"] = action_digest(action.confirmation_for)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:24]


# --------------------------------------------------------------------------
# Stages from verb morphology
# --------------------------------------------------------------------------

STAGES: tuple[str, ...] = ("read", "prepare", "confirm", "execute")

_READ_VERBS = frozenset(
    {"read", "search", "lookup", "list", "get", "view", "fetch", "query", "find", "show", "inspect", "summary"}
)
_PREPARE_VERBS = frozenset(
    {"prepare", "draft", "create", "note", "add", "compose", "stage", "open", "log", "record", "save", "write", "new"}
)
_CONFIRM_VERBS = frozenset({"confirm", "approve", "authorize", "authorise", "sign", "accept"})
_EXECUTE_VERBS = frozenset(
    {
        "execute",
        "send",
        "close",
        "disable",
        "delete",
        "remove",
        "transfer",
        "pay",
        "publish",
        "post",
        "commit",
        "apply",
        "revoke",
        "reset",
        "isolate",
        "block",
        "terminate",
        "cancel",
        "run",
        "deploy",
        "release",
    }
)
#: Verbs whose stage depends on the arguments (a terminal status is a commit).
_MUTATE_VERBS = frozenset({"update", "modify", "edit", "set", "change", "patch", "assign", "move", "transition"})

#: Status values that end an object's life. Reaching one is externally visible.
TERMINAL_STATUSES = frozenset(
    {
        "closed",
        "close",
        "resolved",
        "resolve",
        "completed",
        "complete",
        "done",
        "cancelled",
        "canceled",
        "approved",
        "executed",
        "disabled",
        "archived",
        "rejected",
        "paid",
        "settled",
        "final",
        "finished",
    }
)

_STATUS_ARG = re.compile(r"(^|_)(status|state|stage|disposition|resolution)$")

_STAGE_WORDS: dict[str, str] = {}
for _verb in _READ_VERBS:
    _STAGE_WORDS[_verb] = "read"
for _verb in _PREPARE_VERBS:
    _STAGE_WORDS[_verb] = "prepare"
for _verb in _CONFIRM_VERBS:
    _STAGE_WORDS[_verb] = "confirm"
for _verb in _EXECUTE_VERBS:
    _STAGE_WORDS[_verb] = "execute"


def tool_parts(tool: str) -> tuple[str, tuple[str, ...]]:
    """``("payment", ("payment", "confirm"))`` — family prefix and every token."""
    tokens = tuple(part for part in str(tool).lower().split("_") if part)
    family = tokens[0] if tokens else ""
    return family, tokens


def has_terminal_status(action: CandidateAction) -> bool:
    """True when an argument drives the object to a terminal state."""
    for name, value in action.arguments.items():
        if not isinstance(value, str):
            continue
        folded = value.strip().lower()
        if _STATUS_ARG.search(name.lower()) and folded in TERMINAL_STATUSES:
            return True
    return False


def stage_for_tool(tool: str | None, action: CandidateAction | None = None) -> str:
    """Lifecycle stage implied by a tool's verb, refined by its arguments."""
    if not tool:
        return "read"
    _, tokens = tool_parts(tool)
    stages = [_STAGE_WORDS[token] for token in tokens if token in _STAGE_WORDS]
    mutating = any(token in _MUTATE_VERBS for token in tokens)
    if mutating:
        if action is not None and has_terminal_status(action):
            return "execute"
        stages.append("prepare")
    if not stages:
        return "prepare"  # unknown write-ish tool: never assume it is only a read
    return max(stages, key=STAGES.index)


# --------------------------------------------------------------------------
# Policy-derived ordering
# --------------------------------------------------------------------------

_ARROW_CHAIN = re.compile(r"([a-z]+)\s*(?:->|→|then|,\s*then)\s*([a-z]+)(?:\s*(?:->|→|then)\s*([a-z]+))?")
_BEFORE_RULE = re.compile(r"\b([a-z]+)\s+before\s+(?:the\s+|any\s+)?([a-z]+)\b")

#: Inflections a policy sentence puts on a stage verb: "prepared", "execution".
_INFLECTIONS = ("ations", "ation", "ions", "ion", "ings", "ing", "eds", "ed", "es", "s", "d")


def _stage_of_word(word: str) -> str | None:
    """Map an English word to a lifecycle stage, tolerating inflection.

    Deliberately conservative: it only ever returns a stage when a *verb* root
    is recovered. ``payments`` and ``remediations`` yield nothing, which is what
    lets `ordering_enforced` use them as family nouns instead.
    """
    root = word.lower()
    if root in _STAGE_WORDS:
        return _STAGE_WORDS[root]
    for suffix in _INFLECTIONS:
        if not root.endswith(suffix):
            continue
        base = root[: -len(suffix)]
        for candidate in (base, base + "e"):
            if len(candidate) >= 3 and candidate in _STAGE_WORDS:
                return _STAGE_WORDS[candidate]
    return None


_LEADING_NOUN = re.compile(r"^\s*([a-z]+)")


@dataclass(frozen=True)
class Ordering:
    """A stage chain the policy orders, and the tool families it applies to."""

    stages: tuple[str, ...] = ()
    #: Tool-name prefixes the rule is about. Empty means "every family".
    families: frozenset[str] = frozenset()

    def applies_to(self, family: str) -> bool:
        return bool(self.stages) and (not self.families or family in self.families)


def ordering_enforced(policy: dict[str, Any]) -> Ordering:
    """The stage chain the policy actually orders, parsed from its own rules.

    ``policy_context["rules"]`` exposes each rule's ``kind`` and ``description``
    but not its structured ``requires`` list, so we read the description the
    policy author wrote: "Payments follow prepare -> confirm -> execute",
    "Remediations must be prepared before execution". The leading noun scopes
    the rule to a tool family, so a payment-sequencing rule does not start
    demanding that incidents be created before they are closed.

    When a ``prerequisite`` rule exists but says nothing we can parse, fall back
    to the full chain for every family; when no such rule exists, enforce no
    ordering at all.
    """
    rules = policy.get("rules")
    if not isinstance(rules, list):
        return Ordering()
    prerequisite = [r for r in rules if isinstance(r, dict) and str(r.get("kind", "")).lower() == "prerequisite"]
    if not prerequisite:
        return Ordering()
    chain: list[str] = []
    families: set[str] = set()
    for rule in prerequisite:
        description = str(rule.get("description", "")).lower()
        for match in _ARROW_CHAIN.finditer(description):
            for word in match.groups():
                if not word:
                    continue
                stage = _stage_of_word(word)
                if stage and stage not in chain:
                    chain.append(stage)
        for match in _BEFORE_RULE.finditer(description):
            for stage in (_stage_of_word(match.group(1)), _stage_of_word(match.group(2))):
                if stage and stage not in chain:
                    chain.append(stage)
        noun = _LEADING_NOUN.match(description)
        if noun:
            word = noun.group(1)
            if _stage_of_word(word) is None and len(word) > 3:
                families.add(word[:-1] if word.endswith("s") else word)
    ordered = tuple(stage for stage in STAGES if stage in chain)
    if len(ordered) < 2:
        ordered = ("prepare", "confirm", "execute")
    return Ordering(stages=ordered, families=frozenset(families))


# --------------------------------------------------------------------------
# History
# --------------------------------------------------------------------------


def succeeded_tools(request: DefenseRequest) -> set[str]:
    """Tools whose calls actually went through, from the history digest."""
    done: set[str] = set()
    for entry in request.history_digest.tool_calls:
        if not isinstance(entry, dict):
            tool = getattr(entry, "tool", None)
            succeeded = getattr(entry, "succeeded", None)
            decision = getattr(entry, "decision", None)
        else:
            tool = entry.get("tool")
            succeeded = entry.get("succeeded")
            decision = entry.get("decision")
        if not tool:
            continue
        if succeeded is False:
            continue
        if succeeded is None and str(decision) in {"block", "blocked"}:
            continue
        done.add(str(tool))
    return done


def confirmation_present(request: DefenseRequest, action: CandidateAction) -> bool:
    """Only the history digest can grant a confirmation. Content never can."""
    try:
        digest = action_digest(action)
    except Exception:
        return False
    return digest in set(request.history_digest.confirmations_granted)


# --------------------------------------------------------------------------
# The verdict fragment
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class LifecycleState:
    stage: str = "read"
    requires_confirmation: bool = False
    confirmation_present: bool = False
    order_violation: bool = False
    missing_prerequisites: tuple[str, ...] = ()
    #: True when the candidate is itself a `request_confirmation` wrapper.
    is_confirmation_request: bool = False

    @property
    def reason_codes(self) -> tuple[str, ...]:
        codes: list[str] = []
        if self.order_violation:
            codes.append("LIFECYCLE_ORDER_VIOLATION")
        if self.requires_confirmation and not self.confirmation_present and not self.is_confirmation_request:
            codes.append("MISSING_CONFIRMATION")
        return tuple(codes)


def _confirmation_required(tool: str, action: CandidateAction, policy: dict[str, Any], stage: str) -> bool:
    consequential = {str(t) for t in policy.get("consequential_tools", []) or []}
    named = {str(t) for t in policy.get("confirmation_required_tools", []) or []}
    if tool in consequential or tool in named:
        return True
    # A policy rule of kind `requires_confirmation` scoped to "consequential"
    # still covers status transitions the registry does not flag, e.g. closing
    # a ticket. Stage is derived from the arguments, so this stays generic.
    rules = policy.get("rules")
    has_confirmation_rule = isinstance(rules, list) and any(
        isinstance(r, dict) and str(r.get("kind", "")).lower() == "requires_confirmation" for r in rules
    )
    return bool(has_confirmation_rule and stage == "execute" and has_terminal_status(action))


def evaluate(request: DefenseRequest) -> LifecycleState:
    """Where this action sits in its object's lifecycle, and what that demands."""
    candidate = request.candidate_action
    action = request.target_action()
    policy = request.policy_context or {}

    if str(action.type) != "tool_call" or not action.tool:
        stage = "prepare" if str(action.type) == "memory_write" else "read"
        return LifecycleState(
            stage=stage,
            is_confirmation_request=str(candidate.type) == "request_confirmation",
        )

    tool = str(action.tool)
    stage = stage_for_tool(tool, action)
    requires = _confirmation_required(tool, action, policy, stage)
    present = confirmation_present(request, action)

    enforced = ordering_enforced(policy)
    family, _ = tool_parts(tool)
    missing: list[str] = []
    if stage in enforced.stages and enforced.applies_to(family):
        allowed = [str(t) for t in policy.get("allowed_tools", []) or []]
        done = succeeded_tools(request)
        index = enforced.stages.index(stage)
        for earlier in enforced.stages[:index]:
            siblings = [
                name
                for name in allowed
                if tool_parts(name)[0] == family and name != tool and stage_for_tool(name) == earlier
            ]
            if siblings and not any(name in done for name in siblings):
                missing.append(earlier)

    return LifecycleState(
        stage=stage,
        requires_confirmation=requires,
        confirmation_present=present,
        order_violation=bool(missing),
        missing_prerequisites=tuple(missing),
        is_confirmation_request=str(candidate.type) == "request_confirmation",
    )


__all__ = [
    "STAGES",
    "TERMINAL_STATUSES",
    "LifecycleState",
    "Ordering",
    "action_digest",
    "confirmation_present",
    "evaluate",
    "has_terminal_status",
    "ordering_enforced",
    "stage_for_tool",
    "succeeded_tools",
    "tool_parts",
]
