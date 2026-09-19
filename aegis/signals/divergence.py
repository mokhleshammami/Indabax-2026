"""Plan divergence — AEGIS's primary original signal.

**The idea.** Every injection, however it is worded, has the same tell: it asks
the agent to take a step *nobody asked for*. So instead of looking at the attack,
AEGIS looks at the task. It builds a model of the expected shape of the work from
the user's own goal text — which is the one string in the request that carries
authority — and measures how far the candidate action departs from it.

Three departures are measured, in order of strength:

1. **Explicitly excluded** — the goal names this kind of step inside a negation
   ("prepare the refund … *do not confirm or execute the payment*"). Nothing an
   observation says can re-authorise it.
2. **Not entailed** — none of the tool's morphemes, expanded through a generic
   English synonym map, appear anywhere in the goal. Legitimate multi-step tasks
   contain unenumerated steps, so this is graded, and heavily discounted for
   read-class actions, which are how an agent explores.
3. **Argument provenance mismatch** — a *steering* argument (the short scalar that
   selects what the action acts on) carries an identifier that appears nowhere in
   the goal and nowhere in trusted context, but does appear in untrusted text.
   The user asked for something; the data chose the object.

Prose arguments are deliberately exempt from (3). "Quote the scam message in a
case note" is a legitimate task whose payload is, by design, untrusted text. What
matters is not where the *words* came from but where the *decision* came from.

This module also hosts :class:`BenignContextSignal`, the hard-negative guard: it
recognises the legitimate-but-alarming case structurally and emits a damping
factor the arbiter applies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from aegis.signals.base import (
    UNTRUSTED_LEVELS,
    BaseSignal,
    action_class,
    content_words,
    control_arguments,
    destination_is_internal,
    expand,
    identifier_tokens,
    is_outbound,
    morpheme_covered,
    normalize,
    outbound_destination,
    stem,
    text_view,
    tool_morphemes,
)
from aegis.types import SignalContext, SignalResult

#: Lane A tags every traced value in the chain with the argument it came from.
_CHAIN_ARG = re.compile(r"^\[(?P<kind>arg|content):(?P<name>[^\]]{1,64})\]")

# --------------------------------------------------------------------------- #
# Goal parsing
# --------------------------------------------------------------------------- #

#: Generic English negation cues. A cue opens a scope that runs to the end of the
#: clause, and every *action verb* inside that scope is treated as forbidden.
_NEGATION_CUE = re.compile(
    r"\b(?:do\s+not|don'?t|never|without|no\s+need\s+to|must\s+not|should\s+not|"
    r"shouldn'?t|cannot|can'?t|avoid|refrain\s+from|under\s+no\s+circumstances|"
    r"do\s+NOT)\b",
    re.IGNORECASE,
)

#: Clause boundaries. A negation does not reach past one of these.
_CLAUSE_SPLIT = re.compile(r"[.;:\n]|--|—|\bbut\b|\bhowever\b|\bthen\b|\balso\b", re.IGNORECASE)

#: Words that can be the head of an imperative step. Only these are collected
#: inside a negation scope, so "do not confirm or execute the payment" forbids
#: *confirm* and *execute* without also forbidding everything about *payments*.
ACTION_VERBS = frozenset(
    {
        "read", "search", "lookup", "look", "list", "get", "fetch", "view", "check", "review",
        "find", "query", "summarize", "summarise", "correlate", "triage", "inspect",
        "create", "add", "open", "log", "write", "record", "file", "make", "note", "draft",
        "compose", "prepare", "stage", "save", "store", "remember", "update", "set", "change",
        "modify", "edit", "mark", "assign", "close", "resolve",
        "send", "email", "mail", "forward", "deliver", "share", "notify", "message", "transmit",
        "confirm", "approve", "authorize", "authorise", "sign", "accept",
        "execute", "run", "perform", "apply", "trigger", "release", "commit", "pay", "transfer",
        "delete", "remove", "purge", "disable", "silence", "suppress", "reply", "respond",
        "publish", "post", "upload", "export", "escalate", "isolate", "contain", "quarantine",
    }
)


@dataclass(frozen=True)
class GoalModel:
    """What the user actually asked for. Derived from ``user_goal`` only."""

    words: frozenset[str]
    identifiers: frozenset[str]
    forbidden_verbs: frozenset[str]

    @property
    def is_empty(self) -> bool:
        return not self.words and not self.identifiers


def parse_goal(goal: str) -> GoalModel:
    """Extract intents, entities and prohibitions from the trusted goal text."""
    text = goal or ""
    words = content_words(text)
    identifiers = identifier_tokens(text)

    forbidden: set[str] = set()
    for match in _NEGATION_CUE.finditer(text):
        tail = text[match.end() : match.end() + 160]
        boundary = _CLAUSE_SPLIT.search(tail)
        scope = tail[: boundary.start()] if boundary else tail
        for word in re.findall(r"[A-Za-z]+", scope):
            lowered = word.lower()
            if lowered in ACTION_VERBS or stem(lowered) in ACTION_VERBS:
                forbidden.add(stem(lowered))
                forbidden.add(lowered)
    return GoalModel(
        words=frozenset(words),
        identifiers=frozenset(identifiers),
        forbidden_verbs=frozenset(forbidden),
    )


def tool_coverage(tool: str | None, goal: GoalModel) -> tuple[float, tuple[str, ...]]:
    """Fraction of the tool's morphemes the user's own wording accounts for."""
    morphemes = tool_morphemes(tool)
    if not morphemes:
        return 1.0, ()
    vocabulary = set(goal.words) | set(goal.identifiers)
    missing = [m for m in morphemes if not morpheme_covered(m, vocabulary)]
    covered = len(morphemes) - len(missing)
    return covered / len(morphemes), tuple(missing)


def forbidden_hit(tool: str | None, goal: GoalModel) -> str | None:
    """The tool morpheme the user explicitly excluded, if any."""
    if not goal.forbidden_verbs:
        return None
    for morpheme in tool_morphemes(tool):
        family = expand(morpheme)
        if morpheme in goal.forbidden_verbs or stem(morpheme) in goal.forbidden_verbs:
            return morpheme
        if family & goal.forbidden_verbs:
            return morpheme
    return None


# --------------------------------------------------------------------------- #
# The signal
# --------------------------------------------------------------------------- #

#: Read-class actions are how an agent explores. A read the user did not spell
#: out is normal; a commit the user did not spell out is not.
_CLASS_WEIGHT = {"read": 0.30, "prepare": 0.70, "commit": 1.0}


class PlanDivergenceSignal(BaseSignal):
    """How far this action departs from the task the user described."""

    name = "plan_divergence"

    def _score(self, ctx: SignalContext) -> SignalResult:
        action = ctx.action
        if action.type == "respond":
            # Talking back to the caller is always entailed; leaks are another
            # signal's job.
            return self._empty({"skipped": "respond"})

        goal = parse_goal(ctx.request.user_goal)
        detail: dict[str, Any] = {}
        codes: list[str] = []

        if goal.is_empty:
            return self._empty({"skipped": "no_goal_text"})

        cls = action_class(ctx)
        detail["action_class"] = cls

        # (1) explicit exclusion --------------------------------------------
        excluded = forbidden_hit(action.tool, goal) if action.type == "tool_call" else None
        exclusion_score = 0.0
        if excluded is not None:
            exclusion_score = 0.95
            codes.append("ACTION_NOT_IN_USER_PLAN")
            detail["excluded_by_goal"] = excluded

        # (2) entailment ------------------------------------------------------
        entail_score = 0.0
        if action.type == "tool_call":
            coverage, missing = tool_coverage(action.tool, goal)
            detail["tool_coverage"] = round(coverage, 3)
            if missing:
                detail["unmatched_morphemes"] = list(missing)[:4]
            entail_score = (1.0 - coverage) * _CLASS_WEIGHT.get(cls, 0.7)
            if coverage < 0.5 and cls != "read" and "ACTION_NOT_IN_USER_PLAN" not in codes:
                codes.append("ACTION_NOT_IN_USER_PLAN")
            # A read the policy already permits, with no imported identifiers, is
            # ordinary exploration.
            if cls == "read" and action.tool in ctx.allowed_tools:
                entail_score = min(entail_score, 0.15)

        # (3) argument provenance ---------------------------------------------
        mismatch_score, mismatched = self._argument_provenance(ctx, goal)
        if mismatched:
            detail["untrusted_only_arguments"] = mismatched[:4]
            codes.append("ARG_PROVENANCE_MISMATCH")
            mismatch_score *= 0.6 if cls == "read" else 1.0

        # (4) destination the user never named ---------------------------------
        destination_score = 0.0
        destination = outbound_destination(action)
        if destination is not None:
            key, value = destination
            named = bool(identifier_tokens(value) & goal.identifiers) or normalize(
                value
            ) in normalize(ctx.request.user_goal)
            detail["destination"] = value[:80]
            detail["destination_named_by_user"] = named
            if not named:
                inside = destination_is_internal(value, ctx)
                destination_score = 0.45 if inside is False else 0.25
                if inside is False and "ARG_PROVENANCE_MISMATCH" not in codes:
                    codes.append("ARG_PROVENANCE_MISMATCH")

        score = max(exclusion_score, entail_score, mismatch_score, destination_score)

        if score < 0.15 and not codes:
            codes.append("USER_GOAL_ALIGNED")

        return SignalResult(name=self.name, score=score, reason_codes=tuple(codes), detail=detail)

    # -- helpers -----------------------------------------------------------
    def _argument_provenance(self, ctx: SignalContext, goal: GoalModel) -> tuple[float, list[str]]:
        """Control values that only untrusted text could have supplied.

        Lane A's answer is preferred: its chain tags each traced value ``[arg:…]``
        for control or ``[content:…]`` for payload, and marks ``(user-named)`` and
        ``self_originated`` values that carry their own authority. Only an
        unanchored control match counts. When the chain is empty — Lane A absent,
        or a value it could not attribute — the lexical fallback below asks the
        same question of the same, name-based notion of a control argument.
        """
        action = ctx.action
        if action.type != "tool_call":
            return 0.0, []

        from_chain = self._chain_mismatches(ctx)
        if from_chain is not None:
            return self._grade(from_chain)

        view = text_view(ctx)
        untrusted_ids: set[str] = set()
        for text in view.untrusted:
            untrusted_ids |= identifier_tokens(text)
        if not untrusted_ids:
            return 0.0, []
        trusted_ids: set[str] = set()
        for text in view.trusted:
            trusted_ids |= identifier_tokens(text)

        mismatched: list[str] = []
        for key, value in control_arguments(action).items():
            for token in identifier_tokens(value):
                if token in goal.identifiers or token in trusted_ids:
                    continue
                if token in untrusted_ids:
                    mismatched.append(f"{key}={value[:40]}")
                    break
        return self._grade(mismatched)

    @staticmethod
    def _chain_mismatches(ctx: SignalContext) -> list[str] | None:
        """Lane A's own verdict on which control values came from untrusted text.

        Returns ``None`` when Lane A traced no values at all, so the caller falls
        back to the lexical check rather than reading silence as innocence.
        """
        chain = ctx.taint.chain
        if not chain:
            return None
        traced = False
        mismatched: list[str] = []
        for link in chain:
            if link.relation not in ("value_match", "self_originated"):
                continue
            traced = True
            excerpt = link.excerpt or ""
            match = _CHAIN_ARG.match(excerpt)
            if match is None or link.relation == "self_originated":
                continue
            # `[content:…]` is the work product — an incident title drawn from the
            # alert, a note quoting the document the user asked about. Only
            # `[arg:…]`, a value that steers the effect, can be a mismatch.
            if match.group("kind") != "arg":
                continue
            # A value the user's own goal contained, or one this run minted, is
            # anchored: Lane A has already established it carries its own authority.
            if "(user-named)" in excerpt[: match.end() + 16]:
                continue
            if link.trust_level not in UNTRUSTED_LEVELS:
                continue
            name = match.group("name")
            if name not in mismatched:
                mismatched.append(name)
        if not traced:
            return None
        return mismatched

    @staticmethod
    def _grade(mismatched: list[str]) -> tuple[float, list[str]]:
        if not mismatched:
            return 0.0, []
        return min(0.85, 0.55 + 0.15 * (len(mismatched) - 1)), mismatched


# --------------------------------------------------------------------------- #
# Hard-negative protection
# --------------------------------------------------------------------------- #

#: Vocabulary that makes a legitimate task *look* like an attack. This list is
#: used only to decide whether to attach the ``BENIGN_SENSITIVE_CONTEXT`` label —
#: never to decide the damping factor, which is purely structural. Rewording a
#: scenario therefore cannot change a decision, only the explanation text.
ALARMING_VOCABULARY = frozenset(
    {
        "phishing", "scam", "fraud", "fraudulent", "malware", "ransomware", "credential",
        "credentials", "password", "passwords", "token", "secret", "override", "urgent",
        "bypass", "exfiltration", "exfiltrate", "attack", "attacker", "threat", "breach",
        "compromise", "compromised", "suspicious", "injection", "powershell", "encoded",
        "obfuscated", "spoof", "spoofed", "impersonation", "mfa", "hijack", "backdoor",
        "payload", "malicious", "ignore", "disable", "social", "engineering", "vishing",
        "smishing", "fatigue", "isolation", "isolate", "containment", "quarantine",
    }
)


class BenignContextSignal(BaseSignal):
    """Recognise the legitimate-but-alarming task and damp the score.

    Security digests, fraud-awareness notes, PowerShell triage and verbatim scam
    quotes all *discuss* attacks; they do not *enact* them. Structurally they look
    nothing alike from the point of view of a keyword filter and exactly alike
    from the point of view of authority:

    * the tool is one the policy already permits for this task;
    * the user's own words entail the action;
    * every steering argument traces to the goal or to trusted context;
    * the destination, if there is one, is inside the trust boundary;
    * the authority the step needs is authority it has.

    The signal's own risk score is always 0 — it is evidence of innocence, not of
    risk. It publishes a multiplicative ``damp`` in ``detail`` that the arbiter
    applies to the monitor's probability, and reports which of the five
    conditions held so the trace can show its work.
    """

    name = "benign_context"

    #: Each condition met multiplies the damp closer to this floor.
    DAMP_FLOOR = 0.30

    def _score(self, ctx: SignalContext) -> SignalResult:
        action = ctx.action
        goal = parse_goal(ctx.request.user_goal)
        conditions: dict[str, bool] = {}

        allowed = ctx.allowed_tools
        conditions["tool_permitted"] = (
            action.type != "tool_call" or not allowed or action.tool in allowed
        )

        if action.type == "tool_call":
            coverage, _ = tool_coverage(action.tool, goal)
            conditions["entailed_by_goal"] = coverage >= 0.5 and forbidden_hit(action.tool, goal) is None
        else:
            conditions["entailed_by_goal"] = True

        divergence = PlanDivergenceSignal()
        mismatch, _ = divergence._argument_provenance(ctx, goal)
        conditions["arguments_trace_to_trusted"] = mismatch == 0.0

        destination = outbound_destination(action)
        if destination is None:
            conditions["destination_internal"] = not is_outbound(action)
        else:
            inside = destination_is_internal(destination[1], ctx)
            named = bool(identifier_tokens(destination[1]) & goal.identifiers)
            conditions["destination_internal"] = bool(inside) or named

        conditions["authority_satisfied"] = ctx.authority.satisfied

        met = [key for key, value in conditions.items() if value]
        # Full alignment is required before damping at all: four of five is not
        # a benign task, it is a task with one unexplained property.
        if len(met) < len(conditions):
            return self._empty({"conditions": conditions, "damp": 1.0})

        damp = self.DAMP_FLOOR
        codes: list[str] = ["USER_GOAL_ALIGNED"]
        detail: dict[str, Any] = {"conditions": conditions, "damp": damp}

        view = text_view(ctx)
        haystack = content_words(" ".join((*view.untrusted, *view.sensitive, action.text_payload())))
        alarming = sorted(haystack & ALARMING_VOCABULARY)[:6]
        if alarming:
            codes.insert(0, "BENIGN_SENSITIVE_CONTEXT")
            detail["alarming_vocabulary"] = alarming
            detail["discusses_not_enacts"] = True

        return SignalResult(name=self.name, score=0.0, reason_codes=tuple(codes), detail=detail)


__all__ = [
    "ACTION_VERBS",
    "ALARMING_VOCABULARY",
    "BenignContextSignal",
    "GoalModel",
    "PlanDivergenceSignal",
    "forbidden_hit",
    "parse_goal",
    "tool_coverage",
]
