"""Action rewriting — keep the task moving at a lower authority.

Blocking is the cheap answer and it costs utility every time it is wrong. When an
action asks for more authority than its provenance allows, there is often a
neighbouring action that achieves the legitimate part of the intent and is
reversible: send becomes draft, execute becomes prepare, publish becomes stage.
AEGIS prefers that substitution, so a poisoned turn degrades into a safe artifact
a human can inspect rather than into a dead end.

A rewrite is only offered when it will actually work:

* the substitute tool is in ``policy_context["allowed_tools"]``;
* it is a genuine downgrade — the same object, an earlier lifecycle verb;
* the original arguments plausibly fit it. The gate here is the
  **stage-artifact rule**: if the action is keyed by an id the *later* stage
  produced (``payment_id`` for ``payment_*``, ``remediation_id`` for
  ``remediation_*``), the earlier tool takes entirely different arguments and the
  rewrite would fail at the gateway. Those cases escalate instead.
* a non-final action never becomes final, and the action type never changes.

The same idea applies to memory. "Read the newsletter and remember anything we
need" is a real task, and refusing it because the newsletter contains an injected
instruction fails the task to prevent nothing: memory inherits the trust of what
it was written from, so a recalled newsletter is evidence with no authority
either way. What AEGIS does instead is write the substance and drop the order —
:func:`sanitize_memory_content` strips tool-call-shaped fragments and JSON
argument blobs out of the stored text. The newsletter gets remembered; the
instruction hidden inside it does not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aegis.signals.base import normalize, tool_morphemes
from aegis.types import CandidateAction, SignalContext

#: Lifecycle downgrades over the terminal verb of a tool name. Generic: these are
#: English lifecycle verbs, not tool names.
DOWNGRADES: dict[str, tuple[str, ...]] = {
    "send": ("draft", "prepare", "compose"),
    "execute": ("prepare", "stage", "draft"),
    "publish": ("draft", "prepare"),
    "post": ("draft", "prepare"),
    "commit": ("prepare", "stage"),
    "apply": ("prepare", "stage"),
    "confirm": ("prepare",),
    "delete": ("archive",),
    "close": ("update",),
}

_ID_KEY = re.compile(r"^(?:(?P<stem>[a-z][a-z0-9]*)_)?id$")

#: Imperative fragments removed from text on its way into durable memory. Each is
#: a *shape* — a call with arguments, a JSON argument blob, an explicit order to
#: the assistant — not a phrase from any particular payload.
_INSTRUCTION_FRAGMENTS = (
    re.compile(
        r"\b(?:then\s+)?(?:call|invoke|execute|run|use|trigger)\s+[a-z][a-z0-9_]{2,47}"
        r"(?:\s+with\s*\{[^{}]{0,400}\})?",
        re.IGNORECASE,
    ),
    re.compile(r"\{[^{}]{0,400}?\"[a-z_][a-z0-9_]{0,63}\"\s*:[^{}]{0,400}\}", re.IGNORECASE),
    re.compile(
        r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|earlier)\s+"
        r"[a-z ]{0,32}(?:instructions?|warnings?|rules?|messages?)",
        re.IGNORECASE,
    ),
    re.compile(r"\{\{[^{}]{0,200}\}\}"),
)

@dataclass(frozen=True)
class RewriteProposal:
    action: CandidateAction
    from_tool: str
    to_tool: str
    reason: str


def _keyed_by_stage_artifact(action: CandidateAction) -> bool:
    """True when the action is addressed by an id a later lifecycle stage minted.

    ``payment_execute{payment_id: PAY-0001}`` is keyed by the artifact that
    ``payment_prepare`` produces, so rewriting it to ``payment_prepare`` would
    hand that tool arguments it does not accept.
    """
    morphemes = set(tool_morphemes(action.tool))
    for key in action.arguments:
        match = _ID_KEY.match(key.lower())
        if match is None:
            continue
        stem = match.group("stem")
        if stem is None or stem in morphemes:
            return True
    return False


def _candidate_tools(action: CandidateAction, ctx: SignalContext) -> list[str]:
    """Lower-authority tools with the same object, in preference order."""
    morphemes = tool_morphemes(action.tool)
    if not morphemes:
        return []
    allowed = ctx.allowed_tools
    verb = morphemes[-1]
    head = morphemes[:-1]
    options: list[str] = []
    for replacement in DOWNGRADES.get(verb, ()):
        name = "_".join((*head, replacement))
        if name in allowed and name != action.tool:
            options.append(name)
    return options


def propose_rewrite(ctx: SignalContext) -> RewriteProposal | None:
    """The safer substitute for this action, or ``None`` if there is not one."""
    action = ctx.action
    if action.type != "tool_call" or not action.tool:
        return None
    allowed = ctx.allowed_tools

    preferred: list[str] = []
    suggestion = ctx.authority.safer_alternative
    if suggestion and suggestion in allowed and suggestion != action.tool:
        preferred.append(suggestion)
    preferred.extend(t for t in _candidate_tools(action, ctx) if t not in preferred)
    if not preferred:
        return None

    if _keyed_by_stage_artifact(action):
        # Arguments would not survive the substitution; a human decides instead.
        return None

    target = preferred[0]
    rewritten = CandidateAction(
        type="tool_call",
        tool=target,
        arguments=dict(action.arguments),
        final=False,
    )
    if not is_valid_rewrite(action, rewritten, ctx):
        return None
    return RewriteProposal(
        action=rewritten,
        from_tool=action.tool,
        to_tool=target,
        reason=f"{action.tool} downgraded to the reversible {target}",
    )


#: Below this, a sanitized memory is too gutted to be worth writing.
MIN_SANITIZED_CHARS = 24


def sanitize_memory_content(content: str) -> str | None:
    """Strip instruction-shaped fragments, keep the substance.

    Returns ``None`` when nothing was removed, or when so little survives that the
    write would no longer carry the information the user asked to retain.
    """
    cleaned = content
    for pattern in _INSTRUCTION_FRAGMENTS:
        cleaned = pattern.sub(" ", cleaned)
    cleaned = re.sub(r"\s{2,}", " ", cleaned)
    cleaned = re.sub(r"(?:\s*[.;,]){2,}", ".", cleaned).strip(" .;,-")
    # Tidying punctuation is not a change worth rewriting for: compare on the
    # form that ignores spacing and punctuation entirely.
    if not cleaned or normalize(cleaned) == normalize(content):
        return None
    if len(cleaned) < MIN_SANITIZED_CHARS or len(cleaned) < len(content) * 0.25:
        return None
    return cleaned


def propose_memory_rewrite(ctx: SignalContext) -> RewriteProposal | None:
    """A memory write with the orders taken out of it."""
    action = ctx.action
    if action.type != "memory_write" or not action.content:
        return None
    cleaned = sanitize_memory_content(action.content)
    if cleaned is None:
        return None
    rewritten = CandidateAction(type="memory_write", content=cleaned, final=False)
    if not is_valid_rewrite(action, rewritten, ctx):
        return None
    return RewriteProposal(
        action=rewritten,
        from_tool="memory_write",
        to_tool="memory_write",
        reason="instruction-shaped fragments removed before the text is stored",
    )


def is_valid_rewrite(
    original: CandidateAction, rewritten: CandidateAction, ctx: SignalContext
) -> bool:
    """Invariants a substitute must satisfy before it is offered."""
    if rewritten.final and not original.final:
        return False
    if rewritten.type != original.type:
        return False
    if rewritten.type == "tool_call":
        allowed = ctx.allowed_tools
        if not rewritten.tool:
            return False
        if allowed and rewritten.tool not in allowed:
            return False
        if rewritten.tool == original.tool:
            return False
        # Arguments are preserved, never invented.
        if set(rewritten.arguments) - set(original.arguments):
            return False
    return True


__all__ = [
    "DOWNGRADES",
    "MIN_SANITIZED_CHARS",
    "RewriteProposal",
    "is_valid_rewrite",
    "propose_memory_rewrite",
    "propose_rewrite",
    "sanitize_memory_content",
]
