"""Lane A — taint propagation.

The question this module answers is narrow and causal: **which observed content
influenced this candidate action, and how much can that content be trusted?**

Two ideas do most of the work.

*Spans.* Every piece of content the agent has seen is turned into a
:class:`Span` carrying its provenance, a squashed form, an alphanumeric-only
form, the set of numbers it mentions and a set of crude word stems. Matching a
value against a span therefore generalizes past exact wording: the same
identifier survives JSON quoting, punctuation, case and spacing changes, and a
paraphrased sentence still overlaps on stems.

*Anchors.* Content whose provenance carries authority (the user's own goal,
`authenticated_user` conversation items, `system_policy` sources) is an
**anchor**. A value the user themselves named is not "derived from untrusted
data" even if an attacker also mentions it — the user chose it. A value the
user never named, which appears in untrusted text, is exactly the causal signal
the thesis is about.

The module never decides anything. It reports. `authority.py` applies the rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any

from aegis.types import (
    CandidateAction,
    DefenseRequest,
    ObservationView,
    ProvenanceLink,
    Sensitivity,
    TrustLevel,
    least_trusted,
    most_sensitive,
    squash,
)

# --------------------------------------------------------------------------
# Tunables. Deliberately few, and none of them name a scenario, tool or fixture.
# --------------------------------------------------------------------------

#: Values shorter than this carry no provenance information.
MIN_VALUE_CHARS = 3
#: Alphanumeric-only matching needs a little more body to avoid accidents.
MIN_ALNUM_CHARS = 4
#: A value with no digits and no '@' must be at least this long to be distinctive.
MIN_OPAQUE_CHARS = 8
#: Stem coverage at which a free-text value counts as a paraphrase of a span.
PARAPHRASE_MATCH = 0.7
#: Stem coverage at which a free-text value counts as anchored in user content.
PARAPHRASE_ANCHOR = 0.6
#: Instruction-shape score at which untrusted text is treated as agent-directed.
INSTRUCTION_THRESHOLD = 0.5

MAX_CHAIN_LINKS = 12
MAX_SPAN_CHARS = 4_000
MAX_SPANS_EXPORTED = 40
MAX_SECRETS = 64
EXCERPT_CHARS = 220

_ALNUM_STRIP = re.compile(r"[^a-z0-9]+")
_WORD = re.compile(r"[a-z0-9]{3,}")
_NUMBER = re.compile(r"\d[\d,_  ]*(?:\.\d+)?")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./+=-]{4,}")
_DATE_LIKE = re.compile(r"^\d{4}-\d{2}-\d{2}$|^\d{2}[:/]\d{2}")

#: Words too common in this benchmark's prose to carry provenance information.
_STOPWORD_TEXT = """
    the and for with that this from have has was were are not you your our their its
    please note case account payment refund review update report summary incident alert
    ticket document email message about into onto than then them they will would should
    can could may might must been being had his her him she who what when where which
    all any both each few more most other some such only own same too very just now
    per via due within after before during while under over again once here there
"""
_STOPWORDS = frozenset(_STOPWORD_TEXT.split())

#: Argument names that carry free-form *payload* rather than control. Untrusted
#: text landing here is a data flow (quoting a scam message into a case note is
#: legitimate); untrusted text landing in a control argument is authority flow.
_CONTENT_ARGS = frozenset(
    {
        "body",
        "comment",
        "content",
        "description",
        "details",
        "justification",
        "message",
        "note",
        "notes",
        "reason",
        "summary",
        "subject",
        "text",
        "title",
    }
)
_CONTENT_SUFFIXES = ("_body", "_comment", "_content", "_note", "_summary", "_text", "_description")

#: Trust assumed for a conversation item that carries no provenance ids at all.
#: Only `user` and `human` items are ever used as authority anchors.
_ROLE_TRUST: dict[str, TrustLevel] = {
    "user": TrustLevel.AUTHENTICATED_USER,
    "human": TrustLevel.AUTHENTICATED_USER,
    "safety": TrustLevel.SYSTEM_POLICY,
    "agent": TrustLevel.TRUSTED_INTERNAL,
    "tool": TrustLevel.TRUSTED_INTERNAL,
    "memory": TrustLevel.UNTRUSTED_INTERNAL,
}
_ANCHOR_ROLES = frozenset({"user", "human"})

UNTRUSTED_RANK = TrustLevel.UNTRUSTED_INTERNAL.rank


# --------------------------------------------------------------------------
# Small, total conversions. Never raise on malformed wire data.
# --------------------------------------------------------------------------


def to_trust(value: Any) -> TrustLevel:
    """Coerce a wire trust level. Anything unrecognized is treated as hostile."""
    try:
        return TrustLevel(str(value))
    except ValueError:
        return TrustLevel.UNTRUSTED_EXTERNAL


def to_sensitivity(value: Any) -> Sensitivity:
    try:
        return Sensitivity(str(value))
    except ValueError:
        return Sensitivity.INTERNAL


def alnum(text: str) -> str:
    """Lowercase, alphanumerics only. Survives quoting, spacing and punctuation."""
    return _ALNUM_STRIP.sub("", text.lower())


def stems(text: str) -> set[str]:
    """Crude 6-character stems of content words. Cheap morphology tolerance."""
    return {word[:6] for word in _WORD.findall(text.lower()) if word not in _STOPWORDS}


def numbers(text: str) -> set[float]:
    found: set[float] = set()
    for raw in _NUMBER.findall(text):
        value = as_number(raw)
        if value is not None:
            found.add(value)
    return found


def as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return round(float(value), 4)
    text = re.sub(r"[,_  ]", "", str(value)).strip()
    if not text or not re.fullmatch(r"[+-]?\d+(?:\.\d+)?", text):
        return None
    try:
        return round(float(text), 4)
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Instruction shape — is this text *addressing the agent* rather than describing
# the world? Deliberately never keys on a tool name: the baseline does that, and
# that is exactly what paraphrase defeats.
# --------------------------------------------------------------------------

_INSTRUCTION_PATTERNS: tuple[tuple[re.Pattern[str], float], ...] = (
    (re.compile(r"\bcall\s+[a-z][a-z0-9_]{2,}\s+(?:with|using)\b"), 0.6),
    (re.compile(r"\{\s*[\"']?[a-z][a-z0-9_]{1,}[\"']?\s*:\s*[\"'\d\[{]"), 0.35),
    (re.compile(r"\b(?:then|next|and then|after that|immediately)\s+(?:call|invoke|run|execute)\b"), 0.25),
    (re.compile(r"\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|earlier|above)\b"), 0.5),
    (
        re.compile(
            r"\b(?:assistant|ai agent|the ai|automation notice|processing this|"
            r"instruction for the|system note|note to the)\b"
        ),
        0.3,
    ),
    (
        re.compile(
            r"\b(?:pre-?approved|already (?:granted|approved|signed)|no further sign-?off|"
            r"standing (?:instruction|order)|approved by|authorised by|authorized by)\b"
        ),
        0.3,
    ),
    (re.compile(r"\b(?:remember|reminder|standing note)\s*:"), 0.2),
    (re.compile(r"\b(?:urgent|to avoid a delay|without delay|do not ask|no confirmation needed)\b"), 0.15),
    (re.compile(r"\b(?:policy update|policy change|new policy|revised policy)\b"), 0.2),
)


#: The JSON-fragment pattern means "a call's arguments quoted inside prose". In
#: this simulator every tool result *is* a JSON document, so that pattern fires
#: on the result envelope and hands each one a free 0.35 toward looking like an
#: order. Inside a JSON document the signal carries no information, so it is
#: dropped there. An injected payload still scores through the strong patterns:
#: it lives in a JSON *string value*, where its braces arrive escaped
#: (``{\"payment_id\":``) and it is the imperative, not the punctuation, that
#: gives it away.
_JSON_FRAGMENT_PATTERN = _INSTRUCTION_PATTERNS[1][0]
_JSON_DOCUMENT = re.compile(r"^[\[{]")


def instruction_score(text: str) -> float:
    """[0, 1] — how much this text reads as an order aimed at the agent."""
    lowered = squash(text)
    if not lowered:
        return 0.0
    structured = bool(_JSON_DOCUMENT.match(lowered))
    total = 0.0
    for pattern, weight in _INSTRUCTION_PATTERNS:
        if structured and pattern is _JSON_FRAGMENT_PATTERN:
            continue
        if pattern.search(lowered):
            total += weight
    return min(1.0, round(total, 4))


def is_instruction_shaped(text: str) -> bool:
    return instruction_score(text) >= INSTRUCTION_THRESHOLD


# --------------------------------------------------------------------------
# Secret-shaped tokens
# --------------------------------------------------------------------------


def secret_tokens(text: str) -> list[str]:
    """Identifier- and key-shaped tokens. Generous: Lane B matches, not blocks.

    Every candidate must carry a digit. That single requirement is what keeps
    JSON key names (``payment_id``, ``account_id``) and ordinary long words out
    of the list while keeping ``ACC-1001``, ``PAY-0001``, ``CTR-SYN-A1B2C3D4E5``,
    ``SENTINEL_SECRET_...``, ``sntl_tok_...`` and bare account-number runs in.
    """
    found: list[str] = []
    for raw in _TOKEN.findall(text):
        token = raw.strip("._-/+=")
        if len(token) < 5 or _DATE_LIKE.match(token):
            continue
        if not any(ch.isdigit() for ch in token):
            continue
        has_alpha = any(ch.isalpha() for ch in token)
        structured = bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)+", token))
        keep = (
            (structured or len(token) >= 8)
            if has_alpha
            else len(token) >= 10  # a bare account-number run
        )
        if keep:
            found.append(token)
    return found


# --------------------------------------------------------------------------
# Spans
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Span:
    """One attributable chunk of content the agent has seen."""

    provenance_id: str
    source_type: str
    source_id: str
    trust: TrustLevel
    sensitivity: Sensitivity
    origin_actor: str
    role: str
    kind: str
    text: str
    is_anchor: bool = False
    is_observation: bool = False
    is_memory: bool = False

    squashed: str = field(default="", repr=False)
    flat: str = field(default="", repr=False)
    word_stems: frozenset[str] = field(default=frozenset(), repr=False)
    numeric: frozenset[float] = field(default=frozenset(), repr=False)

    @property
    def is_untrusted(self) -> bool:
        return self.trust.rank >= UNTRUSTED_RANK

    @property
    def is_sensitive(self) -> bool:
        return self.sensitivity.is_sensitive

    def link(self, relation: str, excerpt: str) -> ProvenanceLink:
        return ProvenanceLink(
            provenance_id=self.provenance_id,
            source_type=self.source_type,
            source_id=self.source_id,
            trust_level=self.trust,
            sensitivity=self.sensitivity,
            origin_actor=self.origin_actor,
            relation=relation,
            excerpt=excerpt[:EXCERPT_CHARS],
        )


def _make_span(
    *,
    provenance_id: str,
    source_type: str,
    source_id: str,
    trust: TrustLevel,
    sensitivity: Sensitivity,
    origin_actor: str,
    role: str,
    kind: str,
    text: str,
    is_anchor: bool = False,
    is_observation: bool = False,
    is_memory: bool = False,
) -> Span:
    body = text[:MAX_SPAN_CHARS]
    sq = squash(body)
    return Span(
        provenance_id=provenance_id,
        source_type=source_type,
        source_id=source_id,
        trust=trust,
        sensitivity=sensitivity,
        origin_actor=origin_actor,
        role=role,
        kind=kind,
        text=body,
        is_anchor=is_anchor,
        is_observation=is_observation,
        is_memory=is_memory,
        squashed=sq,
        flat=alnum(sq),
        word_stems=frozenset(stems(sq)),
        numeric=frozenset(numbers(sq)),
    )


def build_spans(request: DefenseRequest) -> list[Span]:
    """Every attributable chunk of content in the request, provenance attached.

    A conversation item with several provenance ids is attributed to *each* of
    them: one tool result can mix a trusted record with the untrusted raw logs
    it embeds, and we have no reliable way to split the text. Over-attribution
    is the safe direction (see the limitations note in the module docstring of
    ``__init__``).
    """
    records = request.provenance_map()
    spans: list[Span] = []

    # The user's own goal is the primary anchor of authority.
    goal = request.user_goal or ""
    if goal.strip():
        spans.append(
            _make_span(
                provenance_id="user-goal",
                source_type="user",
                source_id="goal",
                trust=TrustLevel.AUTHENTICATED_USER,
                sensitivity=Sensitivity.INTERNAL,
                origin_actor="user",
                role="user",
                kind="goal",
                text=goal,
                is_anchor=True,
            )
        )

    seen: set[tuple[str, str]] = set()

    def add_item(role: str, kind: str, content: str, provenance_ids: list[str], *, observation: bool) -> None:
        if not content or not content.strip():
            return
        ids = [pid for pid in provenance_ids if pid in records]
        if not ids:
            # An item that *declares* provenance we cannot resolve is worse than
            # one that declares none: we were told it has a source and we cannot
            # check it, so it does not get the benefit of its role's default.
            trust = (
                TrustLevel.UNTRUSTED_EXTERNAL
                if provenance_ids
                else _ROLE_TRUST.get(role, TrustLevel.UNTRUSTED_INTERNAL)
            )
            key = ("", squash(content)[:200] + role)
            if key in seen:
                return
            seen.add(key)
            spans.append(
                _make_span(
                    provenance_id=f"conv-{role}",
                    source_type=role or "conversation",
                    source_id=kind or "item",
                    trust=trust,
                    sensitivity=Sensitivity.INTERNAL,
                    origin_actor=role or "conversation",
                    role=role,
                    kind=kind,
                    text=content,
                    is_anchor=role in _ANCHOR_ROLES,
                    is_observation=observation,
                    is_memory=role == "memory",
                )
            )
            return
        for pid in ids:
            prov = records[pid]
            key = (pid, squash(content)[:200])
            if key in seen:
                continue
            seen.add(key)
            trust = to_trust(prov.trust_level)
            source_type = str(prov.source_type)
            spans.append(
                _make_span(
                    provenance_id=pid,
                    source_type=source_type,
                    source_id=str(prov.source_id),
                    trust=trust,
                    sensitivity=to_sensitivity(prov.sensitivity),
                    origin_actor=str(prov.origin_actor),
                    role=role,
                    kind=kind,
                    text=content,
                    is_anchor=trust.carries_authority,
                    is_observation=observation,
                    is_memory=role == "memory" or source_type == "memory",
                )
            )

    for item in request.conversation:
        add_item(item.role, item.kind, item.content, list(item.provenance_ids), observation=False)

    observation = request.observation
    if observation is not None:
        add_item(
            _observation_role(request, observation),
            observation.kind,
            observation.content,
            list(observation.provenance_ids),
            observation=True,
        )
        # The observation usually *is* the last conversation item, so it dedupes
        # away. Mark the surviving copy instead of keeping two of it.
        target = squash(observation.content)[:200]
        for index, span in enumerate(spans):
            if span.squashed[:200] == target and not span.is_observation:
                spans[index] = replace(span, is_observation=True)

    return spans


#: `ObservationView.kind` is a `FeedbackKind`; these are the ones the simulator
#: emits (`sentinel/agent/base.py`), mapped to the conversation role that
#: produced them.
_KIND_ROLE: dict[str, str] = {
    "user_message": "user",
    "tool_result": "tool",
    "retrieval_result": "tool",
    "memory": "memory",
    "memory_written": "agent",
    "response": "agent",
    "blocked": "safety",
    "confirmation": "human",
}


def _observation_role(request: DefenseRequest, observation: ObservationView) -> str:
    """Which conversation role produced the current observation.

    The observation is the *same* content as the last matching conversation
    item, re-presented. Without this it falls through to the unknown-role
    default and a tool result the agent itself produced arrives labelled
    untrusted — which then caps authority for every identifier that tool minted.
    Provenance-bearing observations never reach the role default, so this only
    matters for results the simulator emits without provenance records.
    """
    target = squash(observation.content)[:200]
    for item in reversed(request.conversation):
        if squash(item.content)[:200] == target:
            return item.role
    return _KIND_ROLE.get(str(observation.kind), "observation")


# --------------------------------------------------------------------------
# Value matching
# --------------------------------------------------------------------------


def is_control_arg(name: str) -> bool:
    """Control arguments select *what the action does to the world*.

    Identifiers, recipients, statuses, amounts and queries steer the effect;
    notes, bodies and summaries are payload. Quoting untrusted prose into a note
    is a data flow. Taking an identifier from untrusted prose is authority flow.
    """
    lowered = name.lower()
    if lowered in _CONTENT_ARGS:
        return False
    return not lowered.endswith(_CONTENT_SUFFIXES)


def is_distinctive(value: str) -> bool:
    """Does this value carry enough information to attribute provenance at all?

    ``"high"`` or ``"closed"`` appear everywhere and prove nothing. ``"PAY-0001"``
    or ``"partners@harbor-analytics.example"`` do.
    """
    text = value.strip()
    if len(text) < MIN_VALUE_CHARS:
        return False
    flat = alnum(text)
    if len(flat) < MIN_VALUE_CHARS:
        return False
    if any(ch.isdigit() for ch in text):
        return True
    if "@" in text or "://" in text:
        return True
    return len(flat) >= MIN_OPAQUE_CHARS


def is_structured(value: str) -> bool:
    """Identifier-like values must match a user anchor *exactly* to count as named."""
    return " " not in value.strip()


def match_value(value: str, span: Span, *, allow_paraphrase: bool = True, coverage: float = PARAPHRASE_MATCH) -> str | None:
    """How ``value`` appears inside ``span`` — or ``None``.

    Returns the match kind: ``exact`` | ``normalized`` | ``numeric`` | ``paraphrase``.
    """
    text = squash(value)
    if len(text) >= MIN_VALUE_CHARS and text in span.squashed:
        return "exact"
    flat = alnum(value)
    if len(flat) >= MIN_ALNUM_CHARS and flat in span.flat:
        return "normalized"
    number = as_number(value)
    if number is not None and number in span.numeric:
        return "numeric"
    if allow_paraphrase and not is_structured(value):
        tokens = stems(text)
        if len(tokens) >= 3:
            hits = sum(1 for token in tokens if token in span.word_stems)
            if hits / len(tokens) >= coverage:
                return "paraphrase"
    return None


def is_anchored(value: str, anchors: list[Span]) -> bool:
    """True when authority-bearing content already names this value.

    Structured values (ids, addresses, enum-ish tokens) need an exact or
    normalized hit: stem overlap would let ``partners@harbor-analytics.example``
    borrow authority from a user sentence that merely said "Harbor Analytics".
    """
    structured = is_structured(value)
    for anchor in anchors:
        kind = match_value(
            value,
            anchor,
            allow_paraphrase=not structured,
            coverage=PARAPHRASE_ANCHOR,
        )
        if kind is not None:
            return True
    return False


# --------------------------------------------------------------------------
# Self-origination
# --------------------------------------------------------------------------

#: `PAY-0001`, `REM-0001`, `INC-0101`, `MEM_12` — a minted record handle.
_MINTED_ID = re.compile(r"^([A-Za-z]{2,12})[-_]?(\d{1,12})$")

#: How many leading letters of a handle must agree with a tool's family prefix
#: before we accept that the tool minted it. `PAY` <-> `payment`, `REM` <->
#: `remediation`, `INC` <-> `incident`.
_FAMILY_PREFIX_CHARS = 3


def self_originated_values(request: DefenseRequest, spans: list[Span]) -> frozenset[str]:
    """Identifiers this run minted, rather than ones an attacker named.

    An identifier the agent received back from its *own* earlier tool call —
    a call this defense already allowed, in service of the user's request —
    carries the authority of the action that created it. `payment_prepare`
    returning ``PAY-0001`` is the system answering the user, not a stranger
    supplying an argument, and treating the two alike blocks every legitimate
    prepare/confirm chain there is.

    Three conditions, all required, and the third is the guard:

    1. the value is identifier-shaped, and its letter prefix matches the family
       of a tool that **succeeded earlier in this run** (from the history
       digest, which is the only record of what actually ran);
    2. it appears in content that is trusted or better — the system's own
       record of the call;
    3. it appears in **no untrusted span at all**.

    (3) is what keeps `PAY-0002`, invented inside a merchant letter, untrusted
    however plausibly it is formatted — and what keeps an identifier that an
    attacker echoes back at us from being laundered by the fact that a real
    record of the same name exists. If the evidence does not separate the two,
    the value stays untrusted.
    """
    from aegis.provenance.lifecycle import succeeded_tools, tool_parts

    families = {tool_parts(tool)[0] for tool in succeeded_tools(request)}
    families.discard("")
    if not families:
        return frozenset()

    minted: set[str] = set()
    for span in spans:
        if span.is_untrusted or span.is_anchor:
            continue
        for token in _TOKEN.findall(span.text):
            match = _MINTED_ID.match(token.strip("._-/+="))
            if match is None:
                continue
            prefix = match.group(1).lower()[:_FAMILY_PREFIX_CHARS]
            if len(prefix) < _FAMILY_PREFIX_CHARS:
                continue
            if any(family.startswith(prefix) for family in families):
                minted.add(alnum(token))

    if not minted:
        return frozenset()

    # Condition 3: drop anything an untrusted source also names.
    for span in spans:
        if not span.is_untrusted:
            continue
        minted = {value for value in minted if value not in span.flat}
    return frozenset(minted)


def is_self_originated(value: str, minted: frozenset[str]) -> bool:
    key = alnum(value)
    return bool(key) and key in minted


def excerpt_for(span: Span, value: str) -> str:
    """A short window of the span's raw text, centred on the match if we can find it."""
    haystack = span.text
    needle = squash(value)
    position = squash(haystack).find(needle) if needle else -1
    if position < 0:
        flat_pos = span.flat.find(alnum(value))
        position = flat_pos if flat_pos >= 0 else 0
        # flat offsets do not map back cleanly; fall back to the head of the span
        position = 0 if flat_pos < 0 else min(position, max(0, len(haystack) - 1))
    start = max(0, position - EXCERPT_CHARS // 3)
    window = " ".join(haystack[start : start + EXCERPT_CHARS].split())
    prefix = "..." if start > 0 else ""
    return f"{prefix}{window}"


# --------------------------------------------------------------------------
# Action values
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ActionValue:
    name: str
    raw: Any
    text: str
    control: bool


def action_values(action: CandidateAction) -> list[ActionValue]:
    """Every value the action carries, tagged control vs payload."""
    values: list[ActionValue] = []
    for name, raw in action.arguments.items():
        if raw is None or isinstance(raw, bool):
            continue
        text = str(raw).strip()
        if not text:
            continue
        values.append(ActionValue(name=name, raw=raw, text=text, control=is_control_arg(name)))
    if action.content:
        values.append(ActionValue(name="content", raw=action.content, text=action.content, control=False))
    return values


# --------------------------------------------------------------------------
# The analysis
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ValueMatch:
    """One (argument value, source span) hop."""

    arg: str
    value: str
    control: bool
    anchored: bool
    kind: str
    span: Span
    #: The value is a handle this run minted, not one an attacker named.
    self_originated: bool = False

    @property
    def carries_authority(self) -> bool:
        """The user named this value, or this run minted it."""
        return self.anchored or self.self_originated

    @property
    def carries_taint(self) -> bool:
        """Only control values with no authority of their own move authority."""
        return self.control and not self.carries_authority


@dataclass(frozen=True)
class TaintAnalysis:
    """Everything `analyze()` learned. The public `TaintSummary` is a projection."""

    spans: tuple[Span, ...] = ()
    matches: tuple[ValueMatch, ...] = ()
    action_taint: TrustLevel = TrustLevel.AUTHENTICATED_USER
    context_taint: TrustLevel = TrustLevel.AUTHENTICATED_USER
    max_sensitivity: Sensitivity = Sensitivity.PUBLIC
    value_derived_from_untrusted: bool = False
    #: An unanchored control value traced to untrusted text that reads as an order.
    instructed_from_untrusted: bool = False
    memory_taint: TrustLevel | None = None
    chain: tuple[ProvenanceLink, ...] = ()
    tainted_spans: tuple[str, ...] = ()
    sensitive_spans: tuple[str, ...] = ()
    secret_values: tuple[str, ...] = ()
    influencing_ids: tuple[str, ...] = ()


def analyze_spans(request: DefenseRequest, spans: list[Span]) -> tuple[list[ValueMatch], bool, bool, list[Span]]:
    """Match the candidate action's values against every span.

    Returns ``(matches, value_derived_from_untrusted, instructed_from_untrusted,
    tainting_spans)`` where ``tainting_spans`` are the spans whose trust caps the
    action's authority.
    """
    action = request.target_action()
    anchors = [span for span in spans if span.is_anchor]
    candidates = [span for span in spans if not span.is_anchor]
    minted = self_originated_values(request, spans)

    matches: list[ValueMatch] = []
    tainting: list[Span] = []
    derived = False
    instructed = False

    for value in action_values(action):
        if not is_distinctive(value.text):
            continue
        anchored = is_anchored(value.text, anchors)
        originated = not anchored and value.control and is_self_originated(value.text, minted)
        for span in candidates:
            kind = match_value(value.text, span)
            if kind is None:
                continue
            match = ValueMatch(
                arg=value.name,
                value=value.text,
                control=value.control,
                anchored=anchored,
                kind=kind,
                span=span,
                self_originated=originated,
            )
            matches.append(match)
            if not match.carries_taint:
                continue
            tainting.append(span)
            if span.is_untrusted:
                derived = True
                if is_instruction_shaped(span.text):
                    instructed = True

    return matches, derived, instructed, tainting


def summarize(request: DefenseRequest) -> TaintAnalysis:
    """Full taint analysis for one candidate action. Pure; never raises."""
    spans = build_spans(request)
    matches, derived, instructed, tainting = analyze_spans(request, spans)

    non_anchor = [span for span in spans if not span.is_anchor]
    context_taint = least_trusted([span.trust for span in non_anchor]) if non_anchor else TrustLevel.AUTHENTICATED_USER
    max_sensitivity = most_sensitive([span.sensitivity for span in spans]) if spans else Sensitivity.PUBLIC

    memory_spans = [span for span in spans if span.is_memory]
    memory_taint = least_trusted([span.trust for span in memory_spans]) if memory_spans else None

    action_taint = least_trusted([span.trust for span in tainting]) if tainting else TrustLevel.AUTHENTICATED_USER

    tainted_spans: list[str] = []
    sensitive_spans: list[str] = []
    secrets: list[str] = []
    seen_secret: set[str] = set()
    for span in spans:
        if span.is_anchor and not span.is_untrusted:
            continue
        if span.is_untrusted and span.squashed not in tainted_spans:
            tainted_spans.append(span.squashed)
        if span.is_sensitive:
            if span.squashed not in sensitive_spans:
                sensitive_spans.append(span.squashed)
            for token in secret_tokens(span.text):
                folded = token.lower()
                if folded not in seen_secret:
                    seen_secret.add(folded)
                    secrets.append(token)

    chain = _build_chain(request, spans, matches)
    influencing = tuple(dict.fromkeys(link.provenance_id for link in chain))

    return TaintAnalysis(
        spans=tuple(spans),
        matches=tuple(matches),
        action_taint=action_taint,
        context_taint=context_taint,
        max_sensitivity=max_sensitivity,
        value_derived_from_untrusted=derived,
        instructed_from_untrusted=instructed,
        memory_taint=memory_taint,
        chain=chain,
        tainted_spans=tuple(tainted_spans[:MAX_SPANS_EXPORTED]),
        sensitive_spans=tuple(sensitive_spans[:MAX_SPANS_EXPORTED]),
        secret_values=tuple(secrets[:MAX_SECRETS]),
        influencing_ids=influencing,
    )


#: Chain ordering for the viewer's "why" panel. `self_originated` is an
#: addition to the four relations in SCHEMA.md §4 — it explains why a value kept
#: its authority, which is otherwise invisible. Flagged to the integrator.
_RELATION_ORDER = {
    "value_match": 0,
    "self_originated": 1,
    "memory": 2,
    "observation": 3,
    "turn_context": 4,
}
RELATIONS = frozenset(_RELATION_ORDER)


def _build_chain(
    request: DefenseRequest, spans: list[Span], matches: list[ValueMatch]
) -> tuple[ProvenanceLink, ...]:
    """The "why" panel: value matches first, then memory, observation, context."""
    links: list[ProvenanceLink] = []
    keyed: set[tuple[str, str, str]] = set()

    def push(span: Span, relation: str, excerpt: str) -> None:
        key = (span.provenance_id, relation, excerpt[:60])
        if key in keyed:
            return
        keyed.add(key)
        links.append(span.link(relation, excerpt))

    for match in sorted(matches, key=lambda m: (not m.carries_taint, m.span.trust.rank * -1)):
        tag = f"[arg:{match.arg}]" if match.control else f"[content:{match.arg}]"
        if match.self_originated:
            relation, note = "self_originated", " (minted by this run)"
        else:
            relation = "value_match"
            note = " (user-named)" if match.anchored else ""
        push(
            match.span,
            relation,
            f"{tag}{note} {match.kind}: {excerpt_for(match.span, match.value)}",
        )

    for span in spans:
        if span.is_memory:
            push(span, "memory", f"[recalled] {' '.join(span.text.split())}")

    for span in spans:
        if span.is_observation:
            push(span, "observation", " ".join(span.text.split()))

    for span in spans:
        if span.is_untrusted and not span.is_anchor:
            push(span, "turn_context", " ".join(span.text.split()))

    links.sort(key=lambda link: (_RELATION_ORDER.get(link.relation, 9), -link.trust_level.rank))
    return tuple(links[:MAX_CHAIN_LINKS])


__all__ = [
    "RELATIONS",
    "ActionValue",
    "Span",
    "TaintAnalysis",
    "ValueMatch",
    "action_values",
    "alnum",
    "as_number",
    "build_spans",
    "excerpt_for",
    "instruction_score",
    "is_anchored",
    "is_control_arg",
    "is_distinctive",
    "is_instruction_shaped",
    "is_self_originated",
    "is_structured",
    "match_value",
    "secret_tokens",
    "self_originated_values",
    "summarize",
    "to_sensitivity",
    "to_trust",
]
