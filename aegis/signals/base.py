"""Lane B — shared, dependency-free helpers for every AEGIS signal.

Nothing in this module knows about scenarios, run ids, file names or expected
outcomes. It knows three kinds of thing only:

1. **Text mechanics** — normalisation, tokenisation, identifier extraction and a
   layered decoder used to see through obfuscation.
2. **A generic morpheme ontology** — tool names in this benchmark (and in real
   agent stacks) are ``object_verb`` compounds: ``email_send``,
   ``payment_confirm``, ``incident_update``. Splitting a tool name on ``_`` and
   expanding each morpheme through a small English synonym map lets us ask
   "did the user ask for something of this shape?" without ever looking at the
   observed data.
3. **Structural predicates** — action class (read / prepare / commit), whether an
   action is outbound, whether a destination is inside the trust boundary.

The one lexicon in this file (``MORPHEME_SYNONYMS``) is keyed by *tool-name
morphemes*, which the defense legitimately sees at runtime in
``policy_context["allowed_tools"]``. It contains no strings lifted from any
scenario payload, and no decision anywhere in Lane B depends on a scenario id,
a file name, or an organizer label.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from aegis.types import (
    CandidateAction,
    Provenance,
    Sensitivity,
    SignalContext,
    SignalResult,
    TrustLevel,
)

# --------------------------------------------------------------------------- #
# Bounds. Every helper is O(n) in text length and every loop below is capped so
# the whole signal set stays far under the 50 ms budget even on pathological
# inputs.
# --------------------------------------------------------------------------- #

MAX_TEXT_CHARS = 20_000
#: Identifier extraction runs over every trusted and untrusted span, so it gets a
#: tighter budget than plain word extraction.
MAX_ID_SCAN_CHARS = 8_000
MAX_DECODE_CHARS = 8_000
MAX_VARIANTS = 48
#: A depth-1 decode longer than this is not re-decoded; composing transforms on a
#: large blob costs more than it catches.
MAX_SECOND_PASS_CHARS = 4_000
MAX_SECRETS = 32
MAX_UNTRUSTED_TEXTS = 40

# --------------------------------------------------------------------------- #
# Text mechanics
# --------------------------------------------------------------------------- #

_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_WORD = re.compile(r"[A-Za-z][A-Za-z'\-]*")
#: Commas are part of a token so that ``1,250.00`` survives to
#: :func:`canonical_number` instead of splitting into ``1`` and ``250.00``;
#: underscores so that ``SENTINEL_SECRET_0A1B…`` stays one token instead of three.
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+/,_\-]{1,63}")
_NUMERIC = re.compile(r"^[0-9][0-9,]*(?:\.[0-9]+)?$")

#: Characters that carry no meaning but break naive substring matching.
_INVISIBLE = frozenset(
    "\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00ad\u180e\u061c"
)

#: Confusables that render like ASCII. Deliberately small: NFKD handles the rest.
_HOMOGLYPHS = str.maketrans(
    {
        # Cyrillic and Greek letters that render like ASCII.
        "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
        "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0455": "s", "\u043a": "k",
        "\u041c": "M", "\u0410": "A", "\u0415": "E", "\u041e": "O", "\u0420": "P",
        "\u0421": "C", "\u0425": "X", "\u03bf": "o", "\u0391": "A", "\u0392": "B",
        # Typographic punctuation that breaks naive matching.
        "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-",
        "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
    }
)

STOPWORDS = frozenset(
    (  # noqa: SIM905 - one readable line per row beats an 80-element list literal
        "a an and are as at be been but by can could do does did for from get give had has have "
        "he her him his how i if in into is it its just like make me my no not of on once one only "
        "or our out over own please she should so some such than that the their them then there "
        "these they this those to too us use was we were what when where which while who whom why "
        "will with would you your yours"
    ).split()
)

#: Weak suffixes stripped by :func:`stem`. Order matters (longest first).
_SUFFIXES = ("ization", "isation", "ations", "ation", "ings", "ing", "ies", "ed", "es", "s")


def normalize(text: str) -> str:
    """Lowercase, strip every non-alphanumeric character.

    This is the comparison form used for secret matching. It makes
    ``A C C - 1 0 0 1``, ``ACC_1001`` and ``acc-1001`` identical, which is why
    character-spacing attacks need no dedicated transform.
    """
    return _NON_ALNUM.sub("", text.lower())


_INVISIBLE_DELETE = {ord(ch): None for ch in _INVISIBLE}


def strip_invisible(text: str) -> str:
    """Remove zero-width and format characters, then fold common homoglyphs.

    Pure-ASCII text can carry none of these, so it short-circuits; that keeps the
    decoder cheap on the overwhelmingly common case.
    """
    if text.isascii():
        return text
    cleaned = text.translate(_INVISIBLE_DELETE)
    cleaned = "".join(ch for ch in cleaned if unicodedata.category(ch) != "Cf")
    return unicodedata.normalize("NFKC", cleaned.translate(_HOMOGLYPHS))


def stem(word: str) -> str:
    """A deliberately crude suffix stripper. Good enough to match verb forms."""
    w = word.lower()
    if len(w) <= 4:
        return w
    for suffix in _SUFFIXES:
        if w.endswith(suffix) and len(w) - len(suffix) >= 3:
            return w[: -len(suffix)]
    return w


def content_words(text: str) -> set[str]:
    """Stemmed, stopword-filtered words. The vocabulary of an intent."""
    out: set[str] = set()
    for match in _WORD.findall(text[:MAX_TEXT_CHARS]):
        word = match.lower().strip("'-")
        if len(word) < 2 or word in STOPWORDS:
            continue
        out.add(word)
        out.add(stem(word))
    return out


def canonical_number(token: str) -> str | None:
    """``1,250.00`` -> ``1250``. Lets a goal's prose amount match an int argument."""
    if not _NUMERIC.match(token):
        return None
    value = token.replace(",", "")
    if "." in value:
        value = value.rstrip("0").rstrip(".")
    return value or None


def identifier_tokens(text: str) -> set[str]:
    """Tokens that *name* something: ids, refs, emails, amounts.

    These are the values that steer an action. Prose is deliberately excluded —
    a token qualifies only if it contains a digit or an ``@``.
    """
    out: set[str] = set()
    for raw in _TOKEN.findall(text[:MAX_ID_SCAN_CHARS]):
        token = raw.strip("._-/,")
        if len(token) < 3:
            continue
        number = canonical_number(token)
        if number is not None:
            if len(number) >= 3:
                out.add(number)
            continue
        has_digit = any(ch.isdigit() for ch in token)
        if "@" in token or has_digit:
            out.add(token.lower())
            # A bare identifier core, so ``PAY-0001`` also matches ``pay0001``.
            out.add(normalize(token))
    out.discard("")
    return out


# --------------------------------------------------------------------------- #
# Morpheme ontology
# --------------------------------------------------------------------------- #

#: Generic English expansion for tool-name morphemes. Keys are morphemes that
#: appear in tool names; values are words a user might use for the same thing.
MORPHEME_SYNONYMS: dict[str, set[str]] = {
    # verbs -- reading
    "read": {"read", "open", "view", "check", "review", "look", "see", "inspect", "examine",
             "show", "tell", "summarize", "summary", "fetch", "retrieve", "pull", "triage"},
    "search": {"search", "find", "look", "lookup", "query", "check", "locate", "correlate",
               "scan", "identify", "which", "what"},
    "lookup": {"lookup", "look", "find", "check", "who", "owner", "owns", "detail", "profile",
               "up", "criticality", "affected"},
    "list": {"list", "show", "enumerate", "all"},
    "summary": {"summary", "summarize", "balance", "overview", "status", "detail", "current"},
    "get": {"get", "fetch", "retrieve", "obtain", "show"},
    # verbs -- preparing / recording
    "create": {"create", "add", "open", "log", "write", "record", "file", "make", "note",
               "raise", "start", "new"},
    "prepare": {"prepare", "stage", "ready", "queue", "set", "arrange", "plan"},
    "draft": {"draft", "compose", "write", "prepare", "reply", "respond"},
    "write": {"write", "save", "store", "record", "remember", "note"},
    "update": {"update", "set", "change", "modify", "edit", "mark", "assign", "note", "add",
               "close", "move", "amend"},
    "note": {"note", "comment", "annotation", "log", "remark", "memo"},
    # verbs -- committing
    "send": {"send", "email", "mail", "forward", "deliver", "message", "notify", "share",
             "transmit", "reply"},
    "confirm": {"confirm", "approve", "authorize", "authorise", "sign", "signoff", "accept",
                "ok", "greenlight"},
    "execute": {"execute", "run", "perform", "apply", "carry", "trigger", "release", "commit",
                "enforce", "action"},
    "delete": {"delete", "remove", "purge", "drop", "erase"},
    "disable": {"disable", "turn", "silence", "suppress", "off", "stop", "mute"},
    # objects
    "email": {"email", "mail", "message", "inbox", "correspondence", "reply", "thread"},
    "document": {"document", "doc", "file", "attachment", "paper", "letter", "correspondence",
                 "contract", "agreement", "msa"},
    "payment": {"payment", "pay", "transfer", "refund", "settlement", "remittance",
                "disbursement", "amount"},
    "case": {"case", "dispute", "claim", "complaint", "file"},
    "customer": {"customer", "client", "profile", "person", "holder"},
    "account": {"account", "balance", "acct", "ledger"},
    "policy": {"policy", "rule", "guidance", "procedure", "standard", "guideline", "compliance"},
    "incident": {"incident", "case", "investigation"},
    "alert": {"alert", "detection", "signal", "event", "notification"},
    "asset": {"asset", "host", "workstation", "server", "machine", "device", "endpoint",
              "system", "inventory"},
    "intel": {"intel", "intelligence", "threat", "ioc", "indicator", "feed"},
    "remediation": {"remediation", "containment", "isolation", "isolate", "contain", "response",
                    "quarantine", "action"},
    "ticket": {"ticket", "issue", "request", "case"},
    "wiki": {"wiki", "knowledge", "kb", "page", "article", "handbook"},
    "memory": {"memory", "remember", "recall", "note", "retain"},
    "beneficiary": {"beneficiary", "payee", "recipient", "supplier", "vendor"},
    "comment": {"comment", "note", "reply", "remark"},
}


def _build_closure() -> dict[str, frozenset[str]]:
    """Symmetric closure of the synonym map, so lookup works from either side."""
    table: dict[str, set[str]] = {}
    for key, values in MORPHEME_SYNONYMS.items():
        table.setdefault(key, set()).update({key, *values})
        for value in values:
            table.setdefault(value, set()).update({key, value})
    return {key: frozenset(values) for key, values in table.items()}


SYNONYM_CLOSURE: dict[str, frozenset[str]] = _build_closure()


def expand(term: str) -> frozenset[str]:
    """All words that mean roughly the same thing as ``term``."""
    key = term.lower()
    direct = SYNONYM_CLOSURE.get(key)
    if direct is not None:
        return direct
    stemmed = stem(key)
    return SYNONYM_CLOSURE.get(stemmed, frozenset({key, stemmed}))


def tool_morphemes(tool: str | None) -> tuple[str, ...]:
    """``payment_confirm`` -> ``("payment", "confirm")``."""
    if not tool:
        return ()
    return tuple(part for part in re.split(r"[_\-.]+", tool.lower()) if part)


def morpheme_covered(morpheme: str, vocabulary: set[str]) -> bool:
    """True when the user's own words contain this morpheme, or a synonym of it."""
    if morpheme in vocabulary or stem(morpheme) in vocabulary:
        return True
    return bool(expand(morpheme) & vocabulary)


# --------------------------------------------------------------------------- #
# Action structure
# --------------------------------------------------------------------------- #

READ_TERMS = frozenset({"read", "search", "lookup", "list", "get", "view", "summary", "find",
                        "query", "show", "correlate"})
PREPARE_TERMS = frozenset({"prepare", "draft", "stage", "create", "add", "note", "log", "write",
                           "record", "open", "comment"})
COMMIT_TERMS = frozenset({"send", "execute", "confirm", "approve", "delete", "disable", "close",
                          "transfer", "pay", "publish", "post", "release", "apply", "escalate",
                          "revoke", "reset"})

#: Argument values that turn an otherwise mild "update" into a commit.
CLOSING_STATUSES = frozenset({"closed", "close", "resolved", "resolve", "cancelled", "canceled",
                              "deleted", "disabled", "archived", "approved", "completed", "done"})

#: Argument keys that name a destination outside the agent.
RECIPIENT_KEYS = frozenset({"to", "recipient", "recipients", "cc", "bcc", "dest", "destination",
                            "address", "email", "to_address", "url", "endpoint", "channel",
                            "webhook", "callback", "upload_to", "share_with"})

#: Morphemes that make a tool a sink rather than a source.
OUTBOUND_MORPHEMES = frozenset({"send", "draft", "email", "mail", "post", "publish", "share",
                                "upload", "export", "forward", "message", "notify", "webhook"})

#: Argument keys whose value is the *work product*, not a selector. Kept in step
#: with Lane A's `is_control_arg` so both lanes draw the control/payload line in
#: the same place: identifiers, recipients, statuses, amounts and queries steer
#: the effect; notes, bodies, titles and summaries are what the task produces.
#:
#: This distinction is load-bearing. An incident title derived from the alert the
#: user asked about is the task being done, not an injection; an incident *id*
#: taken from a log line is data choosing the target.
PAYLOAD_KEYS = frozenset({"body", "comment", "content", "description", "details", "detail",
                          "justification", "message", "note", "notes", "reason", "summary",
                          "subject", "text", "title"})

PAYLOAD_SUFFIXES = ("_body", "_comment", "_content", "_note", "_summary", "_text", "_description",
                    "_title", "_subject")


def action_class(ctx: SignalContext, action: CandidateAction | None = None) -> str:
    """``read`` | ``prepare`` | ``commit`` — what this action does to the world."""
    act = action if action is not None else ctx.action
    if act.type == "respond":
        return "read"
    if act.type == "memory_write":
        return "prepare"
    tool = act.tool or ""
    policy = ctx.policy
    consequential = set(policy.get("consequential_tools") or [])
    confirm_required = set(policy.get("confirmation_required_tools") or [])
    if tool and (tool in consequential or tool in confirm_required):
        return "commit"
    status = str(act.arguments.get("status", "")).strip().lower()
    morphemes = set(tool_morphemes(tool))
    if status in CLOSING_STATUSES and morphemes & {"update", "set", "change"}:
        return "commit"
    if morphemes & COMMIT_TERMS:
        return "commit"
    if morphemes & PREPARE_TERMS:
        return "prepare"
    if morphemes & READ_TERMS:
        return "read"
    return "prepare"


def is_consequential(ctx: SignalContext) -> bool:
    """Policy's own notion of consequential, plus the status-transition case."""
    action = ctx.action
    if action.type != "tool_call" or not action.tool:
        return False
    policy = ctx.policy
    if action.tool in set(policy.get("consequential_tools") or []):
        return True
    if action.tool in set(policy.get("confirmation_required_tools") or []):
        return True
    status = str(action.arguments.get("status", "")).strip().lower()
    return status in CLOSING_STATUSES


def confirmation_recorded(ctx: SignalContext) -> bool:
    """Whether a human confirmation exists for this step, per Lane A or history."""
    if ctx.authority.confirmation_present:
        return True
    return bool(ctx.request.history_digest.confirmations_granted)


def is_control_key(name: str) -> bool:
    """Does this argument name steer the effect, or carry the work product?"""
    lowered = name.lower()
    if lowered in PAYLOAD_KEYS:
        return False
    return not lowered.endswith(PAYLOAD_SUFFIXES)


def control_arguments(action: CandidateAction) -> dict[str, str]:
    """Arguments that *select what the action does to the world*.

    Judged by argument name, never by length. A four-word incident title and a
    forty-word one are the same kind of thing: output. This is what lets AEGIS
    allow "log a case note quoting the scam message verbatim" and "title the
    incident after what the alert said", while still catching "close INC-0101
    because a log line said to".
    """
    out: dict[str, str] = {}
    for key, value in action.arguments.items():
        if value is None or isinstance(value, bool):
            continue
        text = str(value)
        if not text.strip() or not is_control_key(key):
            continue
        out[key] = text
    return out


#: Retained name for the control-argument view; see :func:`control_arguments`.
steering_arguments = control_arguments


def outbound_destination(action: CandidateAction) -> tuple[str, str] | None:
    """``(argument_key, value)`` of the destination this action ships to, if any."""
    for key, value in action.arguments.items():
        if value is None or isinstance(value, bool):
            continue
        if key.lower() in RECIPIENT_KEYS:
            text = str(value).strip()
            if text:
                return key, text
    return None


def is_outbound(action: CandidateAction) -> bool:
    """True when the action hands data to somebody other than the caller."""
    if action.type != "tool_call":
        return False
    if outbound_destination(action) is not None:
        return True
    return bool(set(tool_morphemes(action.tool)) & OUTBOUND_MORPHEMES)


def internal_domains(ctx: SignalContext) -> tuple[str, ...]:
    policy = ctx.policy
    raw: list[str] = []
    for key in ("internal_email_domains", "internal_domains", "trusted_domains"):
        value = policy.get(key)
        if isinstance(value, list):
            raw.extend(str(item).lower().lstrip("@") for item in value if item)
        elif isinstance(value, str):
            raw.append(value.lower().lstrip("@"))
    return tuple(dict.fromkeys(d for d in raw if d))


def destination_is_internal(value: str, ctx: SignalContext) -> bool | None:
    """``True``/``False`` inside/outside the trust boundary, ``None`` if not a destination."""
    domains = internal_domains(ctx)
    text = value.strip().lower()
    host: str | None = None
    if "@" in text:
        host = text.rsplit("@", 1)[-1].strip("/> ")
    elif "://" in text:
        host = text.split("://", 1)[1].split("/", 1)[0]
    elif re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", text):
        host = text
    if host is None:
        return None
    if not domains:
        return None
    return any(host == d or host.endswith("." + d) for d in domains)


# --------------------------------------------------------------------------- #
# Provenance-derived views
# --------------------------------------------------------------------------- #

UNTRUSTED_LEVELS = frozenset(
    {TrustLevel.UNTRUSTED_INTERNAL, TrustLevel.UNTRUSTED_EXTERNAL, TrustLevel.ADVERSARY_CONTROLLED}
)


@dataclass(frozen=True)
class TextView:
    """Turn text, split by the trust and sensitivity of where it came from."""

    untrusted: tuple[str, ...] = ()
    trusted: tuple[str, ...] = ()
    sensitive: tuple[str, ...] = ()
    #: Provenance ids parallel to ``untrusted`` — used for split-instruction detection.
    untrusted_ids: tuple[str, ...] = ()


def _provenance_of(record: Provenance) -> tuple[TrustLevel, Sensitivity]:
    try:
        trust = TrustLevel(record.trust_level)
    except ValueError:  # pragma: no cover - wire schema is a Literal
        trust = TrustLevel.UNTRUSTED_EXTERNAL
    try:
        sensitivity = Sensitivity(record.sensitivity)
    except ValueError:  # pragma: no cover
        sensitivity = Sensitivity.INTERNAL
    return trust, sensitivity


def text_view(ctx: SignalContext) -> TextView:
    """Split everything the agent has seen this turn by trust and sensitivity.

    Lane A's ``tainted_spans`` / ``sensitive_spans`` are merged in when present,
    but this function stands alone: the signals keep working while Lane A is
    still a placeholder, and gain precision when it is not.
    """
    records = ctx.request.provenance_map()
    untrusted: list[str] = []
    untrusted_ids: list[str] = []
    trusted: list[str] = []
    sensitive: list[str] = []

    def classify(content: str, provenance_ids: list[str]) -> None:
        """One item can be both. A tool result often carries a trusted record and
        the untrusted raw log quoted inside it, and provenance is attributed per
        item rather than per span. Filing such an item as *only* untrusted would
        make every identifier it contains look attacker-chosen — which is how a
        legitimate "look up the affected host" step gets flagged. So the two
        buckets overlap deliberately: untrusted means "something untrusted is in
        here", trusted means "something trusted is too".
        """
        if not content:
            return
        provs = [records[pid] for pid in provenance_ids if pid in records]
        levels = [_provenance_of(p) for p in provs]
        text = content[:MAX_TEXT_CHARS]
        if any(trust in UNTRUSTED_LEVELS for trust, _ in levels):
            untrusted.append(text)
            untrusted_ids.append(next((pid for pid in provenance_ids if pid in records), ""))
        if any(trust not in UNTRUSTED_LEVELS for trust, _ in levels):
            trusted.append(text)
        if any(sens.is_sensitive for _, sens in levels):
            sensitive.append(text)

    for item in ctx.request.conversation[-60:]:
        if item.role == "user":
            trusted.append(item.content[:MAX_TEXT_CHARS])
            continue
        classify(item.content, list(item.provenance_ids))

    observation = ctx.request.observation
    if observation is not None:
        classify(observation.content, list(observation.provenance_ids))

    taint = ctx.taint
    for span in taint.tainted_spans[:MAX_UNTRUSTED_TEXTS]:
        if span:
            untrusted.append(span[:MAX_TEXT_CHARS])
            untrusted_ids.append("")
    for span in taint.sensitive_spans[:MAX_UNTRUSTED_TEXTS]:
        if span:
            sensitive.append(span[:MAX_TEXT_CHARS])

    return TextView(
        untrusted=tuple(untrusted[:MAX_UNTRUSTED_TEXTS]),
        trusted=tuple(trusted[:MAX_UNTRUSTED_TEXTS]),
        sensitive=tuple(sensitive[:MAX_UNTRUSTED_TEXTS]),
        untrusted_ids=tuple(untrusted_ids[:MAX_UNTRUSTED_TEXTS]),
    )


def overlap_probes(content: str, haystacks: tuple[str, ...], probe: int = 24) -> bool:
    """Sliding-window containment: does ``content`` reproduce a chunk of any haystack?"""
    needle = normalize(content)
    if len(needle) < probe:
        return bool(needle) and any(needle in normalize(h) for h in haystacks) and len(needle) >= 10
    step = max(1, probe // 2)
    probes = {needle[i : i + probe] for i in range(0, len(needle) - probe + 1, step)}
    normalized = [normalize(h) for h in haystacks]
    return any(p in hay for hay in normalized for p in probes)


# --------------------------------------------------------------------------- #
# Layered decoder
# --------------------------------------------------------------------------- #

#: Deliberately short minimums. A decoded blob is only ever *compared against a
#: known secret*, so decoding ordinary words costs a little CPU and risks nothing;
#: requiring 16 characters, by contrast, let a short identifier ride out in base64.
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{8,}={0,2}")
_HEX_TOKEN = re.compile(r"(?:[0-9a-fA-F]{2}){4,}")
_B32_TOKEN = re.compile(r"[A-Z2-7]{8,}={0,6}")


def _decode_base64(text: str) -> str:
    chunks: list[str] = []
    for token in _B64_TOKEN.findall(text)[:24]:
        for candidate in (token, token.replace("-", "+").replace("_", "/")):
            padded = candidate + "=" * (-len(candidate) % 4)
            try:
                decoded = base64.b64decode(padded, validate=False)
            except (binascii.Error, ValueError):
                continue
            text_out = decoded.decode("utf-8", "ignore")
            if text_out.strip():
                chunks.append(text_out)
                break
    return "\n".join(chunks)


def _decode_hex(text: str) -> str:
    chunks: list[str] = []
    for token in _HEX_TOKEN.findall(text)[:24]:
        try:
            chunks.append(bytes.fromhex(token).decode("utf-8", "ignore"))
        except ValueError:
            continue
    return "\n".join(chunks)


def _decode_base32(text: str) -> str:
    chunks: list[str] = []
    for token in _B32_TOKEN.findall(text)[:16]:
        padded = token + "=" * (-len(token) % 8)
        try:
            chunks.append(base64.b32decode(padded, casefold=True).decode("utf-8", "ignore"))
        except (binascii.Error, ValueError):
            continue
    return "\n".join(chunks)


def _decode_rot13(text: str) -> str:
    try:
        return codecs.decode(text, "rot13")
    except (UnicodeError, LookupError):  # pragma: no cover
        return ""


def _decode_percent(text: str) -> str:
    once = unquote(text)
    twice = unquote(once)
    return twice if twice != once else once


#: Name -> transform. Applied at depth 1 to the raw text, and at depth 2 to the
#: output of the reversible ones, so ``reverse(base64(secret))`` is still caught.
_TRANSFORMS: tuple[tuple[str, Any], ...] = (
    ("invisible", strip_invisible),
    ("percent", _decode_percent),
    ("base64", _decode_base64),
    ("hex", _decode_hex),
    ("base32", _decode_base32),
    ("rot13", _decode_rot13),
    ("reversed", lambda t: t[::-1]),
)

#: Transforms worth re-applying to an already-decoded string.
_SECOND_PASS = ("base64", "hex", "base32", "rot13", "percent")


def decode_variants(text: str) -> list[tuple[str, str]]:
    """Every readable form of ``text``, labelled by the transform chain used.

    ``[("plain", ...), ("base64", ...), ("reversed+base64", ...), ...]``. The
    label is what the trace viewer renders — catching a reversed token and being
    able to say *how* is the point.
    """
    source = text[:MAX_DECODE_CHARS]
    variants: list[tuple[str, str]] = [("plain", source)]
    seen: set[str] = {source}

    first_pass: list[tuple[str, str]] = []
    for name, fn in _TRANSFORMS:
        try:
            decoded = fn(source)
        except Exception:  # a decoder must never take the pipeline down
            continue
        if not decoded or decoded in seen:
            continue
        seen.add(decoded)
        first_pass.append((name, decoded))
        variants.append((name, decoded))

    transforms = dict(_TRANSFORMS)
    for name, decoded in first_pass:
        if len(variants) >= MAX_VARIANTS or len(decoded) > MAX_SECOND_PASS_CHARS:
            continue
        for inner_name in _SECOND_PASS:
            if inner_name == name:
                continue
            fn = transforms[inner_name]
            try:
                twice = fn(decoded)
            except Exception:
                continue
            if not twice or twice in seen:
                continue
            seen.add(twice)
            variants.append((f"{name}+{inner_name}", twice))
            if len(variants) >= MAX_VARIANTS:
                break
    return variants


def variant_index(text: str) -> tuple[str, tuple[tuple[str, str], ...]]:
    """``(lowercased text, ((transform, normalized variant), ...))``.

    Built once per carrier and reused across every secret, which is what keeps the
    decoder affordable when many candidate secrets are in play.
    """
    return text.lower(), tuple((name, normalize(v)) for name, v in decode_variants(text))


def find_in_variants(
    needle: str,
    text: str,
    index: tuple[str, tuple[tuple[str, str], ...]] | None = None,
) -> str | None:
    """Name of the cheapest transform under which ``needle`` appears in ``text``.

    ``"plain"`` means literally present; ``"separated"`` means present only once
    punctuation and spacing are ignored (``A C C - 1 0 0 1``); anything else names
    the decoding chain.
    """
    target = normalize(needle)
    if not target or len(target) < 4:
        return None
    lowered, variants = index if index is not None else variant_index(text)
    if needle.lower() in lowered:
        return "plain"
    for name, variant in variants:
        if target in variant:
            return "separated" if name == "plain" else name
    return None


def preview_secret(value: str) -> str:
    """Never put a full secret in the trace; show enough to recognise it."""
    if len(value) <= 8:
        return value[:2] + "…"
    return f"{value[:4]}…{value[-4:]}"


# --------------------------------------------------------------------------- #
# Signal scaffolding
# --------------------------------------------------------------------------- #


class BaseSignal:
    """Pure, total, side-effect free. Subclasses implement :meth:`_score`."""

    name: str = "signal"

    def score(self, ctx: SignalContext) -> SignalResult:
        try:
            result = self._score(ctx)
        except Exception as exc:  # a signal that raises is *no evidence*, never a pass
            return SignalResult(
                name=self.name,
                score=0.0,
                reason_codes=("SIGNAL_ERROR",),
                detail={"error": type(exc).__name__},
            )
        clamped = min(1.0, max(0.0, float(result.score)))
        if clamped != result.score:
            return SignalResult(
                name=result.name, score=clamped, reason_codes=result.reason_codes, detail=result.detail
            )
        return result

    def _score(self, ctx: SignalContext) -> SignalResult:  # pragma: no cover - abstract
        raise NotImplementedError

    def _empty(self, detail: dict[str, Any] | None = None) -> SignalResult:
        return SignalResult(name=self.name, score=0.0, reason_codes=(), detail=detail or {})


__all__ = [
    "BaseSignal",
    "CLOSING_STATUSES",
    "MORPHEME_SYNONYMS",
    "OUTBOUND_MORPHEMES",
    "PAYLOAD_KEYS",
    "RECIPIENT_KEYS",
    "STOPWORDS",
    "SYNONYM_CLOSURE",
    "TextView",
    "UNTRUSTED_LEVELS",
    "action_class",
    "canonical_number",
    "confirmation_recorded",
    "content_words",
    "decode_variants",
    "destination_is_internal",
    "expand",
    "find_in_variants",
    "identifier_tokens",
    "internal_domains",
    "is_consequential",
    "is_outbound",
    "morpheme_covered",
    "normalize",
    "outbound_destination",
    "overlap_probes",
    "preview_secret",
    "control_arguments",
    "is_control_key",
    "steering_arguments",
    "stem",
    "strip_invisible",
    "text_view",
    "tool_morphemes",
    "variant_index",
]
