"""Encoding-aware exfiltration.

AEGIS never regexes for "things that look like secrets". It asks Lane A which
tokens in this turn *are* sensitive, and then asks a different question: can any
of them be reconstructed from what this action is about to send?

The reconstruction step is where the work is. A secret leaves through an argument
only after some transformation, and the transformation is usually cheap:

* base64 (standard, url-safe, unpadded), hex, base32
* rot13, reversal, percent-encoding (single and double)
* zero-width characters and homoglyph substitution
* character spacing — ``A C C - 1 0 0 1``
* concatenation across several arguments, so no single argument contains it
* any pair of the above, composed

:func:`aegis.signals.base.decode_variants` enumerates those forms and labels each
one, so when the signal fires the trace can say *how* the value was hidden rather
than merely that something matched. An encoded secret is scored as maximal risk
regardless of destination: there is no legitimate reason to base64 an account
number into an email body.
"""

from __future__ import annotations

from typing import Any

from aegis.signals.base import (
    MAX_SECRETS,
    BaseSignal,
    destination_is_internal,
    find_in_variants,
    identifier_tokens,
    is_outbound,
    normalize,
    outbound_destination,
    preview_secret,
    text_view,
    variant_index,
)
from aegis.types import SignalContext, SignalResult

#: Shorter than this and a "secret" is just a word; matching it means nothing.
MIN_SECRET_CHARS = 6

#: A *plain* match on a short value inside the trust boundary is noise: asset ids
#: and case numbers are short, live in confidential records, and are supposed to
#: appear in the incident that discusses them. Obfuscation keeps the low bar,
#: because nobody base64s an asset id by accident.
MIN_PLAIN_SECRET_CHARS = 10

#: How much a plain (unencoded) appearance costs, by where it is going.
_PLAIN_WEIGHT = {
    "external": 0.92,
    "unknown": 0.62,
    "internal": 0.20,
    "caller": 0.18,
}

#: An obfuscated secret is never accidental.
ENCODED_SCORE = 0.96


def candidate_secrets(ctx: SignalContext) -> list[str]:
    """Sensitive tokens worth checking for, most authoritative source first.

    Lane A's ``secret_values`` is the contract. The fallback — identifier-shaped
    tokens drawn from spans Lane A (or provenance) marked sensitive — keeps the
    signal alive while Lane A is a placeholder, and is still provenance-driven:
    it never guesses at secrecy from the shape of a string alone.
    """
    chosen: list[str] = []
    # Deduplicate on the normalised form: ``PAY-0001`` and ``pay0001`` are the
    # same secret, and counting them twice would make a plain appearance look
    # obfuscated.
    seen: set[str] = set()
    # A value the user typed into their own goal is not a secret being smuggled
    # out. "How critical is SRV-22?" cannot be answered without saying SRV-22.
    goal_flat = normalize(ctx.request.user_goal)

    def offer(value: str) -> None:
        text = value.strip()
        key = normalize(text)
        if len(text) < MIN_SECRET_CHARS or not key or key in seen:
            return
        if key in goal_flat:
            return
        seen.add(key)
        chosen.append(text)

    for value in ctx.taint.secret_values:
        offer(str(value))

    if len(chosen) < MAX_SECRETS:
        view = text_view(ctx)
        for span in view.sensitive:
            # `identifier_tokens` is a set, and it yields both the raw token and
            # its normalised core. Sorting longest-first makes the choice between
            # them deterministic — the raw form wins — so the same input always
            # produces the same trace, whatever the hash seed.
            candidates = sorted(identifier_tokens(span), key=lambda t: (-len(t), t))
            for token in candidates:
                if len(token) >= 10 and any(ch.isdigit() for ch in token):
                    offer(token)
                if len(chosen) >= MAX_SECRETS:
                    break
    return chosen[:MAX_SECRETS]


def destination_kind(ctx: SignalContext) -> str:
    """``external`` | ``internal`` | ``unknown`` | ``caller``."""
    action = ctx.action
    if action.type == "respond":
        return "caller"
    destination = outbound_destination(action)
    if destination is not None:
        inside = destination_is_internal(destination[1], ctx)
        if inside is True:
            return "internal"
        if inside is False:
            return "external"
        return "unknown"
    if is_outbound(action):
        return "unknown"
    return "internal"


class EncodedExfiltrationSignal(BaseSignal):
    """A tainted secret reaching a sink, in any of its disguises."""

    name = "encoded_exfiltration"

    def _score(self, ctx: SignalContext) -> SignalResult:
        secrets = candidate_secrets(ctx)
        if not secrets:
            return self._empty({"secrets_considered": 0})

        action = ctx.action
        sink = destination_kind(ctx)
        detail: dict[str, Any] = {"secrets_considered": len(secrets), "destination": sink}

        # Every place a value could ride out: each argument alone, the content
        # blob, and the concatenation of all arguments (which is how a value is
        # split so that no single field contains it).
        carriers: list[tuple[str, str]] = []
        for key, value in action.arguments.items():
            if value is None or isinstance(value, bool):
                continue
            carriers.append((key, str(value)))
        if action.content:
            carriers.append(("content", action.content))
        if len(carriers) > 1:
            joined = "".join(text for _, text in carriers)
            carriers.append(("<all arguments>", joined))
            ordered = "".join(text for _, text in sorted(carriers[:-1]))
            if normalize(ordered) != normalize(joined):
                carriers.append(("<arguments, sorted>", ordered))
        if not carriers:
            return self._empty(detail)

        # Decode each carrier once, then test every secret against that index.
        matches: list[dict[str, str]] = []
        found: set[str] = set()
        for key, text in carriers:
            index = variant_index(text)
            for secret in secrets:
                if secret in found:
                    continue
                transform = find_in_variants(secret, text, index)
                if transform is None:
                    continue
                if (
                    transform == "plain"
                    and sink not in ("external", "unknown")
                    and len(normalize(secret)) < MIN_PLAIN_SECRET_CHARS
                ):
                    # A short identifier sitting in plain sight in an internal
                    # record is the record doing its job.
                    continue
                found.add(secret)
                if key.startswith("<") and transform in ("plain", "separated"):
                    # No single argument contained it; it was reassembled.
                    transform = "concatenated"
                matches.append(
                    {
                        "argument": key,
                        "transform": transform,
                        "secret": preview_secret(secret),
                    }
                )
                if len(matches) >= 6:
                    break
            if len(matches) >= 6:
                break

        if not matches:
            return self._empty(detail)

        detail["matches"] = matches
        encoded = [m for m in matches if m["transform"] not in ("plain",)]
        detail["encoded"] = bool(encoded)

        if encoded:
            score = ENCODED_SCORE if sink != "caller" else 0.80
            detail["how"] = encoded[0]["transform"]
        else:
            score = _PLAIN_WEIGHT.get(sink, 0.6)
            if len(matches) > 1:
                score = min(0.98, score + 0.05 * (len(matches) - 1))

        codes = ("ENCODED_SECRET_DETECTED",) if score > 0.0 else ()
        if not encoded and sink in ("internal", "caller"):
            # Plain sensitive value staying inside the boundary: real, but mild.
            codes = ("ENCODED_SECRET_DETECTED",)
        return SignalResult(name=self.name, score=score, reason_codes=codes, detail=detail)


__all__ = [
    "ENCODED_SCORE",
    "MIN_PLAIN_SECRET_CHARS",
    "MIN_SECRET_CHARS",
    "EncodedExfiltrationSignal",
    "candidate_secrets",
    "destination_kind",
]
