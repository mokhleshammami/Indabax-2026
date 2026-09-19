"""Text mechanics, the layered decoder, the morpheme ontology and action structure."""

from __future__ import annotations

import base64
import codecs

import pytest

from aegis.signals.base import (
    action_class,
    canonical_number,
    content_words,
    control_arguments,
    decode_variants,
    destination_is_internal,
    expand,
    find_in_variants,
    identifier_tokens,
    is_consequential,
    is_control_key,
    is_outbound,
    morpheme_covered,
    normalize,
    outbound_destination,
    overlap_probes,
    preview_secret,
    steering_arguments,
    stem,
    strip_invisible,
    text_view,
    tool_morphemes,
    variant_index,
)
from aegis.types import ConversationItem, SignalContext
from tests.test_signals_common import (
    ENTERPRISE_POLICY,
    FINANCE_POLICY,
    make_ctx,
    provenance,
    respond,
    tool_call,
)

SECRET = "SENTINEL_SECRET_0A1B2C3D4E5F6071"


# --------------------------------------------------------------------- text


def test_normalize_collapses_separators():
    assert normalize("A C C - 1 0 0 1") == normalize("acc_1001") == "acc1001"


def test_strip_invisible_is_identity_on_ascii():
    assert strip_invisible("plain ascii text") == "plain ascii text"


def test_strip_invisible_removes_zero_width_and_folds_homoglyphs():
    assert strip_invisible("AC​C-1001") == "ACC-1001"
    assert strip_invisible("АCC") == "ACC"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("1,250.00", "1250"), ("1250", "1250"), ("4,900", "4900"), ("0.50", "0.5"), ("abc", None)],
)
def test_canonical_number(raw, expected):
    assert canonical_number(raw) == expected


def test_identifier_tokens_keeps_ids_and_drops_prose():
    tokens = identifier_tokens("Refund 1,250.00 TND on ACC-1001 to billing@vendor.example today")
    assert "acc-1001" in tokens
    assert "acc1001" in tokens
    assert "1250" in tokens
    assert "billing@vendor.example" in tokens
    assert "refund" not in tokens and "today" not in tokens


def test_content_words_strips_stopwords_and_stems():
    words = content_words("Please prepare the refunds for the customer")
    assert "prepare" in words and "refund" in words
    assert "the" not in words and "for" not in words


def test_stem_is_conservative():
    assert stem("payments") == "payment"
    assert stem("reading") == "read"
    assert stem("cat") == "cat"


def test_overlap_probes_finds_quoted_span():
    source = "Customer reported a scam message asking for a secret code to override the hold"
    assert overlap_probes(f"Note: {source}", (source,))
    assert not overlap_probes("Unrelated note about laptops", (source,))


def test_preview_secret_never_reveals_the_whole_value():
    preview = preview_secret(SECRET)
    assert SECRET not in preview
    assert preview.startswith("SENT") and preview.endswith("6071")


# ------------------------------------------------------------------ decoder


@pytest.mark.parametrize(
    ("label", "encode"),
    [
        ("plain", lambda s: s),
        ("base64", lambda s: base64.b64encode(s.encode()).decode()),
        ("base64-unpadded", lambda s: base64.b64encode(s.encode()).decode().rstrip("=")),
        ("base64url", lambda s: base64.urlsafe_b64encode(s.encode()).decode()),
        ("hex", lambda s: s.encode().hex()),
        ("base32", lambda s: base64.b32encode(s.encode()).decode()),
        ("rot13", lambda s: codecs.encode(s, "rot13")),
        ("reversed", lambda s: s[::-1]),
        ("spaced", lambda s: " ".join(s)),
        ("dashed", lambda s: "-".join(s)),
        ("zero-width", lambda s: "​".join(s)),
        ("percent", lambda s: "".join(f"%{ord(c):02X}" for c in s)),
        ("double-percent", lambda s: "".join(f"%25{ord(c):02X}" for c in s)),
        ("reversed-base64", lambda s: base64.b64encode(s.encode()).decode()[::-1]),
        ("rot13-of-base64", lambda s: codecs.encode(base64.b64encode(s.encode()).decode(), "rot13")),
        ("homoglyph", lambda s: s.replace("E", "Е")),
    ],
)
def test_every_transform_is_seen_through(label, encode):
    carrier = f"Reference data: {encode(SECRET)} -- regards"
    assert find_in_variants(SECRET, carrier) is not None, label


def test_find_in_variants_labels_the_transform():
    assert find_in_variants(SECRET, f"token {SECRET}") == "plain"
    assert find_in_variants(SECRET, " ".join(SECRET)) == "separated"
    assert find_in_variants(SECRET, base64.b64encode(SECRET.encode()).decode()) == "base64"
    assert find_in_variants(SECRET, SECRET[::-1]) == "reversed"


def test_find_in_variants_has_no_false_positive():
    assert find_in_variants(SECRET, "an ordinary sentence with no secret in it") is None


def test_short_needles_are_ignored():
    assert find_in_variants("ab", "ab ab ab") is None


def test_variant_index_is_reusable_and_equivalent():
    carrier = f"x {base64.b64encode(SECRET.encode()).decode()} y"
    index = variant_index(carrier)
    assert find_in_variants(SECRET, carrier, index) == find_in_variants(SECRET, carrier)


def test_decode_variants_is_bounded_and_never_raises():
    variants = decode_variants("%%%% not valid !!! \x00\x01" * 400)
    assert 1 <= len(variants) <= 64
    assert variants[0][0] == "plain"


# --------------------------------------------------------------- morphology


def test_tool_morphemes_splits_compounds():
    assert tool_morphemes("payment_confirm") == ("payment", "confirm")
    assert tool_morphemes(None) == ()


def test_expand_is_symmetric():
    assert "send" in expand("email") or "email" in expand("send")
    assert "log" in expand("create")


def test_morpheme_covered_uses_synonyms():
    vocabulary = content_words("log a case note for the customer")
    assert morpheme_covered("create", vocabulary)
    assert morpheme_covered("note", vocabulary)
    assert not morpheme_covered("payment", vocabulary)


# ---------------------------------------------------------------- structure


def test_action_class_uses_policy_first():
    ctx = make_ctx(goal="g", action=tool_call("payment_confirm", payment_id="PAY-1"))
    assert action_class(ctx) == "commit"
    assert is_consequential(ctx)


def test_action_class_falls_back_to_morphemes():
    ctx = make_ctx(goal="g", action=tool_call("case_document_read", doc_id="CD-01"))
    assert action_class(ctx) == "read"
    assert not is_consequential(ctx)


def test_closing_status_makes_an_update_consequential():
    open_ctx = make_ctx(
        goal="g", action=tool_call("incident_update", incident_id="INC-1", status="investigating")
    )
    closed_ctx = make_ctx(
        goal="g", action=tool_call("incident_update", incident_id="INC-1", status="closed")
    )
    assert not is_consequential(open_ctx)
    assert is_consequential(closed_ctx)
    assert action_class(closed_ctx) == "commit"


def test_respond_is_read_class():
    assert action_class(make_ctx(goal="g", action=respond("done"))) == "read"


def test_outbound_detection():
    assert is_outbound(tool_call("email_draft", to="a@b.example", body="x"))
    assert is_outbound(tool_call("notify_webhook", url="https://x.example/hook"))
    assert not is_outbound(tool_call("case_note_create", case_id="C-1", text="x"))
    assert outbound_destination(tool_call("email_send", to="a@b.example")) == ("to", "a@b.example")


def test_destination_is_internal_uses_policy_domains():
    ctx = make_ctx(goal="g", action=tool_call("email_send"), policy=ENTERPRISE_POLICY)
    assert destination_is_internal("leila.mansour@atlas.example", ctx) is True
    assert destination_is_internal("billing@vendor.example", ctx) is False
    assert destination_is_internal("not a destination", ctx) is None


def test_destination_unknown_when_policy_declares_no_boundary():
    ctx = make_ctx(goal="g", action=tool_call("email_send"), policy=FINANCE_POLICY)
    assert destination_is_internal("someone@anywhere.example", ctx) is None


def test_control_arguments_separate_selectors_from_work_product():
    action = tool_call(
        "case_note_create",
        case_id="CASE-7002",
        text="A long free text field that quotes a great many words from a document elsewhere",
    )
    assert control_arguments(action) == {"case_id": "CASE-7002"}
    assert steering_arguments is control_arguments


def test_short_payload_arguments_are_still_payload():
    """Regression: a four-word incident title is output, not a selector.

    Judging by length made `title="Encoded PowerShell on WS-114"` look like an
    identifier chosen by the logs, and escalated a legitimate triage step.
    """
    action = tool_call(
        "incident_create",
        alert_id="AL-3001",
        title="Encoded PowerShell on WS-114",
        severity="high",
        summary="Host WS-114 owned by Karim Trabelsi.",
    )
    control = control_arguments(action)
    assert set(control) == {"alert_id", "severity"}
    assert not is_control_key("title") and not is_control_key("summary")
    assert is_control_key("alert_id") and is_control_key("query")


# -------------------------------------------------------------- text_view


def test_text_view_buckets_overlap_for_mixed_items():
    """Regression: an item carrying both trusted and untrusted provenance.

    Filing it as *only* untrusted made every identifier in it look
    attacker-chosen, which blocked "look up the affected workstation".
    """
    ctx = make_ctx(goal="g", action=tool_call("asset_lookup", asset_id="WS-114"))
    request = ctx.request.model_copy(
        update={
            "provenance": [
                provenance("t1", trust="trusted_internal"),
                provenance("u1", trust="untrusted_internal"),
            ],
            "conversation": [
                ConversationItem(
                    role="tool",
                    kind="tool_result",
                    content="AL-3001 on WS-114, raw log attached",
                    provenance_ids=["t1", "u1"],
                )
            ],
        }
    )
    view = text_view(SignalContext(request=request, taint=ctx.taint, authority=ctx.authority))
    assert any("WS-114" in t for t in view.untrusted)
    assert any("WS-114" in t for t in view.trusted)


def test_text_view_splits_by_provenance():
    ctx = make_ctx(
        goal="the goal",
        action=tool_call("email_read", email_id="EM-1"),
        untrusted=[("p1", "vendor says hello")],
        trusted=[("p2", "internal note")],
        sensitive=[("p3", "restricted material")],
    )
    view = text_view(ctx)
    assert any("vendor says" in t for t in view.untrusted)
    assert any("internal note" in t for t in view.trusted)
    assert any("restricted" in t for t in view.sensitive)
    assert any("the goal" in t for t in view.trusted)
