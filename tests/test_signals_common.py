"""Shared fixtures for the Lane B signal tests.

Not a test module itself — it builds `SignalContext` objects by hand so each
signal can be exercised in isolation, without Lane A, without the simulator and
without any I/O. Named `test_signals_common` only because Lane B owns exactly
`tests/test_signals_*.py`.
"""

from __future__ import annotations

from typing import Any

from aegis.types import (
    Authority,
    AuthorityVerdict,
    CandidateAction,
    ConversationItem,
    DefenseRequest,
    HistoryDigest,
    ObservationView,
    Provenance,
    ProvenanceRecord,
    Sensitivity,
    SignalContext,
    TaintSummary,
    TrustLevel,
)

FINANCE_POLICY: dict[str, Any] = {
    "policy_id": "finance_standard",
    "policy_version": 1,
    "allowed_tools": [
        "customer_lookup",
        "payment_prepare",
        "payment_confirm",
        "case_document_read",
        "case_note_create",
        "policy_search",
    ],
    "confirmation_required_tools": ["payment_confirm", "payment_execute"],
    "consequential_tools": ["payment_confirm", "payment_execute"],
    "rules": [{"id": "TOOL_PERMISSION", "kind": "tool_permission", "severity": "high", "description": ""}],
}

ENTERPRISE_POLICY: dict[str, Any] = {
    "policy_id": "enterprise_standard",
    "policy_version": 1,
    "allowed_tools": ["email_read", "email_search", "wiki_search", "email_draft", "email_send"],
    "confirmation_required_tools": [],
    # Mirrors the simulator: only tools with a static ``consequential`` flag are
    # listed here. ``ticket_update`` is consequential only for closing statuses.
    "consequential_tools": ["email_send"],
    "internal_email_domains": ["atlas.example"],
    "rules": [{"id": "TOOL_PERMISSION", "kind": "tool_permission", "severity": "high", "description": ""}],
}

SOC_POLICY: dict[str, Any] = {
    "policy_id": "soc_standard",
    "policy_version": 1,
    "allowed_tools": ["alert_read", "asset_lookup", "incident_create", "incident_update"],
    "confirmation_required_tools": [],
    "consequential_tools": ["remediation_execute"],
    "rules": [{"id": "TOOL_PERMISSION", "kind": "tool_permission", "severity": "high", "description": ""}],
}


def provenance(
    pid: str,
    *,
    trust: str = "untrusted_external",
    sensitivity: str = "internal",
    source_type: str = "document",
    origin: str = "third_party",
) -> ProvenanceRecord:
    return ProvenanceRecord(
        id=pid,
        provenance=Provenance(
            source_type=source_type,
            source_id=pid.upper(),
            trust_level=trust,  # type: ignore[arg-type]
            origin_actor=origin,
            retrieved_via="tool_call",
            sensitivity=sensitivity,  # type: ignore[arg-type]
        ),
    )


def tool_call(tool: str, **arguments: Any) -> CandidateAction:
    return CandidateAction(type="tool_call", tool=tool, arguments=arguments)


def respond(content: str, *, final: bool = True) -> CandidateAction:
    return CandidateAction(type="respond", content=content, final=final)


def memory_write(content: str) -> CandidateAction:
    return CandidateAction(type="memory_write", content=content)


def make_ctx(
    *,
    goal: str,
    action: CandidateAction,
    policy: dict[str, Any] | None = None,
    untrusted: list[tuple[str, str]] | None = None,
    trusted: list[tuple[str, str]] | None = None,
    sensitive: list[tuple[str, str]] | None = None,
    observation: tuple[str, str] | None = None,
    taint: TaintSummary | None = None,
    authority: AuthorityVerdict | None = None,
    confirmations: list[str] | None = None,
) -> SignalContext:
    """Build a `SignalContext` from plain text and provenance labels.

    `untrusted` / `trusted` / `sensitive` are `(provenance_id, content)` pairs and
    are wired up as conversation items with matching provenance records.
    """
    records: list[ProvenanceRecord] = []
    conversation: list[ConversationItem] = [
        ConversationItem(role="user", kind="goal", content=goal, provenance_ids=[])
    ]

    def add(pairs: list[tuple[str, str]] | None, **kwargs: Any) -> None:
        for pid, content in pairs or []:
            records.append(provenance(pid, **kwargs))
            conversation.append(
                ConversationItem(role="tool", kind="tool_result", content=content, provenance_ids=[pid])
            )

    add(untrusted, trust="untrusted_external")
    add(trusted, trust="trusted_internal")
    add(sensitive, trust="trusted_internal", sensitivity="restricted")

    observation_view = None
    if observation is not None:
        pid, content = observation
        if pid not in {r.id for r in records}:
            records.append(provenance(pid))
        observation_view = ObservationView(kind="tool_result", content=content, provenance_ids=[pid])

    request = DefenseRequest(
        run_id="fixture",
        step_id=1,
        user_goal=goal,
        conversation=conversation,
        observation=observation_view,
        candidate_action=action,
        policy_context=policy if policy is not None else FINANCE_POLICY,
        provenance=records,
        history_digest=HistoryDigest(confirmations_granted=confirmations or []),
    )
    return SignalContext(
        request=request,
        taint=taint or TaintSummary(),
        authority=authority or AuthorityVerdict(),
    )


def tainted(
    *,
    action_taint: TrustLevel = TrustLevel.UNTRUSTED_EXTERNAL,
    sensitivity: Sensitivity = Sensitivity.INTERNAL,
    secrets: tuple[str, ...] = (),
    sensitive_spans: tuple[str, ...] = (),
    tainted_spans: tuple[str, ...] = (),
    value_derived: bool = True,
    memory_taint: TrustLevel | None = None,
) -> TaintSummary:
    return TaintSummary(
        action_taint=action_taint,
        context_taint=action_taint,
        max_sensitivity=sensitivity,
        tainted_spans=tainted_spans,
        sensitive_spans=sensitive_spans,
        secret_values=secrets,
        value_derived_from_untrusted=value_derived,
        memory_taint=memory_taint,
    )


def unsatisfied(
    *,
    required: Authority = Authority.COMMIT,
    available: Authority = Authority.READ,
    codes: tuple[str, ...] = ("AUTHORITY_EXCEEDS_PROVENANCE",),
    safer: str | None = None,
    requires_confirmation: bool = False,
) -> AuthorityVerdict:
    return AuthorityVerdict(
        required=required,
        available=available,
        satisfied=False,
        reason_codes=codes,
        safer_alternative=safer,
        requires_confirmation=requires_confirmation,
    )
