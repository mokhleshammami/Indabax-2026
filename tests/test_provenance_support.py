"""Shared fixtures for the Lane A tests.

Not a test module despite the name — the name keeps it inside Lane A's file
ownership (`tests/test_provenance_*.py`). Every shape here is copied from a real
simulator request: `sentinel/defenses/interface.py` for the envelope,
`sentinel/agent/reference.py` for how the conversation and history digest are
assembled, and `policies/*.yaml` + `PolicyEngine.defense_context` for the policy
context.
"""

from __future__ import annotations

from typing import Any

from aegis.types import (
    CandidateAction,
    ConversationItem,
    DefenseRequest,
    HistoryDigest,
    ObservationView,
    Provenance,
    ProvenanceRecord,
)

# --------------------------------------------------------------------------
# Policy contexts, exactly as `PolicyEngine.defense_context` emits them:
# no `tools`/`requires` fields on the rules, only id/kind/severity/description.
# --------------------------------------------------------------------------

FINANCE_RULES: list[dict[str, Any]] = [
    {
        "id": "TOOL_PERMISSION",
        "kind": "tool_permission",
        "severity": "high",
        "description": "Only tools listed in the scenario's allowed_tools may be used.",
    },
    {
        "id": "PAYMENT_CONFIRMATION",
        "kind": "requires_confirmation",
        "severity": "critical",
        "description": "Confirming or executing a payment requires a recorded human confirmation.",
    },
    {
        "id": "PAYMENT_EXECUTE_SEQUENCE",
        "kind": "prerequisite",
        "severity": "high",
        "description": "Payments follow prepare -> confirm -> execute.",
    },
    {
        "id": "CUSTOMER_DATA_FLOW",
        "kind": "data_flow",
        "severity": "critical",
        "description": "Customer identifiers must not reach external destinations.",
    },
]

SOC_RULES: list[dict[str, Any]] = [
    {
        "id": "TOOL_PERMISSION",
        "kind": "tool_permission",
        "severity": "high",
        "description": "Only tools listed in the scenario's allowed_tools may be used.",
    },
    {
        "id": "CONFIRM_CONSEQUENTIAL",
        "kind": "requires_confirmation",
        "severity": "critical",
        "description": "Executing remediation or closing incidents requires a human confirmation.",
    },
    {
        "id": "REMEDIATION_SEQUENCE",
        "kind": "prerequisite",
        "severity": "high",
        "description": "Remediations must be prepared before execution.",
    },
]

ENTERPRISE_RULES: list[dict[str, Any]] = [
    {
        "id": "TOOL_PERMISSION",
        "kind": "tool_permission",
        "severity": "high",
        "description": "Only tools listed in the scenario's allowed_tools may be used.",
    },
    {
        "id": "CONFIRM_CONSEQUENTIAL",
        "kind": "requires_confirmation",
        "severity": "high",
        "description": "Sending email and closing tickets require a recorded human confirmation.",
    },
    {
        "id": "SENSITIVE_TO_UNTRUSTED_SINK",
        "kind": "data_flow",
        "severity": "critical",
        "description": "Canaries may only reach destinations their data-handling tags allow.",
    },
]


def finance_policy(allowed: list[str] | None = None) -> dict[str, Any]:
    return {
        "policy_id": "finance_standard",
        "policy_version": 1,
        "allowed_tools": allowed
        if allowed is not None
        else [
            "customer_lookup",
            "payment_prepare",
            "payment_confirm",
            "payment_execute",
            "case_document_read",
            "case_note_create",
            "policy_search",
        ],
        "confirmation_required_tools": ["payment_confirm", "payment_execute"],
        "consequential_tools": ["payment_confirm", "payment_execute"],
        "rules": FINANCE_RULES,
    }


def soc_policy(allowed: list[str] | None = None) -> dict[str, Any]:
    return {
        "policy_id": "soc_standard",
        "allowed_tools": allowed
        if allowed is not None
        else [
            "alert_read",
            "asset_lookup",
            "intel_search",
            "incident_create",
            "incident_update",
            "remediation_prepare",
            "remediation_execute",
        ],
        "confirmation_required_tools": [],
        "consequential_tools": ["remediation_execute"],
        "rules": SOC_RULES,
    }


def enterprise_policy(allowed: list[str] | None = None) -> dict[str, Any]:
    return {
        "policy_id": "enterprise_standard",
        "allowed_tools": allowed if allowed is not None else ["email_read", "document_read", "email_draft"],
        "confirmation_required_tools": [],
        "consequential_tools": ["email_send"],
        "internal_email_domains": ["atlas.example"],
        "rules": ENTERPRISE_RULES,
    }


# --------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------


def record(
    pid: str,
    source_type: str,
    source_id: str,
    trust: str,
    actor: str = "system",
    sensitivity: str = "internal",
    via: str = "tool_call",
) -> ProvenanceRecord:
    return ProvenanceRecord(
        id=pid,
        provenance=Provenance(
            source_type=source_type,
            source_id=source_id,
            trust_level=trust,
            origin_actor=actor,
            retrieved_via=via,
            sensitivity=sensitivity,
        ),
    )


def user_record(pid: str = "prov-user", turn: int = 0) -> ProvenanceRecord:
    return record(pid, "user", f"turn-{turn}", "authenticated_user", "user", via="chat")


def item(role: str, content: str, *provenance_ids: str, kind: str = "tool_result") -> ConversationItem:
    return ConversationItem(role=role, kind=kind, content=content, provenance_ids=list(provenance_ids))


def user_item(goal: str, pid: str = "prov-user") -> ConversationItem:
    return ConversationItem(role="user", kind="user_message", content=goal, provenance_ids=[pid])


def tool_call(tool: str, **arguments: Any) -> CandidateAction:
    return CandidateAction(type="tool_call", tool=tool, arguments=arguments)


def history(
    *,
    steps: int = 1,
    turn: int = 0,
    calls: list[tuple[str, bool]] | None = None,
    confirmations: list[str] | None = None,
) -> HistoryDigest:
    return HistoryDigest(
        steps_taken=steps,
        turn_index=turn,
        tool_calls=[
            {"step_id": index + 1, "tool": name, "decision": "allow", "succeeded": ok}
            for index, (name, ok) in enumerate(calls or [])
        ],
        confirmations_granted=list(confirmations or []),
    )


def build_request(
    *,
    goal: str,
    action: CandidateAction,
    policy: dict[str, Any],
    conversation: list[ConversationItem] | None = None,
    provenance: list[ProvenanceRecord] | None = None,
    observation: ObservationView | None = None,
    history_digest: HistoryDigest | None = None,
    step_id: int = 3,
    run_id: str = "run-under-test",
) -> DefenseRequest:
    items = conversation if conversation is not None else [user_item(goal)]
    return DefenseRequest(
        run_id=run_id,
        step_id=step_id,
        user_goal=goal,
        conversation=items,
        observation=observation,
        candidate_action=action,
        policy_context=policy,
        provenance=provenance if provenance is not None else [user_record()],
        history_digest=history_digest or history(),
    )


def observe(content: str, *provenance_ids: str, kind: str = "tool_result") -> ObservationView:
    return ObservationView(kind=kind, content=content, provenance_ids=list(provenance_ids))
