"""Lane A — lifecycle ordering and confirmation matching.

The digest test is the load-bearing one: if our digest disagrees with the
simulator's by a single byte, every legitimate confirmed action is re-escalated
and every task that needs one fails. The expected values below are computed by
`sentinel.core.actions.CandidateAction.digest` itself.
"""

from __future__ import annotations

import hashlib
import json

from aegis.provenance import ProvenanceEngine
from aegis.provenance.lifecycle import (
    action_digest,
    confirmation_present,
    evaluate,
    has_terminal_status,
    ordering_enforced,
    stage_for_tool,
)
from aegis.types import Authority, CandidateAction
from tests.test_provenance_support import (
    build_request,
    enterprise_policy,
    finance_policy,
    history,
    soc_policy,
    tool_call,
)


def verdict(request):
    engine = ProvenanceEngine()
    return engine.check_authority(request, engine.analyze(request))


# --------------------------------------------------------------------------
# The digest
# --------------------------------------------------------------------------


def _reference_digest(action: CandidateAction) -> str:
    """An independent transcription of `sentinel.core.actions.CandidateAction.digest`."""

    def canonical(value):
        if isinstance(value, str):
            return " ".join(value.split())
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return value

    payload = {
        "type": action.type,
        "tool": action.tool,
        "arguments": {k: canonical(v) for k, v in sorted(action.arguments.items())},
        "content": action.content if action.type != "tool_call" else None,
    }
    if action.confirmation_for is not None:
        payload["confirmation_for"] = _reference_digest(action.confirmation_for)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:24]


def test_digest_matches_the_simulator_byte_for_byte() -> None:
    cases = [
        tool_call("payment_confirm", payment_id="PAY-0001"),
        tool_call("payment_prepare", account_id="ACC-1001", beneficiary_id="BEN-01", amount=1250, reference="refund"),
        tool_call("incident_update", incident_id="INC-0101", status="investigating", note="triage under way"),
        CandidateAction(type="respond", content="Prepared PAY-0001 for review."),
        CandidateAction(type="memory_write", content="Takeaway: loader domain blocked."),
    ]
    for action in cases:
        assert action_digest(action) == _reference_digest(action), action.tool or action.type


def test_digest_canonicalizes_whitespace_and_integral_floats() -> None:
    spaced = tool_call("payment_prepare", reference="CASE-7001   chargeback\n refund", amount=1250.0)
    tidy = tool_call("payment_prepare", reference="CASE-7001 chargeback refund", amount=1250)
    assert action_digest(spaced) == action_digest(tidy)
    assert action_digest(spaced) == _reference_digest(spaced)


def test_digest_of_a_confirmation_wrapper_nests_the_target() -> None:
    target = tool_call("payment_confirm", payment_id="PAY-0001")
    wrapper = CandidateAction(type="request_confirmation", content="May I confirm?", confirmation_for=target)
    assert action_digest(wrapper) == _reference_digest(wrapper)
    assert action_digest(wrapper) != action_digest(target)


def test_argument_order_does_not_change_the_digest() -> None:
    a = tool_call("payment_prepare", account_id="ACC-1001", amount=1250)
    b = tool_call("payment_prepare", amount=1250, account_id="ACC-1001")
    assert action_digest(a) == action_digest(b)


def test_confirmation_is_matched_by_digest_not_by_tool_name() -> None:
    action = tool_call("payment_confirm", payment_id="PAY-0001")
    other = tool_call("payment_confirm", payment_id="PAY-0002")
    request = build_request(
        goal="Confirm the prepared refund once I approve.",
        action=action,
        policy=finance_policy(),
        history_digest=history(confirmations=[action_digest(other)]),
    )
    assert not confirmation_present(request, action)

    approved = build_request(
        goal="Confirm the prepared refund once I approve.",
        action=action,
        policy=finance_policy(),
        history_digest=history(confirmations=[action_digest(action)]),
    )
    assert confirmation_present(approved, action)


def test_a_recorded_confirmation_restores_commit_authority() -> None:
    goal = "Officer Amel Trabelsi approved the CASE-7001 refund. Prepare it, then confirm it once I approve."
    action = tool_call("payment_confirm", payment_id="PAY-0001")
    unconfirmed = verdict(
        build_request(
            goal=goal,
            action=action,
            policy=finance_policy(),
            history_digest=history(steps=2, calls=[("payment_prepare", True)]),
        )
    )
    assert unconfirmed.required is Authority.COMMIT
    assert unconfirmed.available is Authority.PREPARE
    assert unconfirmed.reason_codes == ("MISSING_CONFIRMATION",)

    confirmed = verdict(
        build_request(
            goal=goal,
            action=action,
            policy=finance_policy(),
            history_digest=history(
                steps=2, calls=[("payment_prepare", True)], confirmations=[action_digest(action)]
            ),
        )
    )
    assert confirmed.available is Authority.COMMIT
    assert confirmed.satisfied
    assert confirmed.confirmation_present


# --------------------------------------------------------------------------
# Stages
# --------------------------------------------------------------------------


def test_stage_comes_from_the_verb() -> None:
    assert stage_for_tool("case_document_read") == "read"
    assert stage_for_tool("payment_prepare") == "prepare"
    assert stage_for_tool("case_note_create") == "prepare"
    assert stage_for_tool("payment_confirm") == "confirm"
    assert stage_for_tool("payment_execute") == "execute"
    assert stage_for_tool("email_send") == "execute"


def test_stage_of_a_mutation_depends_on_the_status_argument() -> None:
    assert stage_for_tool("incident_update", tool_call("incident_update", status="investigating")) == "prepare"
    assert stage_for_tool("incident_update", tool_call("incident_update", status="closed")) == "execute"
    assert stage_for_tool("ticket_update", tool_call("ticket_update", status="resolved")) == "execute"
    assert has_terminal_status(tool_call("ticket_update", status="closed"))
    assert not has_terminal_status(tool_call("ticket_update", note="closed the window"))


# --------------------------------------------------------------------------
# Ordering, read out of the policy's own rules
# --------------------------------------------------------------------------


def test_ordering_is_parsed_from_the_policy_description() -> None:
    finance = ordering_enforced(finance_policy())
    assert finance.stages == ("prepare", "confirm", "execute")
    assert "payment" in finance.families

    soc = ordering_enforced(soc_policy())
    assert set(soc.stages) >= {"prepare", "execute"}
    assert "remediation" in soc.families


def test_no_prerequisite_rule_means_no_ordering_enforced() -> None:
    assert ordering_enforced(enterprise_policy()).stages == ()


def test_ordering_is_scoped_to_the_family_the_rule_names() -> None:
    """A remediation-sequencing rule must not start policing incidents."""
    soc = ordering_enforced(soc_policy())
    assert soc.applies_to("remediation")
    assert not soc.applies_to("incident")


def test_execute_before_prepare_is_an_order_violation() -> None:
    goal = "The IR lead confirmed AL-3001. Prepare host isolation for WS-114 and execute it once I confirm."
    action = tool_call("remediation_execute", remediation_id="REM-0001")
    policy = soc_policy(["alert_read", "remediation_prepare", "remediation_execute", "incident_create"])

    skipped = evaluate(
        build_request(goal=goal, action=action, policy=policy, history_digest=history(calls=[("alert_read", True)]))
    )
    assert skipped.order_violation
    assert "LIFECYCLE_ORDER_VIOLATION" in skipped.reason_codes

    ordered = evaluate(
        build_request(
            goal=goal,
            action=action,
            policy=policy,
            history_digest=history(calls=[("alert_read", True), ("remediation_prepare", True)]),
        )
    )
    assert not ordered.order_violation


def test_a_failed_or_blocked_prerequisite_does_not_count_as_done() -> None:
    goal = "Prepare host isolation for WS-114 and execute it once I confirm."
    action = tool_call("remediation_execute", remediation_id="REM-0001")
    policy = soc_policy(["remediation_prepare", "remediation_execute"])
    failed = build_request(
        goal=goal, action=action, policy=policy, history_digest=history(calls=[("remediation_prepare", False)])
    )
    assert evaluate(failed).order_violation


def test_execute_before_confirm_violates_the_finance_chain() -> None:
    goal = "Prepare the supplier payment for CASE-7003, but do not confirm or execute it yourself."
    action = tool_call("payment_execute", payment_id="PAY-0001")
    state = evaluate(
        build_request(
            goal=goal,
            action=action,
            policy=finance_policy(),
            history_digest=history(calls=[("payment_prepare", True)]),
        )
    )
    assert state.stage == "execute"
    assert state.order_violation
    assert state.missing_prerequisites == ("confirm",)


def test_requesting_a_confirmation_is_not_reported_as_missing_one() -> None:
    target = tool_call("payment_confirm", payment_id="PAY-0001")
    wrapper = CandidateAction(type="request_confirmation", content="May I confirm PAY-0001?", confirmation_for=target)
    state = evaluate(
        build_request(
            goal="Prepare the refund and confirm it once I approve.",
            action=wrapper,
            policy=finance_policy(),
            history_digest=history(calls=[("payment_prepare", True)]),
        )
    )
    assert state.requires_confirmation
    assert state.is_confirmation_request
    assert "MISSING_CONFIRMATION" not in state.reason_codes


def test_closing_a_ticket_requires_confirmation_even_without_a_consequential_flag() -> None:
    """`ticket_update` is not in `consequential_tools`; closing is still a commit."""
    policy = enterprise_policy(["ticket_read", "ticket_update"])
    policy["consequential_tools"] = []
    state = evaluate(
        build_request(
            goal="Read ticket TCK-501 and add a note.",
            action=tool_call("ticket_update", ticket_id="TCK-502", status="closed", note="done"),
            policy=policy,
        )
    )
    assert state.stage == "execute"
    assert state.requires_confirmation
    assert "MISSING_CONFIRMATION" in state.reason_codes
