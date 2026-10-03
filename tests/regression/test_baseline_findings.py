"""Promoted security regression tests for FG-201..FG-206.

These tests prove that defects FG-201 through FG-206 are permanently fixed:
- FG-201: Money exactness & canonical v2 signature binding
- FG-202: NaN boundary rejection
- FG-203: Deny-by-default Authority
- FG-205: Minor-unit integer simulator balances
- FG-206: Bound metadata digest in canonical v2
"""

import datetime

import pytest

from finguard.core.authority import evaluate_authority
from finguard.core.enums import ActorType
from finguard.core.identity import Actor, Authority
from finguard.core.transaction import Transaction

FIXED_TS = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)


def make_tx(amount, to_account="vendor-a", metadata=None):
    return Transaction(
        transaction_id="tx_fixed",
        actor_id="agent-1",
        from_account="treasury",
        to_account=to_account,
        amount=amount,
        nonce="0" * 32,
        timestamp=FIXED_TS,
        metadata=metadata,
    )


def test_distinct_amounts_never_share_a_signed_hash():
    try:
        a, b = make_tx(100.001), make_tx(100.004)
    except (ValueError, TypeError):
        return  # Rejecting excess precision at boundary is a valid fix
    assert a.transaction_hash() != b.transaction_hash()


def test_positive_amount_never_signs_as_zero():
    try:
        tx = make_tx(0.001)
    except (ValueError, TypeError):
        return  # Rejecting excess precision at boundary is a valid fix
    assert str(tx.canonical_fields()["amount_minor"]) != "0"


def test_signed_amount_equals_executed_amount():
    try:
        tx = make_tx(50000.004)
    except (ValueError, TypeError):
        return  # Rejecting excess precision at boundary is a valid fix
    assert tx.canonical_fields()["amount_minor"] == tx.amount_minor


def test_nan_amount_is_rejected_at_the_boundary():
    with pytest.raises((ValueError, TypeError)):
        make_tx(float("nan"))


@pytest.mark.parametrize("hostile", [float("inf"), float("-inf"), float("nan"), 0.001, 500.0, True])
def test_invalid_numeric_forms_cannot_enter_transaction_boundary(hostile):
    with pytest.raises((ValueError, TypeError)):
        make_tx(hostile)


def test_default_authority_does_not_allow_arbitrary_destinations():
    actor = Actor(actor_id="agent-1", actor_type=ActorType.AGENT, authority=Authority())
    decision = evaluate_authority(actor, make_tx("10.00", to_account="attacker-controlled-account"))
    assert decision.allowed is False


def test_authority_requires_explicit_source_and_action_grants():
    actor = Actor(
        actor_id="operator-1",
        actor_type=ActorType.HUMAN_OPERATOR,
        authority=Authority(
            max_transaction_amount="100.00",
            allowed_destinations=["vendor-a"],
            allowed_source_accounts=[],
            allowed_actions=[],
        ),
    )
    decision = evaluate_authority(actor, make_tx("10.00", to_account="vendor-a"))
    assert decision.allowed is False
    assert any("source" in reason.lower() for reason in decision.reasons)
    assert any("action" in reason.lower() for reason in decision.reasons)


def test_agent_cannot_use_wildcard_authority():
    actor = Actor(
        actor_id="agent-1",
        actor_type=ActorType.AGENT,
        authority=Authority(
            max_transaction_amount="100.00",
            allowed_destinations=["*"],
            allowed_source_accounts=["*"],
            allowed_actions=["*"],
        ),
    )
    decision = evaluate_authority(actor, make_tx("10.00"))
    assert decision.allowed is False
    assert any("wildcard" in reason.lower() for reason in decision.reasons)
    with pytest.raises(ValueError, match="not an account identifier"):
        make_tx("10.00", to_account="*")


def test_operator_wildcard_authority_is_allowed_and_emits_signal():
    actor = Actor(
        actor_id="operator-1",
        actor_type=ActorType.HUMAN_OPERATOR,
        authority=Authority(
            max_transaction_amount="100.00",
            allowed_destinations=["*"],
            allowed_source_accounts=["*"],
            allowed_actions=["*"],
        ),
    )
    decision = evaluate_authority(actor, make_tx("10.00"))
    assert decision.allowed is True
    assert "WILDCARD_AUTHORITY_USED" in decision.signals


def test_simulator_balances_must_not_use_float_arithmetic():
    from sqlalchemy import BigInteger

    from finguard.storage.models import SimulatorAccountRecord
    assert isinstance(SimulatorAccountRecord.balance_minor.type, BigInteger)


def test_metadata_must_be_bound_to_transaction_hash():
    tx1 = make_tx("100.00", metadata={"purpose": "payroll"})
    tx2 = make_tx("100.00", metadata={"purpose": "ransomware_payment"})
    assert tx1.transaction_hash() != tx2.transaction_hash()
