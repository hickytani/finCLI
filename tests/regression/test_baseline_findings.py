"""Executable proof of defects found in the Day-1 baseline (see FINGUARD_AGENT_PROMPT_V2, Appendix A).

Each test is `xfail(strict=True)`: the suite stays green today, but the moment a
defect is actually fixed the test XPASSes, strict mode turns that into a failure,
and the fixer must delete the marker. A fix therefore cannot land without the
proof test being promoted to a normal regression test.

Contract being tested (deliberately implementation-agnostic): a value must either be
REJECTED at the boundary or be bound EXACTLY by the signed bytes. It may never be
silently altered between "what is checked/executed" and "what is signed".
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


@pytest.mark.xfail(strict=True, reason="FG-201: canonical_amount rounds to 2dp; distinct amounts share one signed hash")
def test_distinct_amounts_never_share_a_signed_hash():
    try:
        a, b = make_tx(100.001), make_tx(100.004)
    except ValueError:
        return  # rejecting excess precision at the boundary is a valid fix
    assert a.transaction_hash() != b.transaction_hash()


@pytest.mark.xfail(strict=True, reason="FG-201: a positive amount below one cent signs as 0.00")
def test_positive_amount_never_signs_as_zero():
    try:
        tx = make_tx(0.001)
    except ValueError:
        return
    assert tx.canonical_fields()["amount"] != "0.00"


@pytest.mark.xfail(strict=True, reason="FG-201: signed amount (50000.00) differs from compared/executed amount (50000.004)")
def test_signed_amount_equals_executed_amount():
    try:
        tx = make_tx(50000.004)
    except ValueError:
        return
    from decimal import Decimal

    assert Decimal(tx.canonical_fields()["amount"]) == Decimal(str(tx.amount))


@pytest.mark.xfail(strict=True, reason="FG-202: NaN passes model validation and compares False to every threshold")
def test_nan_amount_is_rejected_at_the_boundary():
    with pytest.raises(ValueError):
        make_tx(float("nan"))


@pytest.mark.xfail(strict=True, reason="FG-203: default Authority has empty allowed_destinations, which means ALLOW ALL (fail-open)")
def test_default_authority_does_not_allow_arbitrary_destinations():
    actor = Actor(actor_id="agent-1", actor_type=ActorType.AGENT, authority=Authority())
    decision = evaluate_authority(actor, make_tx(10.0, to_account="attacker-controlled-account"))
    assert decision.allowed is False


@pytest.mark.xfail(strict=True, reason="FG-205: simulator accounts and transactions store float balances causing precision drift")
def test_simulator_balances_must_not_use_float_arithmetic():
    from finguard.storage.models import SimulatorAccountRecord
    from sqlalchemy import Column, Float
    assert not isinstance(SimulatorAccountRecord.balance.type, Float)


@pytest.mark.xfail(strict=True, reason="FG-206: metadata is excluded from canonical_fields, allowing metadata tampering after signing")
def test_metadata_must_be_bound_to_transaction_hash():
    tx1 = make_tx(100.0, metadata={"purpose": "payroll"})
    tx2 = make_tx(100.0, metadata={"purpose": "ransomware_payment"})
    assert tx1.transaction_hash() != tx2.transaction_hash()
