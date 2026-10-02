import pytest

from finguard.core.enums import TransactionState
from finguard.core.state_machine import InvalidTransitionError, TransactionStateMachine
from finguard.core.transaction import Transaction
from finguard.money import Money


def _tx() -> Transaction:
    return Transaction(
        actor_id="actor-1",
        from_account="treasury",
        to_account="vendor-a",
        amount=Money(minor_units=5000, currency="INR"),
        currency="INR",
    )


def test_transaction_state_machine_rejects_invalid_transition() -> None:
    tx = _tx()

    with pytest.raises(InvalidTransitionError):
        tx.transition_to(TransactionState.EXECUTED)

    tx.transition_to(TransactionState.PENDING_APPROVAL)
    assert tx.state == TransactionState.PENDING_APPROVAL
    assert tx.version == 2


def test_transaction_state_machine_requires_expected_version() -> None:
    tx = _tx()
    tx.transition_to(TransactionState.PENDING_APPROVAL)

    with pytest.raises(InvalidTransitionError, match="expected version"):
        tx.transition_to(TransactionState.APPROVED, expected_version=1)

    tx.transition_to(TransactionState.APPROVED, expected_version=2)
    assert tx.state == TransactionState.APPROVED
