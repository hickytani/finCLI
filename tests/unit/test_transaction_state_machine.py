import datetime

import pytest

from finguard.core.enums import TransactionState
from finguard.core.state_machine import InvalidTransitionError
from finguard.core.transaction import Transaction
from finguard.money import Money
from finguard.storage.database import get_session
from finguard.storage.models import ActorRecord, TransactionRecord
from finguard.storage.repositories import TransactionRepository


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


def test_transaction_repository_compare_and_swap_state_is_atomic() -> None:
    session = get_session()
    try:
        session.merge(ActorRecord(actor_id="cas-actor", actor_type="human", active=True))
        record = TransactionRecord(
            transaction_id="TX-CAS-1",
            actor_id="cas-actor",
            from_account="treasury",
            to_account="vendor-a",
            amount_minor=5000,
            currency="INR",
            nonce="nonce-cas-1",
            timestamp=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
            state=TransactionState.CREATED.value,
            version=1,
        )
        session.add(record)
        session.commit()

        repository = TransactionRepository(session)
        assert repository.compare_and_swap_state("TX-CAS-1", expected_version=1, new_state=TransactionState.PENDING_APPROVAL) is True
        refreshed = repository.get("TX-CAS-1")
        assert refreshed is not None
        assert refreshed.state == TransactionState.PENDING_APPROVAL.value
        assert refreshed.version == 2

        assert repository.compare_and_swap_state("TX-CAS-1", expected_version=1, new_state=TransactionState.APPROVED) is False
        assert repository.get("TX-CAS-1").state == TransactionState.PENDING_APPROVAL.value
    finally:
        session.close()


def test_transaction_repository_rejects_reused_idempotency_key_with_different_body() -> None:
    session = get_session()
    try:
        session.merge(ActorRecord(actor_id="idem-actor", actor_type="human", active=True))
        first = TransactionRecord(
            transaction_id="TX-IDEM-1",
            actor_id="idem-actor",
            from_account="treasury",
            to_account="vendor-a",
            amount_minor=5000,
            currency="INR",
            nonce="nonce-idem-1",
            idempotency_key="invoice-2026-42",
            timestamp=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
            state=TransactionState.CREATED.value,
            version=1,
        )
        session.add(first)
        session.commit()

        with pytest.raises(ValueError, match="reused idempotency key"):
            TransactionRepository(session)._assert_unique_idempotency_key("invoice-2026-42", "TX-IDEM-2", "body-2")
    finally:
        session.close()
