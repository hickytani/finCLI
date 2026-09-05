"""Unit tests for canonical serialization and transaction hashing."""

import datetime
from finguard.core.canonical import canonical_serialize, canonical_amount
from finguard.core.transaction import Transaction
from finguard.core.enums import Currency


def test_canonical_serialize_deterministic():
    d1 = {"b": 2, "a": 1, "c": [3, 2, 1]}
    d2 = {"a": 1, "c": [3, 2, 1], "b": 2}
    assert canonical_serialize(d1) == canonical_serialize(d2)


def test_canonical_amount_fixed_point():
    assert canonical_amount(1000.0) == "1000.00"
    assert canonical_amount(1000.5) == "1000.50"
    assert canonical_amount(1000) == "1000.00"


def test_transaction_canonical_hash_invariance():
    ts = datetime.datetime(2026, 9, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
    tx1 = Transaction(
        transaction_id="TX-001",
        actor_id="actor-1",
        from_account="acc-a",
        to_account="acc-b",
        amount=5000.0,
        currency=Currency.INR,
        nonce="nonce-123",
        timestamp=ts
    )

    tx2 = Transaction(
        transaction_id="TX-001",
        actor_id="actor-1",
        from_account="acc-a",
        to_account="acc-b",
        amount=5000.0,
        currency=Currency.INR,
        nonce="nonce-123",
        timestamp=ts
    )

    assert tx1.canonical_bytes() == tx2.canonical_bytes()
    assert tx1.transaction_hash() == tx2.transaction_hash()


def test_transaction_modification_changes_hash():
    ts = datetime.datetime(2026, 9, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
    tx1 = Transaction(
        transaction_id="TX-001",
        actor_id="actor-1",
        from_account="acc-a",
        to_account="acc-b",
        amount=5000.0,
        currency=Currency.INR,
        nonce="nonce-123",
        timestamp=ts
    )

    # Modifying amount
    tx_mod_amount = tx1.model_copy(update={"amount": 5000.01})
    assert tx1.transaction_hash() != tx_mod_amount.transaction_hash()

    # Modifying recipient
    tx_mod_to = tx1.model_copy(update={"to_account": "acc-c"})
    assert tx1.transaction_hash() != tx_mod_to.transaction_hash()

    # Modifying actor
    tx_mod_actor = tx1.model_copy(update={"actor_id": "actor-2"})
    assert tx1.transaction_hash() != tx_mod_actor.transaction_hash()
