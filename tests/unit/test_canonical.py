"""Unit tests for canonical serialization and transaction hashing."""

import datetime
import json
from pathlib import Path

import pytest

from finguard.core.canonical import DOMAIN_PREFIX_V2, canonical_amount, canonical_serialize
from finguard.core.enums import Currency
from finguard.core.errors import ValidationError
from finguard.core.transaction import Transaction


def test_canonical_serialize_deterministic():
    d1 = {"b": 2, "a": 1, "c": [3, 2, 1]}
    d2 = {"a": 1, "c": [3, 2, 1], "b": 2}
    assert canonical_serialize(d1) == canonical_serialize(d2)


def test_v2_rejects_floats_and_prefixes_domain():
    assert canonical_serialize({"canonical_version": 2, "amount_minor": 1}).startswith(DOMAIN_PREFIX_V2)
    tx = Transaction(
        transaction_id="tx_float", actor_id="actor", from_account="src", to_account="dst",
        amount="1.00", currency=Currency.USD,
    )
    assert isinstance(tx.canonical_fields()["amount_minor"], int)
    with pytest.raises(TypeError):
        Transaction(actor_id="actor", from_account="src", to_account="dst", amount=1.0)


def test_canonical_amount_fixed_point():
    assert canonical_amount(1000.0) == "1000.00"
    assert canonical_amount(1000.5) == "1000.50"
    assert canonical_amount(1000) == "1000.00"


def test_transaction_canonical_hash_invariance():
    ts = datetime.datetime(2026, 9, 1, 12, 0, 0, tzinfo=datetime.UTC)
    tx1 = Transaction(
        transaction_id="TX-001",
        actor_id="actor-1",
        from_account="acc-a",
        to_account="acc-b",
        amount="5000.00",
        currency=Currency.INR,
        nonce="nonce-123",
        timestamp=ts
    )

    tx2 = Transaction(
        transaction_id="TX-001",
        actor_id="actor-1",
        from_account="acc-a",
        to_account="acc-b",
        amount="5000.00",
        currency=Currency.INR,
        nonce="nonce-123",
        timestamp=ts
    )

    assert tx1.canonical_bytes() == tx2.canonical_bytes()
    assert tx1.transaction_hash() == tx2.transaction_hash()
    assert tx1.canonical_bytes() != tx1.canonical_bytes(version=1)
    assert tx1.canonical_bytes().startswith(b"finguard.tx.v2\x00")


def test_offset_aware_timestamps_canonicalize_to_the_same_utc_instant():
    utc = datetime.datetime(2026, 1, 1, 12, tzinfo=datetime.UTC)
    offset = datetime.datetime(
        2026, 1, 1, 17, tzinfo=datetime.timezone(datetime.timedelta(hours=5))
    )
    base = {
      "transaction_id": "tx_utc", "actor_id": "actor", "from_account": "src", "to_account": "dst",
      "amount": "1.00", "currency": Currency.USD, "nonce": "nonce",
    }
    assert Transaction(**base, timestamp=utc).canonical_bytes() == Transaction(
        **base, timestamp=offset
    ).canonical_bytes()
    assert Transaction(**base, timestamp=utc).timestamp == Transaction(
        **base, timestamp=offset
    ).timestamp
    assert canonical_serialize({"timestamp": utc}, version=1) != canonical_serialize(
        {"timestamp": offset}, version=1
    )


def test_transaction_modification_changes_hash():
    ts = datetime.datetime(2026, 9, 1, 12, 0, 0, tzinfo=datetime.UTC)
    tx1 = Transaction(
        transaction_id="TX-001",
        actor_id="actor-1",
        from_account="acc-a",
        to_account="acc-b",
        amount="5000.00",
        currency=Currency.INR,
        nonce="nonce-123",
        timestamp=ts
    )

    # Modifying amount
    tx_mod_amount = tx1.model_copy(update={"amount": tx1.money.__class__.from_decimal("5000.01", Currency.INR)})
    assert tx1.transaction_hash() != tx_mod_amount.transaction_hash()

    # Modifying recipient
    tx_mod_to = tx1.model_copy(update={"to_account": "acc-c"})
    assert tx1.transaction_hash() != tx_mod_to.transaction_hash()

    # Modifying actor
    tx_mod_actor = tx1.model_copy(update={"actor_id": "actor-2"})
    assert tx1.transaction_hash() != tx_mod_actor.transaction_hash()


def test_legacy_v1_golden_vector_remains_readable():
    vector_path = Path(__file__).parents[1] / "vectors" / "canonical_v1.json"
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    tx = Transaction(
        transaction_id="tx_legacy", actor_id="actor-1", from_account="src", to_account="dst",
        amount="500.00", currency=Currency.USD, session_id=None, nonce="0000",
        timestamp=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
    )
    assert tx.canonical_bytes(version=1).hex() == vector["canonical_bytes_hex"]
    assert tx.canonical_bytes(version=1) != tx.canonical_bytes(version=2)


def test_new_transactions_cannot_select_legacy_version():
    with pytest.raises(ValidationError, match="canonical version 2"):
        Transaction(actor_id="actor", from_account="src", to_account="dst", amount="1.00", canonical_version=1)
    tx = Transaction(actor_id="actor", from_account="src", to_account="dst", amount="1.00")
    with pytest.raises(ValueError):
        tx.canonical_version = 1


@pytest.mark.parametrize("identifier", ["account\u200b1", "cafe\u0301"])
def test_signed_identifiers_reject_zero_width_and_non_nfc_text(identifier):
    with pytest.raises(ValueError):
        Transaction(actor_id="actor", from_account=identifier, to_account="dst", amount="1.00")


def test_wildcard_is_not_a_valid_account_identifier():
    with pytest.raises(ValueError, match="not an account identifier"):
        Transaction(actor_id="actor", from_account="*", to_account="dst", amount="1.00")
    with pytest.raises(ValueError, match="not an account identifier"):
        Transaction(actor_id="actor", from_account="src", to_account="*", amount="1.00")


def test_v2_rejects_non_finite_values_hidden_in_signed_metadata():
    tx = Transaction(
        actor_id="actor", from_account="src", to_account="dst", amount="1.00",
        metadata={"nested": {"risk_score": float("nan")}},
    )
    with pytest.raises(ValidationError, match="Non-finite"):
        tx.canonical_bytes()
