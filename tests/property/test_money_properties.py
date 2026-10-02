"""Property-based tests for Money and Canonical v2 using Hypothesis (test_money_properties.py)."""

from hypothesis import given, strategies as st

from finguard.core.enums import Currency
from finguard.core.transaction import Transaction
from finguard.money import MAX_AMOUNT_MINOR, Money


@given(
    minor_units=st.integers(min_value=1, max_value=1_000_000_000_000),
    curr=st.sampled_from([Currency.INR, Currency.USD, Currency.EUR]),
)
def test_property_money_roundtrip(minor_units: int, curr: Currency):
    """PROPERTY: Money -> decimal string -> Money preserves exact minor units and currency."""
    m1 = Money(minor_units=minor_units, currency=curr)
    dec_str = m1.to_decimal_string()
    m2 = Money.from_decimal(dec_str, currency=curr)
    assert m1 == m2
    assert m1.minor_units == m2.minor_units


@given(
    val_int=st.integers(min_value=1, max_value=10_000_000),
    curr=st.sampled_from([Currency.INR, Currency.USD, Currency.EUR]),
)
def test_property_amount_identity_spellings(val_int: int, curr: Currency):
    """PROPERTY: Equivalent valid decimal representations ('500', '500.0', '500.00') produce identical Money."""
    s1 = str(val_int)
    s2 = f"{val_int}.0"
    s3 = f"{val_int}.00"

    m1 = Money.from_decimal(s1, currency=curr)
    m2 = Money.from_decimal(s2, currency=curr)
    m3 = Money.from_decimal(s3, currency=curr)

    assert m1 == m2 == m3
    assert m1.minor_units == m2.minor_units == m3.minor_units


@given(
    minor_a=st.integers(min_value=1, max_value=1_000_000),
    minor_b=st.integers(min_value=1, max_value=1_000_000),
    curr=st.sampled_from([Currency.INR, Currency.USD, Currency.EUR]),
)
def test_property_money_arithmetic_exactness(minor_a: int, minor_b: int, curr: Currency):
    """PROPERTY: Money addition and subtraction preserve exact integer arithmetic."""
    ma = Money(minor_units=minor_a, currency=curr)
    mb = Money(minor_units=minor_b, currency=curr)

    added = ma + mb
    assert added.minor_units == minor_a + minor_b

    if minor_a > minor_b:
        subbed = ma - mb
        assert subbed.minor_units == minor_a - minor_b


@given(
    tx_id=st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", min_size=1, max_size=20),
    amount_int=st.integers(min_value=1, max_value=100000),
)
def test_property_canonical_v2_determinism(tx_id: str, amount_int: int):
    """PROPERTY: Repeated canonical v2 serialization produces identical bytes with domain prefix."""
    tx = Transaction(
        transaction_id=f"tx_{tx_id}",
        actor_id="agent-1",
        from_account="acc_a",
        to_account="acc_b",
        amount=amount_int,
        currency=Currency.USD,
    )
    b1 = tx.canonical_bytes(version=2)
    b2 = tx.canonical_bytes(version=2)

    assert b1 == b2
    assert b1.startswith(b"finguard.tx.v2\x00")
    assert b"amount_minor" in b1
    assert b"canonical_version" in b1


@given(value=st.text(max_size=120))
def test_property_arbitrary_text_never_changes_value_silently(value: str):
    """Any accepted spelling must normalize to one stable decimal representation."""
    try:
        money = Money.from_decimal(value, Currency.USD)
    except (TypeError, ValueError):
        return
    assert Money.from_decimal(money.to_decimal_string(), Currency.USD) == money


@given(
    left=st.integers(min_value=1, max_value=MAX_AMOUNT_MINOR),
    right=st.integers(min_value=1, max_value=MAX_AMOUNT_MINOR),
)
def test_property_distinct_minor_units_have_distinct_v2_bytes(left: int, right: int):
    if left == right:
        return
    shared = {
        "transaction_id": "tx_prop",
        "actor_id": "actor",
        "from_account": "src",
        "to_account": "dst",
        "currency": Currency.USD,
    }
    first = Transaction(**shared, amount=Money(left, Currency.USD))
    second = Transaction(**shared, amount=Money(right, Currency.USD))
    assert first.canonical_bytes() != second.canonical_bytes()
