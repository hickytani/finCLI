"""Unit tests for exact Money value object (finguard/money.py)."""

import pytest

from finguard.core.enums import Currency
from finguard.money import Money


def test_money_constructor_valid():
    m = Money(minor_units=50000, currency=Currency.USD)
    assert m.minor_units == 50000
    assert m.currency_str == "USD"
    assert m.exponent == 2
    assert m.to_decimal_string() == "500.00"


def test_money_from_decimal_valid():
    m1 = Money.from_decimal("500.00", Currency.USD)
    assert m1.minor_units == 50000

    m2 = Money.from_decimal("0.01", Currency.USD)
    assert m2.minor_units == 1

    m3 = Money.from_decimal("500", Currency.USD)
    assert m3.minor_units == 50000

    m4 = Money.from_decimal(100, Currency.INR)
    assert m4.minor_units == 10000


def test_money_jpy_zero_exponent():
    m = Money.from_decimal("500", "JPY")
    assert m.exponent == 0
    assert m.minor_units == 500
    assert m.to_decimal_string() == "500"


def test_money_kwd_three_exponent():
    m = Money.from_decimal("5.125", "KWD")
    assert m.exponent == 3
    assert m.minor_units == 5125
    assert m.to_decimal_string() == "5.125"


def test_money_rejects_floats():
    with pytest.raises(TypeError, match="Floating-point numbers are forbidden"):
        Money.from_decimal(500.00, Currency.USD)

    with pytest.raises(TypeError, match="must be an integer"):
        Money(500.0, Currency.USD)  # type: ignore


def test_money_rejects_booleans():
    with pytest.raises(TypeError, match="Boolean value cannot be parsed"):
        Money.from_decimal(True, Currency.USD)

    with pytest.raises(TypeError, match="must be an integer"):
        Money(True, Currency.USD)  # type: ignore


def test_money_rejects_excess_precision():
    with pytest.raises(ValueError, match="excess precision"):
        Money.from_decimal("0.001", Currency.USD)

    with pytest.raises(ValueError, match="excess precision"):
        Money.from_decimal("10.0001", Currency.INR)


def test_money_rejects_nan_and_infinity():
    for hostile in ["NaN", "nan", "Infinity", "-Infinity", "inf"]:
        with pytest.raises(ValueError):
            Money.from_decimal(hostile, Currency.USD)


def test_money_rejects_hostile_notations():
    hostile_inputs = [
        "5e2", "5E2", "1_000", " 500.00 ", "500.00 USD", "$500", "-0",
        "00.00", "000500.00", "0.0000001", "999999999999999999999999",
        "١٢.٣٤", "−1.00", "1,00", "1e+", "null", "None",
    ]
    for inp in hostile_inputs:
        with pytest.raises(ValueError):
            Money.from_decimal(inp, Currency.USD)


@pytest.mark.parametrize("hostile", [None, [], {}, True, False, 500.0])
def test_money_rejects_non_decimal_input_types(hostile):
    with pytest.raises((TypeError, ValueError)):
        Money.from_decimal(hostile, Currency.USD)


def test_money_rejects_unknown_currency_and_is_immutable():
    with pytest.raises(ValueError, match="Unsupported currency"):
        Money.from_decimal("1.00", "XXX")
    money = Money(100, Currency.USD)
    with pytest.raises(AttributeError, match="immutable"):
        money._minor_units = 200


def test_money_rejects_zero_and_negative():
    with pytest.raises(ValueError, match="must be strictly positive"):
        Money(0, Currency.USD)

    with pytest.raises(ValueError, match="must be strictly positive"):
        Money(-100, Currency.USD)


def test_money_equality_and_comparison():
    m1 = Money(50000, Currency.USD)
    m2 = Money(50000, Currency.USD)
    m3 = Money(60000, Currency.USD)

    assert m1 == m2
    assert m1 != m3
    assert m1 < m3
    assert m3 > m1
    assert m1 <= m2


def test_money_arithmetic():
    m1 = Money(50000, Currency.USD)
    m2 = Money(25000, Currency.USD)

    added = m1 + m2
    assert added.minor_units == 75000
    assert added.to_decimal_string() == "750.00"

    subbed = m1 - m2
    assert subbed.minor_units == 25000
    assert subbed.to_decimal_string() == "250.00"


def test_money_currency_mismatch_fails():
    m1 = Money(50000, Currency.USD)
    m2 = Money(50000, Currency.INR)

    with pytest.raises(ValueError, match="Currency mismatch"):
        _ = m1 + m2
