"""Authoritative Money Value Object and Currency Exponents for FIN//GUARD.

SECURITY PROPERTIES:
- Monetary amounts are strictly represented as (minor_units: int, currency: Currency).
- Binary floating-point numbers (float) are NEVER accepted as authoritative money.
- Parsing from decimal strings/integers uses exact decimal arithmetic without rounding.
- Excess precision (e.g. 0.001 for 2-exponent currencies), NaN, Infinity, negative zero,
  and boolean values are rejected at the boundary.
"""

import re
from decimal import Decimal
from enum import Enum
from typing import Any, Self

from pydantic import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema

from finguard.core.enums import Currency
from finguard.core.errors import ExcessPrecisionError, UnsupportedCurrencyError

# Per-currency minor unit exponent lookup table
CURRENCY_EXPONENTS: dict[Currency, int] = {
    Currency.INR: 2,
    Currency.USD: 2,
    Currency.EUR: 2,
    Currency.JPY: 0,
    Currency.KWD: 3,
}

_DECIMAL_SYNTAX = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z", re.ASCII)

MAX_AMOUNT_MINOR = 1_000_000_000_000_000  # 10^15 minor units cap (~10 trillion major)


def get_currency_exponent(currency: Currency | str) -> int:
    """Return the configured minor-unit exponent; unknown currencies fail closed."""
    try:
        currency_value = currency if isinstance(currency, Currency) else Currency(currency.upper())
        return CURRENCY_EXPONENTS[currency_value]
    except (AttributeError, KeyError, ValueError) as exc:
        raise UnsupportedCurrencyError("Unsupported currency") from exc


class Money:
    """Immutable authoritative monetary value object.

    Uses integer minor units and explicit Currency.
    """

    __slots__ = ("_currency", "_minor_units")

    def __init__(self, minor_units: int, currency: Currency | str):
        if isinstance(minor_units, bool) or not isinstance(minor_units, int):
            raise TypeError("minor_units must be an integer (booleans and floats are forbidden)")

        get_currency_exponent(currency)
        if minor_units <= 0:
            raise ValueError("Monetary amount must be strictly positive")

        if minor_units > MAX_AMOUNT_MINOR:
            raise ValueError(f"Monetary amount exceeds maximum limit ({MAX_AMOUNT_MINOR})")

        curr_obj = currency if isinstance(currency, Currency) else Currency(currency.upper())
        object.__setattr__(self, "_minor_units", minor_units)
        object.__setattr__(self, "_currency", curr_obj)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("Money values are immutable")

    @property
    def minor_units(self) -> int:
        return self._minor_units

    @property
    def currency(self) -> Currency | str:
        return self._currency

    @property
    def currency_str(self) -> str:
        return self._currency.value if isinstance(self._currency, Enum) else str(self._currency)

    @property
    def exponent(self) -> int:
        return get_currency_exponent(self._currency)

    @classmethod
    def from_decimal(cls, value: str | int | Decimal, currency: Currency | str) -> Self:
        """Parse a human-readable numeric input into a Money object using exact decimal arithmetic.

        Rejects floats, NaN, Infinity, excess decimal places, booleans, and malformed strings.
        """
        if isinstance(value, bool):
            raise TypeError("Boolean value cannot be parsed as money")
        if isinstance(value, float):
            raise TypeError("Floating-point numbers are forbidden in money paths")
        if not isinstance(value, (str, int, Decimal)):
            raise TypeError(f"Invalid input type for Money: {type(value).__name__}")

        exponent = get_currency_exponent(currency)
        value_text = str(value)
        if len(value_text) > 64:
            raise ValueError("Amount exceeds the supported input length")
        if isinstance(value, Decimal) and not value.is_finite():
            raise ValueError("Non-finite monetary amounts are forbidden")
        if value_text.casefold() in {"nan", "infinity", "-infinity", "+infinity", "inf", "-inf", "+inf"}:
            raise ValueError("Non-finite monetary amounts are forbidden")
        if not _DECIMAL_SYNTAX.fullmatch(value_text):
            raise ValueError("Invalid decimal amount syntax")

        whole, separator, fraction = value_text.partition(".")
        if separator and len(fraction) > exponent:
            raise ExcessPrecisionError("Amount has excess precision for its currency")

        scale = 10 ** exponent
        fractional_minor = int(fraction.ljust(exponent, "0")) if fraction else 0
        minor_units = int(whole) * scale + fractional_minor
        return cls(minor_units=minor_units, currency=currency)

    def to_decimal_string(self) -> str:
        """Format Money into authoritative decimal string representation."""
        exp = self.exponent
        if exp == 0:
            return str(self._minor_units)
        
        factor = 10 ** exp
        integer_part = self._minor_units // factor
        fractional_part = self._minor_units % factor
        return f"{integer_part}.{fractional_part:0{exp}d}"

    def __repr__(self) -> str:
        return f"Money({self.to_decimal_string()} {self.currency_str}, minor={self._minor_units})"

    def __str__(self) -> str:
        return self.to_decimal_string()

    def __format__(self, format_spec: str) -> str:
        return format(Decimal(self.to_decimal_string()), format_spec)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Money):
            return False
        return self._minor_units == other._minor_units and self.currency_str == other.currency_str

    def __hash__(self) -> int:
        return hash((self._minor_units, self.currency_str))

    def __lt__(self, other: "Money") -> bool:
        self._check_currency(other)
        return self._minor_units < other._minor_units

    def __le__(self, other: "Money") -> bool:
        self._check_currency(other)
        return self._minor_units <= other._minor_units

    def __gt__(self, other: "Money") -> bool:
        self._check_currency(other)
        return self._minor_units > other._minor_units

    def __ge__(self, other: "Money") -> bool:
        self._check_currency(other)
        return self._minor_units >= other._minor_units

    def __add__(self, other: "Money") -> "Money":
        self._check_currency(other)
        return Money(minor_units=self._minor_units + other._minor_units, currency=self._currency)

    def __sub__(self, other: "Money") -> "Money":
        self._check_currency(other)
        diff = self._minor_units - other._minor_units
        if diff <= 0:
            raise ValueError("Subtraction resulting in zero or negative money is rejected")
        return Money(minor_units=diff, currency=self._currency)

    def _check_currency(self, other: "Money") -> None:
        if not isinstance(other, Money):
            raise TypeError(f"Cannot operate Money with {type(other).__name__}")
        if self.currency_str != other.currency_str:
            raise ValueError(f"Currency mismatch: {self.currency_str} vs {other.currency_str}")

    # Pydantic v2 integration
    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        def validate(val: Any) -> Money:
            if isinstance(val, Money):
                return val
            if isinstance(val, dict):
                if "minor_units" in val and "currency" in val:
                    minor_units = val["minor_units"]
                    if isinstance(minor_units, bool) or not isinstance(minor_units, int):
                        raise TypeError("minor_units must be an integer")
                    return cls(minor_units=minor_units, currency=val["currency"])
                if "amount" in val and "currency" in val:
                    return cls.from_decimal(val["amount"], val["currency"])
            if isinstance(val, str):
                parts = val.split()
                if len(parts) == 2:
                    return cls.from_decimal(parts[0], parts[1])
            raise ValueError(f"Cannot parse {val!r} into Money object")

        return core_schema.no_info_plain_validator_function(
            validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda m: m.to_decimal_string()
            ),
        )
