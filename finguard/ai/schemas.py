"""Strict, non-authoritative schemas for local model output."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from finguard.money import Money


class AIAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_level: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    signals: list[str] = Field(default_factory=list, max_length=10)
    reason: str = Field(min_length=1, max_length=1000)


class TransactionExtraction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    amount: str | int = Field()
    currency: Literal["INR", "USD", "EUR"] = "INR"
    destination: str = Field(min_length=1, max_length=128)
    purpose: str = Field(min_length=1, max_length=256)
    analysis: AIAnalysis

    @field_validator("amount", mode="before")
    @classmethod
    def amount_is_bounded_decimal_input(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise TypeError("amount must be a decimal string or integer")
        if len(str(value)) > 64:
            raise ValueError("amount exceeds the supported input length")
        return value

    @model_validator(mode="after")
    def amount_must_be_exact(self) -> "TransactionExtraction":
        money = Money.from_decimal(self.amount, self.currency)
        if money.minor_units > 1_000_000_000:
            raise ValueError("amount exceeds extraction limit")
        self.amount = money.to_decimal_string()
        return self

    @field_validator("destination")
    @classmethod
    def destination_must_be_explicit(cls, value: str) -> str:
        value = value.strip()
        if value.lower() in {"unknown", "none", "null", "unresolved", "undefined"}:
            raise ValueError("destination is ambiguous or absent")
        return value
