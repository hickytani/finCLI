"""Strict, non-authoritative schemas for local model output."""
from typing import Literal
from pydantic import BaseModel, Field, field_validator, model_validator

from finguard.money import Money


class AIAnalysis(BaseModel):
    risk_level: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    signals: list[str] = Field(default_factory=list, max_length=10)
    reason: str = Field(min_length=1, max_length=1000)


class TransactionExtraction(BaseModel):
    amount: str | int = Field()
    currency: Literal["INR", "USD", "EUR"] = "INR"
    destination: str = Field(min_length=1, max_length=128)
    purpose: str = Field(min_length=1, max_length=256)
    analysis: AIAnalysis

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
        if value.strip().lower() in {"unknown", "none", "null", "unresolved", "undefined"}:
            raise ValueError("destination is ambiguous or absent")
        return value.strip()
