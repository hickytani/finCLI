"""Strict, non-authoritative schemas for local model output."""
from typing import Literal
from pydantic import BaseModel, Field, field_validator


class AIAnalysis(BaseModel):
    risk_level: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    signals: list[str] = Field(default_factory=list, max_length=10)
    reason: str = Field(min_length=1, max_length=1000)


class TransactionExtraction(BaseModel):
    amount: float = Field(gt=0, le=10_000_000)
    currency: Literal["INR", "USD", "EUR"] = "INR"
    destination: str = Field(min_length=1, max_length=128)
    purpose: str = Field(min_length=1, max_length=256)
    analysis: AIAnalysis

    @field_validator("destination")
    @classmethod
    def destination_must_be_explicit(cls, value: str) -> str:
        # Names such as "Rahul" are ambiguous; FinGuard requires an account ID.
        if value.strip().lower() in {"unknown", "none", "null", "rahul"}:
            raise ValueError("destination is ambiguous or absent")
        return value.strip()
