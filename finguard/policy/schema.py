"""YAML Policy configuration schema for FIN//GUARD.

Supports declarative policy-as-code:
- Maximum transaction amounts
- Destination allowlists
- Velocity limits
- Required approval thresholds & quorums
- Actor / Agent-specific constraints
"""

from typing import Optional
from pydantic import BaseModel, Field, field_validator

from finguard.core.enums import Currency
from finguard.money import Money


def _exact_policy_amount(value: object, currency: Currency) -> str:
    if isinstance(value, float):
        value = str(value)
    money = Money.from_decimal(value, currency)
    return money.to_decimal_string()


class MaxAmountPolicy(BaseModel):
    """Max transaction amount rule config."""
    currency: Currency = Currency.INR
    amount: str | int = Field(default="50000.00")

    @field_validator("amount", mode="before")
    @classmethod
    def amount_is_exact(cls, value: object) -> object:
        if isinstance(value, float):
            return str(value)
        return value

    @field_validator("amount")
    @classmethod
    def amount_has_currency_precision(cls, value: str | int, info):
        currency = info.data.get("currency", Currency.INR)
        return _exact_policy_amount(value, currency)


class VelocityPolicy(BaseModel):
    """Velocity limit rule config."""
    count: int = Field(default=5)
    window_seconds: int = Field(default=600)
    max_cumulative_amount: Optional[str | int] = None


class ApprovalPolicy(BaseModel):
    """Approval requirement rule config."""
    currency: Currency = Currency.INR
    required_above: str | int = Field(default="25000.00")
    required_approvals: int = Field(default=2)

    @field_validator("required_above", mode="before")
    @classmethod
    def required_above_is_exact(cls, value: object) -> object:
        return str(value) if isinstance(value, float) else value

    @field_validator("required_above")
    @classmethod
    def required_above_has_currency_precision(cls, value: str | int, info):
        return _exact_policy_amount(value, info.data.get("currency", Currency.INR))


class AgentPolicyConfig(BaseModel):
    """Agent-specific policy constraints."""
    currency: Currency = Currency.INR
    max_amount: str | int = Field(default="10000.00")
    allowed_destinations: list[str] = Field(default_factory=list)

    @field_validator("max_amount", mode="before")
    @classmethod
    def max_amount_is_exact(cls, value: object) -> object:
        return str(value) if isinstance(value, float) else value

    @field_validator("max_amount")
    @classmethod
    def max_amount_has_currency_precision(cls, value: str | int, info):
        return _exact_policy_amount(value, info.data.get("currency", Currency.INR))


class PolicyConfig(BaseModel):
    """Root policy configuration schema."""

    policy_id: str
    version: int = 1
    description: Optional[str] = None
    max_amount: Optional[MaxAmountPolicy] = None
    allowed_destinations: list[str] = Field(default_factory=list)
    velocity: Optional[VelocityPolicy] = None
    approval: Optional[ApprovalPolicy] = None
    agent: Optional[AgentPolicyConfig] = None
