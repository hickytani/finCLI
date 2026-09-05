"""YAML Policy configuration schema for FIN//GUARD.

Supports declarative policy-as-code:
- Maximum transaction amounts
- Destination allowlists
- Velocity limits
- Required approval thresholds & quorums
- Actor / Agent-specific constraints
"""

from typing import Optional
from pydantic import BaseModel, Field

from finguard.core.enums import Currency


class MaxAmountPolicy(BaseModel):
    """Max transaction amount rule config."""
    amount: float = Field(default=50000.0)
    currency: Currency = Currency.INR


class VelocityPolicy(BaseModel):
    """Velocity limit rule config."""
    count: int = Field(default=5)
    window_seconds: int = Field(default=600)
    max_cumulative_amount: Optional[float] = None


class ApprovalPolicy(BaseModel):
    """Approval requirement rule config."""
    required_above: float = Field(default=25000.0)
    currency: Currency = Currency.INR
    required_approvals: int = Field(default=2)


class AgentPolicyConfig(BaseModel):
    """Agent-specific policy constraints."""
    max_amount: float = Field(default=10000.0)
    currency: Currency = Currency.INR
    allowed_destinations: list[str] = Field(default_factory=list)


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
