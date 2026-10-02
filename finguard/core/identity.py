"""Identity and authority domain models for FIN//GUARD.

SECURITY PRINCIPLE:
- Authentication (knowing who an actor is) does NOT imply authorization (authority to move money).
- Actors have explicit roles, permissions, transaction limits, and destination allowlists.
"""

from typing import Optional, Any
from pydantic import BaseModel, Field

from finguard.core.enums import ActorType, Currency


class Authority(BaseModel):
    """Authority constraints associated with an actor (deny-by-default)."""

    max_transaction_amount: str | int = Field(default="50000.00")
    currency: Currency = Currency.INR
    allowed_destinations: list[str] = Field(default_factory=list)  # Empty list means DENY ALL
    allowed_source_accounts: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=lambda: ["tx:create"])
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)

    @property
    def max_transaction_amount_minor(self) -> int:
        from finguard.money import Money
        return Money.from_decimal(self.max_transaction_amount, self.currency).minor_units


class Actor(BaseModel):
    """Actor identity record."""

    actor_id: str
    actor_type: ActorType
    display_name: Optional[str] = None
    authority: Authority = Field(default_factory=Authority)
    active: bool = True


class Session(BaseModel):
    """Active session metadata."""

    session_id: str
    actor_id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: Optional[str] = None
