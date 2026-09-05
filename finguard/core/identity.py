"""Identity and authority domain models for FIN//GUARD.

SECURITY PRINCIPLE:
- Authentication (knowing who an actor is) does NOT imply authorization (authority to move money).
- Actors have explicit roles, permissions, transaction limits, and destination allowlists.
"""

from typing import Optional, Any
from pydantic import BaseModel, Field

from finguard.core.enums import ActorType, Currency


class Authority(BaseModel):
    """Authority constraints associated with an actor."""

    max_transaction_amount: float = Field(default=50000.0)
    currency: Currency = Currency.INR
    allowed_destinations: list[str] = Field(default_factory=list)  # Empty means all destinations allowed unless constrained
    allowed_actions: list[str] = Field(default_factory=lambda: ["tx:create"])
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)


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
