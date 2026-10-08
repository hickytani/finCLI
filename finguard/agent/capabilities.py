"""Agent Capability Model for FIN//GUARD (M6).

Defines typed, server-configured, deny-by-default capabilities for financial agents.
Crucially, capabilities are immutable during an orchestration run. Neither LLM output,
tool output, nor replanning can grant, elevate, or modify agent capabilities.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class AgentCapability(str, Enum):
    """Permitted, granular capabilities for autonomous financial agents."""

    READ_ACCOUNT = "account.read"
    READ_TRANSACTION = "transaction.read"
    RESOLVE_RECIPIENT = "recipient.resolve"
    PROPOSE_TRANSACTION = "transaction.propose"
    REQUEST_APPROVAL = "approval.request"
    ANALYZE_TRANSACTION = "transaction.analyze"


# Explicitly forbidden capabilities that NO agent can ever possess
FORBIDDEN_CAPABILITIES: frozenset[str] = frozenset(
    {
        "approve_transaction",
        "sign_transaction",
        "execute_transaction",
        "grant_capability",
        "change_policy",
        "change_limit",
        "change_identity",
        "change_signer",
        "access_private_key",
    }
)


class AgentCapabilityProfile(BaseModel):
    """Immutable capability specification for an agent orchestration run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    actor_id: str
    granted_capabilities: frozenset[AgentCapability] = Field(
        default_factory=lambda: frozenset({AgentCapability.READ_ACCOUNT, AgentCapability.RESOLVE_RECIPIENT, AgentCapability.PROPOSE_TRANSACTION})
    )
    max_single_tx_limit_minor: int = Field(default=10_000_00, ge=0)  # INR 10,000.00 default

    def has_capability(self, capability: AgentCapability | str) -> bool:
        """Check if a capability is explicitly granted."""
        if isinstance(capability, str):
            try:
                capability = AgentCapability(capability)
            except ValueError:
                return False
        return capability in self.granted_capabilities

    def is_permitted_amount(self, amount_minor: int) -> bool:
        """Check if an amount is within the configured single-transaction ceiling."""
        return 0 <= amount_minor <= self.max_single_tx_limit_minor
