"""Typed Tool Registry for Financial Agents (M6).

Defines permitted agent tools, required capabilities, input/output schemas,
and structural enforcement against privileged tools (signing, approval, key access).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from finguard.agent.capabilities import FORBIDDEN_CAPABILITIES, AgentCapability


class ToolMetadata(BaseModel):
    """Metadata specification for a registered agent tool."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_name: str
    capability_required: AgentCapability
    description: str
    is_mutation: bool = False
    financial_impact: Literal["none", "proposal_only", "request_only"] = "none"
    max_permitted_calls_per_run: int = 5
    approval_required: bool = False


PROHIBITED_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "approve_transaction",
        "sign_transaction",
        "execute_transaction",
        "grant_capability",
        "set_policy",
        "modify_authorization",
        "create_key",
        "delete_key",
        "export_key",
        "get_private_key",
    }
)


class ToolRegistry:
    """Registry managing typed, capability-guarded tools available to agents."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolMetadata] = {}
        self._handlers: dict[str, Callable[..., Any]] = {}
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        self.register_tool(
            ToolMetadata(
                tool_name="resolve_recipient",
                capability_required=AgentCapability.RESOLVE_RECIPIENT,
                description="Resolve a recipient alias to an account identifier.",
                is_mutation=False,
                financial_impact="none",
                max_permitted_calls_per_run=5,
            )
        )
        self.register_tool(
            ToolMetadata(
                tool_name="get_transaction",
                capability_required=AgentCapability.READ_TRANSACTION,
                description="Retrieve transaction details by transaction ID.",
                is_mutation=False,
                financial_impact="none",
                max_permitted_calls_per_run=10,
            )
        )
        self.register_tool(
            ToolMetadata(
                tool_name="list_transactions",
                capability_required=AgentCapability.READ_TRANSACTION,
                description="List recent transactions for the authenticated actor.",
                is_mutation=False,
                financial_impact="none",
                max_permitted_calls_per_run=10,
            )
        )
        self.register_tool(
            ToolMetadata(
                tool_name="propose_transaction",
                capability_required=AgentCapability.PROPOSE_TRANSACTION,
                description="Propose a non-authoritative financial transaction for policy evaluation.",
                is_mutation=True,
                financial_impact="proposal_only",
                max_permitted_calls_per_run=3,
                approval_required=True,
            )
        )
        self.register_tool(
            ToolMetadata(
                tool_name="request_approval",
                capability_required=AgentCapability.REQUEST_APPROVAL,
                description="Request out-of-band human approval for a pending transaction receipt.",
                is_mutation=True,
                financial_impact="request_only",
                max_permitted_calls_per_run=3,
            )
        )
        self.register_tool(
            ToolMetadata(
                tool_name="get_audit_proof",
                capability_required=AgentCapability.READ_TRANSACTION,
                description="Get cryptographic audit proof for a ledger sequence.",
                is_mutation=False,
                financial_impact="none",
                max_permitted_calls_per_run=5,
            )
        )

    def register_tool(self, metadata: ToolMetadata, handler: Callable[..., Any] | None = None) -> None:
        """Register a tool. Rejects any attempt to register a prohibited or authority tool."""
        normalized = metadata.tool_name.strip().lower()
        if normalized in PROHIBITED_TOOL_NAMES or any(f in normalized for f in FORBIDDEN_CAPABILITIES):
            raise ValueError(f"Tool '{metadata.tool_name}' is privileged and cannot be registered in the agent registry.")
        self._tools[normalized] = metadata
        if handler:
            self._handlers[normalized] = handler

    def get_tool(self, tool_name: str) -> ToolMetadata | None:
        """Retrieve tool metadata by name."""
        return self._tools.get(tool_name.strip().lower())

    def is_tool_permitted(self, tool_name: str, granted_capabilities: frozenset[AgentCapability]) -> bool:
        """Check if a tool is registered AND caller holds the required capability."""
        tool = self.get_tool(tool_name)
        if not tool:
            return False
        return tool.capability_required in granted_capabilities

    def list_permitted_tools(self, granted_capabilities: frozenset[AgentCapability]) -> list[ToolMetadata]:
        """List all tools accessible under the given capability set."""
        return [
            tool for tool in self._tools.values()
            if tool.capability_required in granted_capabilities
        ]
