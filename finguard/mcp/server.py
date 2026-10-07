"""FIN//GUARD MCP Server — M5 Secure Boundary.

Exposes ONLY:
    propose_transaction  — proposal; NOT authority
    get_decision         — read-only
    list_transactions    — read-only (actor-scoped)
    get_audit_proof      — read-only

NEVER exposes:
    approve_transaction, sign_transaction, execute_transaction,
    grant_capability, set_policy, get_private_key, export_key.

Actor identity is bound by SERVER CONFIGURATION, never by tool arguments.
The MCP caller cannot set its own capabilities, limits, or identity.

Runtime dependency: `pip install 'finguard[mcp]'` (adds mcp>=1.0.0)
"""

from __future__ import annotations

import logging
from typing import Any

from finguard.mcp.boundary import MCPSecurityBoundary, MCPSession
from finguard.mcp.errors import MCPBoundaryError

logger = logging.getLogger(__name__)


def create_mcp_server(
    actor_id: str,
    session_id: str,
    orchestrator_config: dict[str, Any] | None = None,
):
    """Create and return a configured FastMCP server instance.

    Requires the optional `mcp` dependency:
        pip install 'finguard[mcp]'

    Parameters
    ----------
    actor_id:
        Trusted actor identity bound by server configuration.
        The MCP caller CANNOT override this.
    session_id:
        Server-assigned session identifier.
    orchestrator_config:
        Optional server-side orchestration limits (max_steps, deadline_seconds, etc.)
        The MCP caller CANNOT override these values.
    """
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "MCP server requires the optional 'mcp' dependency. "
            "Install it with: pip install 'finguard[mcp]'"
        ) from exc

    mcp = FastMCP("FIN//GUARD Security Gateway")
    session = MCPSession(session_id)
    boundary = MCPSecurityBoundary(
        actor_id=actor_id,
        session=session,
        orchestrator_config=orchestrator_config,
    )

    @mcp.tool()
    def propose_transaction(
        from_account: str,
        recipient: str,
        amount: str,
        currency: str,
        reason: str,
    ) -> dict[str, Any]:
        """Propose a financial transaction for evaluation.

        This is a PROPOSAL — not an authorization, not an execution.
        The final decision is made by the deterministic security core,
        never by the MCP layer.

        If the decision requires human approval, the response will set
        approval_required=True. The caller MUST stop and await approval.
        """
        raw = {
            "from_account": from_account,
            "recipient": recipient,
            "amount": amount,
            "currency": currency,
            "reason": reason,
        }
        try:
            result = boundary.propose_transaction(raw)
            return result.model_dump(mode="json")
        except MCPBoundaryError as exc:
            return exc.to_dict()

    @mcp.tool()
    def get_decision(receipt_id: str) -> dict[str, Any]:
        """Retrieve a decision receipt by ID. Read-only."""
        try:
            result = boundary.get_decision({"receipt_id": receipt_id})
            return result.model_dump(mode="json")
        except MCPBoundaryError as exc:
            return exc.to_dict()

    @mcp.tool()
    def list_transactions(limit: int = 20) -> dict[str, Any]:
        """List recent transactions for the bound actor. Read-only."""
        try:
            result = boundary.list_transactions({"limit": limit})
            return result.model_dump(mode="json")
        except MCPBoundaryError as exc:
            return exc.to_dict()

    @mcp.tool()
    def get_audit_proof(seq: int) -> dict[str, Any]:
        """Retrieve a tamper-evident audit ledger entry. Read-only."""
        try:
            result = boundary.get_audit_proof({"seq": seq})
            return result.model_dump(mode="json")
        except MCPBoundaryError as exc:
            return exc.to_dict()

    return mcp
