"""FIN//GUARD MCP Security Boundary — M5.

This package exposes a deliberately minimal MCP surface:

    propose_transaction   — proposal only; NOT authority
    get_decision          — read-only
    list_transactions     — read-only (caller-scoped)
    get_audit_proof       — read-only

Prohibited (structurally unreachable from this package):
    approve_transaction, sign_transaction, execute_transaction,
    grant_capability, set_policy, set_signer, modify_authorization.

The MCP layer is NOT an authority. Every proposal flows through:
    MCP boundary → M4 orchestration → StructuredIntent → M3.2 guardrails → DecisionEngine.

Trust model:
    MCP input     — UNTRUSTED
    MCP output    — UNTRUSTED
    DecisionEngine / SigningGate — AUTHORITATIVE (never reachable via MCP)
"""

from finguard.mcp.errors import MCPBoundaryError, MCPInputError, MCPRateLimitError
from finguard.mcp.models import (
    AuditProofResponse,
    DecisionResponse,
    ListTransactionsResponse,
    ProposeTransactionRequest,
    ProposeTransactionResponse,
    TransactionSummary,
)

__all__ = [
    "AuditProofResponse",
    "DecisionResponse",
    "ListTransactionsResponse",
    "MCPBoundaryError",
    "MCPInputError",
    "MCPRateLimitError",
    "ProposeTransactionRequest",
    "ProposeTransactionResponse",
    "TransactionSummary",
]
