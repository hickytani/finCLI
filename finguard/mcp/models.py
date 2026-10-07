"""MCP typed request and response models.

Rules enforced at model level:
- extra="forbid" on requests: unknown fields are rejected immediately
- Authority-shaped fields are explicitly prohibited
- Amount must be a decimal string or integer, NEVER float
- Size limits enforced on every string field
- Response models never carry secrets, keys, or credentials
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Authority-shaped field names that must never appear in MCP input.
# This is the first structural gate — before any business logic runs.
_PROHIBITED_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "approved",
        "authorized",
        "authorization",
        "signer",
        "signature",
        "execute",
        "execution",
        "execution_state",
        "policy_override",
        "grant_capability",
        "admin",
        "root",
        "signing_key",
        "approve",
        "sign",
        "key_id",
        "private_key",
        "secret",
        "credential",
    }
)

# Maximum byte length for free-text fields.
_MAX_REASON_BYTES = 1024
_MAX_IDENTIFIER_BYTES = 128
_MAX_REQUEST_BYTES = 32_768  # 32 KiB total


def _reject_authority_fields(values: dict[str, Any]) -> None:
    """Fail immediately if any authority-shaped key appears in the dict."""
    for key in values:
        normalized = key.strip().lower().replace("-", "_").replace(" ", "_")
        if normalized in _PROHIBITED_FIELD_NAMES:
            raise ValueError(
                f"Authority-shaped field '{key}' is not permitted in MCP requests"
            )


# ─── Request models ──────────────────────────────────────────────────────────


class ProposeTransactionRequest(BaseModel):
    """MCP propose_transaction request.

    This is a PROPOSAL — not an authorization, not an execution.
    The MCP caller never becomes the authority.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Tracing — provided by caller, used for correlation only
    request_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description="Caller-supplied request identifier for correlation; not a nonce.",
    )
    # Required proposal fields
    from_account: str = Field(min_length=1, max_length=_MAX_IDENTIFIER_BYTES)
    recipient: str = Field(min_length=1, max_length=_MAX_IDENTIFIER_BYTES)
    amount: str | int = Field(
        description="Exact amount as a decimal string ('500.00') or integer minor units."
    )
    currency: str = Field(min_length=3, max_length=8)
    reason: str = Field(
        min_length=1,
        max_length=_MAX_REASON_BYTES,
        description="Human-readable purpose. Treated as data only — no authority.",
    )

    @field_validator("amount", mode="before")
    @classmethod
    def amount_must_not_be_float(cls, value: object) -> object:
        if isinstance(value, bool):
            raise TypeError("Amount must be a decimal string or integer, not bool")
        if isinstance(value, float):
            raise TypeError(
                "Float amounts are prohibited. Use a decimal string ('500.00') or integer."
            )
        if not isinstance(value, (str, int)):
            raise TypeError("Amount must be a decimal string or integer")
        if len(str(value)) > 64:
            raise ValueError("Amount exceeds maximum length")
        return value

    @field_validator("currency")
    @classmethod
    def currency_is_uppercase(cls, value: str) -> str:
        upper = value.strip().upper()
        if not upper.isalpha():
            raise ValueError("Currency must be alphabetic")
        return upper

    @field_validator("from_account", "recipient")
    @classmethod
    def identifier_is_safe(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Identifier must not be blank")
        return stripped

    @field_validator("reason")
    @classmethod
    def reason_is_plain_text(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Reason must not be blank")
        return stripped


class GetDecisionRequest(BaseModel):
    """MCP get_decision request — read-only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    receipt_id: str = Field(min_length=1, max_length=_MAX_IDENTIFIER_BYTES)


class ListTransactionsRequest(BaseModel):
    """MCP list_transactions request — read-only, caller-scoped."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    limit: int = Field(default=20, ge=1, le=50)


class GetAuditProofRequest(BaseModel):
    """MCP get_audit_proof request — read-only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    seq: int = Field(ge=1, description="Ledger sequence number to retrieve proof for.")


# ─── Response models ─────────────────────────────────────────────────────────


class ProposeTransactionResponse(BaseModel):
    """Result of propose_transaction — the decision, never authority.

    approval_required=True means execution is BLOCKED pending human approval.
    The MCP caller must NOT interpret this as permission to proceed.
    """

    model_config = ConfigDict(frozen=True)

    tool_id: Literal["propose_transaction"] = "propose_transaction"
    request_id: uuid.UUID
    correlation_id: str
    success: bool
    decision: str  # "allow" | "block" | "require_approval"
    receipt_id: str | None = None
    transaction_id: str | None = None
    transaction_hash: str | None = None
    reasons: list[str] = Field(default_factory=list)
    approval_required: bool = False
    # Explicit non-authority statement always present
    authorization_status: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"


class DecisionResponse(BaseModel):
    """Read-only decision receipt — no secrets, no keys."""

    model_config = ConfigDict(frozen=True)

    tool_id: Literal["get_decision"] = "get_decision"
    request_id: uuid.UUID
    receipt_id: str
    transaction_id: str
    transaction_hash: str
    decision: str
    actor_id: str
    amount: str | None = None
    currency: str | None = None
    approval_required: bool = False
    reasons: list[str] = Field(default_factory=list)
    authorization_status: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"


class TransactionSummary(BaseModel):
    """Minimal read-only transaction metadata. No secrets."""

    model_config = ConfigDict(frozen=True)

    transaction_id: str
    state: str
    amount: str | None = None
    currency: str | None = None
    decision: str | None = None
    created_at: str | None = None


class ListTransactionsResponse(BaseModel):
    """Read-only list of transaction summaries."""

    model_config = ConfigDict(frozen=True)

    tool_id: Literal["list_transactions"] = "list_transactions"
    request_id: uuid.UUID
    items: list[TransactionSummary] = Field(default_factory=list)
    count: int = 0


class AuditProofResponse(BaseModel):
    """Ledger proof for a specific sequence. Read-only."""

    model_config = ConfigDict(frozen=True)

    tool_id: Literal["get_audit_proof"] = "get_audit_proof"
    request_id: uuid.UUID
    seq: int
    entry_hash: str
    previous_hash: str
    action: str
    actor_id: str | None = None
    result: str | None = None
    # No private keys, credentials, or raw secrets in proof output
