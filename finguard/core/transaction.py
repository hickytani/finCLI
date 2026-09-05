"""Transaction domain model for FIN//GUARD.

SECURITY PROPERTIES:
- Every transaction has a unique, cryptographically random nonce
- Canonical serialization is deterministic (for signature binding)
- Transaction hash binds to all security-sensitive fields
- Modifying any bound field invalidates the hash/signature

TRUST MODEL:
- A Transaction object represents an UNTRUSTED request
- It must pass through identity → authority → policy → risk → approval
  before reaching the signing authority
"""

import datetime
import secrets
import uuid
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from finguard.core.canonical import canonical_serialize, canonical_amount
from finguard.core.enums import Currency, TransactionState
from finguard.crypto.hashing import sha256_hash


def _generate_tx_id() -> str:
    """Generate a unique transaction ID."""
    return f"TX-{uuid.uuid4().hex[:12].upper()}"


def _generate_nonce() -> str:
    """Generate a cryptographically random nonce.

    Uses os.urandom via secrets module — NOT predictable.
    """
    return secrets.token_hex(16)


class Transaction(BaseModel):
    """Canonical transaction model.

    All security-sensitive fields are included in the canonical hash.
    Modifying any of these fields after signing or approval invalidates
    the cryptographic binding.
    """

    transaction_id: str = Field(default_factory=_generate_tx_id)
    actor_id: str
    session_id: Optional[str] = None
    from_account: str
    to_account: str
    amount: float
    currency: Currency = Currency.INR
    nonce: str = Field(default_factory=_generate_nonce)
    timestamp: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    metadata: Optional[dict] = None
    idempotency_key: Optional[str] = None
    policy_version: Optional[str] = None
    initiating_actor_type: Optional[str] = None

    # Non-canonical fields (not included in security hash)
    state: TransactionState = TransactionState.CREATED
    signature: Optional[str] = None
    signing_key_id: Optional[str] = None

    @field_validator("amount")
    @classmethod
    def amount_must_be_positive(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("Transaction amount must be positive")
        return v

    @field_validator("from_account", "to_account")
    @classmethod
    def accounts_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Account identifier must not be empty")
        return v.strip()

    def canonical_fields(self) -> dict:
        """Return the security-sensitive fields in canonical form.

        SECURITY: Only these fields are bound to the signature.
        Adding or removing fields here changes all existing signatures.
        Changes to this method require a security review.
        """
        return {
            "transaction_id": self.transaction_id,
            "actor_id": self.actor_id,
            "session_id": self.session_id or "",
            "from_account": self.from_account,
            "to_account": self.to_account,
            "amount": canonical_amount(self.amount),
            "currency": self.currency.value,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "idempotency_key": self.idempotency_key or "",
            "policy_version": self.policy_version or "",
        }

    def canonical_bytes(self) -> bytes:
        """Produce deterministic canonical bytes for this transaction.

        INVARIANT: Two Transaction objects with identical security-sensitive
        fields MUST produce identical canonical bytes.
        """
        return canonical_serialize(self.canonical_fields())

    def transaction_hash(self) -> str:
        """Compute the SHA-256 hash of the canonical transaction.

        This hash is what gets signed. It binds the signature to
        all security-sensitive fields.
        """
        return sha256_hash(self.canonical_bytes())

    def to_display_dict(self) -> dict:
        """Return all fields for display purposes (including non-canonical)."""
        return {
            "transaction_id": self.transaction_id,
            "actor_id": self.actor_id,
            "session_id": self.session_id,
            "from_account": self.from_account,
            "to_account": self.to_account,
            "amount": self.amount,
            "currency": self.currency.value,
            "nonce": self.nonce,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "idempotency_key": self.idempotency_key,
            "policy_version": self.policy_version,
            "state": self.state.value,
            "canonical_hash": self.transaction_hash(),
            "signature": self.signature,
            "signing_key_id": self.signing_key_id,
        }
