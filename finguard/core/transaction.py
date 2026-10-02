"""Transaction domain model for FIN//GUARD.

SECURITY PROPERTIES:
- Every transaction is backed by an authoritative Money object (integer minor units).
- Canonical serialization v2 uses domain separation prefix b"finguard.tx.v2\\x00".
- Metadata is bound via metadata_digest to prevent post-approval purpose tampering.
- Floating-point representations are forbidden as authoritative values.
"""

import datetime
import json
import math
import secrets
import unicodedata
import uuid
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from finguard.core.canonical import canonical_amount, canonical_serialize
from finguard.core.enums import Currency, TransactionState
from finguard.core.errors import ValidationError
from finguard.crypto.hashing import sha256_hash
from finguard.money import Money


def _generate_tx_id() -> str:
    """Generate a unique transaction ID."""
    return f"TX-{uuid.uuid4().hex[:12].upper()}"


def _generate_nonce() -> str:
    """Generate a cryptographically random nonce."""
    return secrets.token_hex(16)


class Transaction(BaseModel):
    """Canonical transaction model.

    Backed by authoritative Money object (integer minor units + Currency).
    Canonical version 2 binds amount_minor, currency, and metadata_digest.
    """

    transaction_id: str = Field(default_factory=_generate_tx_id)
    actor_id: str
    session_id: Optional[str] = None
    from_account: str
    to_account: str
    amount: Money
    currency: Currency = Currency.INR
    canonical_version: int = Field(default=2, frozen=True)
    nonce: str = Field(default_factory=_generate_nonce)
    timestamp: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    metadata: Optional[Dict[str, Any]] = None
    idempotency_key: Optional[str] = None
    policy_version: Optional[str] = None
    initiating_actor_type: Optional[str] = None

    # Non-canonical fields (not included in security hash)
    state: TransactionState = TransactionState.CREATED
    signature: Optional[str] = None
    signing_key_id: Optional[str] = None

    model_config = ConfigDict(validate_assignment=True)

    @model_validator(mode="before")
    @classmethod
    def validate_amount_and_money(cls, data: Any) -> Any:
        if isinstance(data, dict):
            version = data.get("canonical_version", 2)
            if version != 2:
                raise ValidationError("New transactions must use canonical version 2")
            raw_amount = data.get("amount")
            curr = data.get("currency", Currency.INR)
            if isinstance(raw_amount, Money):
                money_obj = raw_amount
                if "currency" in data and money_obj.currency != Currency(curr):
                    raise ValidationError("Money currency does not match transaction currency")
            else:
                if "amount_minor" in data:
                    raise ValidationError("amount_minor is not an accepted transaction input field")
                money_obj = Money.from_decimal(raw_amount, currency=curr)

            data["amount"] = money_obj
            data["currency"] = money_obj.currency
        return data

    @field_validator("from_account", "to_account")
    @classmethod
    def accounts_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Account identifier must not be empty")
        normalized = cls.validate_signed_identifier(v.strip())
        if normalized == "*":
            raise ValueError("Wildcard is an authority grant, not an account identifier")
        return normalized

    @field_validator(
        "transaction_id", "actor_id", "session_id", "nonce", "idempotency_key", "policy_version"
    )
    @classmethod
    def identifiers_must_be_canonical_unicode(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return cls.validate_signed_identifier(value)

    @field_validator("timestamp")
    @classmethod
    def timestamp_is_utc(cls, value: datetime.datetime) -> datetime.datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=datetime.UTC)
        return value.astimezone(datetime.UTC)

    @staticmethod
    def validate_signed_identifier(value: str) -> str:
        if unicodedata.normalize("NFC", value) != value:
            raise ValueError("Signed identifiers must use NFC Unicode normalization")
        if any(unicodedata.category(char) in {"Cc", "Cf"} for char in value):
            raise ValueError("Control and format characters are forbidden in signed identifiers")
        return value

    @property
    def money(self) -> Money:
        return self.amount

    @property
    def amount_minor(self) -> int:
        return self.money.minor_units

    @property
    def metadata_digest(self) -> str:
        """SHA-256 digest of canonical metadata (RFC 0001)."""
        if not self.metadata:
            return sha256_hash(b"")
        def reject_floats(value: Any) -> None:
            if isinstance(value, float) and not math.isfinite(value):
                raise ValidationError("Non-finite numeric values are forbidden in signed metadata")
            if isinstance(value, dict):
                for nested in value.values():
                    reject_floats(nested)
            elif isinstance(value, (list, tuple)):
                for nested in value:
                    reject_floats(nested)

        reject_floats(self.metadata)
        meta_json = json.dumps(self.metadata, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return sha256_hash(meta_json.encode("utf-8"))

    def canonical_fields(self, version: Optional[int] = None) -> dict:
        """Return the security-sensitive fields in canonical form."""
        ver = 2 if version is None else version
        if ver == 1:
            return {
                "transaction_id": self.transaction_id,
                "actor_id": self.actor_id,
                "session_id": self.session_id or "",
                "from_account": self.from_account,
                "to_account": self.to_account,
                "amount": canonical_amount(self.amount.to_decimal_string()),
                "currency": self.currency.value if isinstance(self.currency, Currency) else str(self.currency),
                "nonce": self.nonce,
                "timestamp": self.timestamp,
                "idempotency_key": self.idempotency_key or "",
                "policy_version": self.policy_version or "",
            }
        elif ver == 2:
            fields = {
                "canonical_version": 2,
                "transaction_id": self.transaction_id,
                "actor_id": self.actor_id,
                "session_id": self.session_id or "",
                "from_account": self.from_account,
                "to_account": self.to_account,
                "amount_minor": self.amount_minor,
                "currency": self.currency.value if isinstance(self.currency, Currency) else str(self.currency),
                "nonce": self.nonce,
                "timestamp": self.timestamp,
                "idempotency_key": self.idempotency_key or "",
                "policy_version": self.policy_version or "",
                "metadata_digest": self.metadata_digest,
            }
            if any(isinstance(value, float) for value in fields.values()):
                raise ValidationError("Floating-point values are forbidden in transaction v2")
            return fields
        else:
            raise ValidationError(f"Unsupported canonical version: {ver}")

    def canonical_bytes(self, version: Optional[int] = None) -> bytes:
        """Produce deterministic canonical bytes for this transaction."""
        ver = 2 if version is None else version
        return canonical_serialize(self.canonical_fields(ver), version=ver)

    def transaction_hash(self, version: Optional[int] = None) -> str:
        """Compute the SHA-256 hash of the canonical transaction bytes."""
        return sha256_hash(self.canonical_bytes(version))

    def to_display_dict(self) -> dict:
        """Return all fields for display purposes (including non-canonical)."""
        return {
            "transaction_id": self.transaction_id,
            "actor_id": self.actor_id,
            "session_id": self.session_id,
            "from_account": self.from_account,
            "to_account": self.to_account,
            "amount": self.amount.to_decimal_string(),
            "amount_minor": self.amount_minor,
            "currency": self.currency.value if isinstance(self.currency, Currency) else str(self.currency),
            "canonical_version": self.canonical_version,
            "nonce": self.nonce,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
            "metadata_digest": self.metadata_digest,
            "idempotency_key": self.idempotency_key,
            "policy_version": self.policy_version,
            "state": self.state.value if isinstance(self.state, TransactionState) else str(self.state),
            "canonical_hash": self.transaction_hash(),
            "signature": self.signature,
            "signing_key_id": self.signing_key_id,
        }
