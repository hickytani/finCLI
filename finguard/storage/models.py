"""SQLAlchemy ORM models for FIN//GUARD persistent storage.

These models define the database schema. Domain logic should NOT live here —
it belongs in the Pydantic domain models and service layers. These ORM models
exist solely for persistence.
"""

import datetime

from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Text, Boolean, ForeignKey, Index
)
from sqlalchemy.orm import relationship

from finguard.storage.database import Base


class ActorRecord(Base):
    """Persistent storage for actors (identities with authority)."""
    __tablename__ = "actors"

    actor_id = Column(String, primary_key=True)
    actor_type = Column(String, nullable=False)  # ActorType enum value
    display_name = Column(String, nullable=True)
    roles = Column(Text, nullable=True)  # JSON list
    permissions = Column(Text, nullable=True)  # JSON list
    limits = Column(Text, nullable=True)  # JSON dict
    allowed_destinations = Column(Text, nullable=True)  # JSON list
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    active = Column(Boolean, default=True)


class TransactionRecord(Base):
    """Persistent storage for transactions."""
    __tablename__ = "transactions"

    transaction_id = Column(String, primary_key=True)
    actor_id = Column(String, ForeignKey("actors.actor_id"), nullable=False)
    session_id = Column(String, nullable=True)
    from_account = Column(String, nullable=False)
    to_account = Column(String, nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String, nullable=False)
    nonce = Column(String, nullable=False, unique=True)
    idempotency_key = Column(String, nullable=True, unique=True)
    timestamp = Column(DateTime, nullable=False)
    metadata_json = Column(Text, nullable=True)  # JSON
    state = Column(String, nullable=False, default="created")
    canonical_hash = Column(String, nullable=True)
    signature = Column(String, nullable=True)
    signing_key_id = Column(String, nullable=True)
    policy_version = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    __table_args__ = (
        Index("ix_transactions_actor", "actor_id"),
        Index("ix_transactions_nonce", "nonce"),
        Index("ix_transactions_state", "state"),
        Index("ix_transactions_timestamp", "timestamp"),
    )


class ApprovalRecord(Base):
    """Persistent storage for approval requests and individual approvals."""
    __tablename__ = "approvals"

    approval_id = Column(String, primary_key=True)
    transaction_id = Column(String, ForeignKey("transactions.transaction_id"), nullable=False)
    transaction_hash = Column(String, nullable=False)
    request_id = Column(String, nullable=True)
    policy_version = Column(String, nullable=True)
    policy_hash = Column(String, nullable=True)
    approval_type = Column(String, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    signing_key_id = Column(String, nullable=True)
    approval_payload_hash = Column(String, nullable=True)
    approver_id = Column(String, ForeignKey("actors.actor_id"), nullable=False)
    approver_signature = Column(String, nullable=True)
    state = Column(String, nullable=False, default="pending")
    nonce = Column(String, nullable=False, unique=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    decided_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_approvals_transaction", "transaction_id"),
        Index("ix_approvals_approver", "approver_id"),
    )


class ApprovalRequestRecord(Base):
    """Tracks the overall approval workflow for a transaction."""
    __tablename__ = "approval_requests"

    request_id = Column(String, primary_key=True)
    transaction_id = Column(String, ForeignKey("transactions.transaction_id"),
                            nullable=False, unique=True)
    transaction_hash = Column(String, nullable=False)
    policy_version = Column(String, nullable=True)
    policy_hash = Column(String, nullable=True)
    required_approvals = Column(Integer, nullable=False, default=1)
    current_approvals = Column(Integer, nullable=False, default=0)
    state = Column(String, nullable=False, default="pending")
    requester_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)


class AuditEntryRecord(Base):
    """Tamper-evident audit ledger entry."""
    __tablename__ = "audit_entries"

    entry_id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False)
    actor_id = Column(String, nullable=True)
    action = Column(String, nullable=False)
    transaction_id = Column(String, nullable=True)
    result = Column(String, nullable=True)
    metadata_json = Column(Text, nullable=True)
    previous_hash = Column(String, nullable=False)
    entry_hash = Column(String, nullable=False)

    __table_args__ = (
        Index("ix_audit_timestamp", "timestamp"),
        Index("ix_audit_transaction", "transaction_id"),
    )


class IncidentRecord(Base):
    """Security incident record."""
    __tablename__ = "incidents"

    incident_id = Column(String, primary_key=True)
    severity = Column(String, nullable=False)
    transaction_id = Column(String, nullable=True)
    actor_id = Column(String, nullable=True)
    signals = Column(Text, nullable=True)  # JSON list
    decision = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    evidence_ids = Column(Text, nullable=True)  # JSON list
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    state = Column(String, nullable=False, default="open")


class SecuritySignalRecord(Base):
    """Individual security signal generated during transaction processing."""
    __tablename__ = "security_signals"

    signal_id = Column(String, primary_key=True)
    transaction_id = Column(String, ForeignKey("transactions.transaction_id"), nullable=False)
    signal_type = Column(String, nullable=False)
    score = Column(Integer, nullable=False, default=0)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)


class DecisionReceiptRecord(Base):
    """Cryptographically linked decision receipt."""
    __tablename__ = "decision_receipts"

    receipt_id = Column(String, primary_key=True)
    transaction_id = Column(String, ForeignKey("transactions.transaction_id"), nullable=False)
    transaction_hash = Column(String, nullable=False)
    actor_id = Column(String, nullable=True)
    session_id = Column(String, nullable=True)
    policy_id = Column(String, nullable=True)
    policy_version = Column(String, nullable=True)
    matched_rules = Column(Text, nullable=True)  # JSON
    security_signals = Column(Text, nullable=True)  # JSON
    risk_score = Column(Integer, nullable=True)
    risk_level = Column(String, nullable=True)
    approval_state = Column(String, nullable=True)
    decision = Column(String, nullable=False)
    reason = Column(Text, nullable=True)
    timestamp = Column(DateTime, nullable=False)
    previous_receipt_hash = Column(String, nullable=True)
    receipt_hash = Column(String, nullable=False)


class KeyRecord(Base):
    """Metadata for stored cryptographic keys (NOT the key material itself)."""
    __tablename__ = "keys"

    key_id = Column(String, primary_key=True)
    public_key_hex = Column(String, nullable=False)
    algorithm = Column(String, nullable=False, default="Ed25519")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    active = Column(Boolean, default=True)
    fingerprint = Column(String, nullable=True)


class NonceRecord(Base):
    """Used nonces for replay protection."""
    __tablename__ = "used_nonces"

    nonce = Column(String, primary_key=True)
    transaction_id = Column(String, nullable=False)
    used_at = Column(DateTime, default=datetime.datetime.utcnow)
