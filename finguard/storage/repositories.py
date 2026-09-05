"""Repository pattern for database access.

Encapsulates all SQLAlchemy queries. Business/security logic should NOT
live here — repositories are purely data access.

SECURITY NOTE: Never log or return raw query exceptions to callers.
Wrap database errors to prevent information leakage.
"""

import json
import datetime
from typing import Optional

from sqlalchemy.orm import Session

from finguard.storage.models import (
    ActorRecord, TransactionRecord, ApprovalRecord, ApprovalRequestRecord,
    AuditEntryRecord, IncidentRecord, SecuritySignalRecord,
    DecisionReceiptRecord, KeyRecord, NonceRecord,
)


class TransactionRepository:
    """Data access for transactions."""

    def __init__(self, session: Session):
        self.session = session

    def save(self, record: TransactionRecord) -> None:
        self.session.merge(record)
        self.session.commit()

    def get(self, transaction_id: str) -> Optional[TransactionRecord]:
        return self.session.get(TransactionRecord, transaction_id)

    def list_all(self, limit: int = 50) -> list[TransactionRecord]:
        return (
            self.session.query(TransactionRecord)
            .order_by(TransactionRecord.created_at.desc())
            .limit(limit)
            .all()
        )

    def list_by_state(self, state: str, limit: int = 50) -> list[TransactionRecord]:
        return (
            self.session.query(TransactionRecord)
            .filter(TransactionRecord.state == state)
            .order_by(TransactionRecord.created_at.desc())
            .limit(limit)
            .all()
        )

    def list_by_actor(self, actor_id: str, limit: int = 50) -> list[TransactionRecord]:
        return (
            self.session.query(TransactionRecord)
            .filter(TransactionRecord.actor_id == actor_id)
            .order_by(TransactionRecord.created_at.desc())
            .limit(limit)
            .all()
        )

    def count_in_window(self, actor_id: str, since: datetime.datetime) -> int:
        return (
            self.session.query(TransactionRecord)
            .filter(
                TransactionRecord.actor_id == actor_id,
                TransactionRecord.timestamp >= since,
            )
            .count()
        )

    def sum_in_window(self, actor_id: str, since: datetime.datetime) -> float:
        from sqlalchemy import func
        result = (
            self.session.query(func.coalesce(func.sum(TransactionRecord.amount), 0))
            .filter(
                TransactionRecord.actor_id == actor_id,
                TransactionRecord.timestamp >= since,
            )
            .scalar()
        )
        return float(result)


class ActorRepository:
    """Data access for actors."""

    def __init__(self, session: Session):
        self.session = session

    def save(self, record: ActorRecord) -> None:
        self.session.merge(record)
        self.session.commit()

    def get(self, actor_id: str) -> Optional[ActorRecord]:
        return self.session.get(ActorRecord, actor_id)

    def list_all(self) -> list[ActorRecord]:
        return self.session.query(ActorRecord).all()


class NonceRepository:
    """Data access for used nonces (replay protection)."""

    def __init__(self, session: Session):
        self.session = session

    def exists(self, nonce: str) -> bool:
        return self.session.get(NonceRecord, nonce) is not None

    def register(self, nonce: str, transaction_id: str) -> None:
        record = NonceRecord(nonce=nonce, transaction_id=transaction_id)
        self.session.add(record)
        self.session.commit()


class ApprovalRepository:
    """Data access for approvals."""

    def __init__(self, session: Session):
        self.session = session

    def save_approval(self, record: ApprovalRecord) -> None:
        self.session.merge(record)
        self.session.commit()

    def save_request(self, record: ApprovalRequestRecord) -> None:
        self.session.merge(record)
        self.session.commit()

    def get_request(self, transaction_id: str) -> Optional[ApprovalRequestRecord]:
        return (
            self.session.query(ApprovalRequestRecord)
            .filter(ApprovalRequestRecord.transaction_id == transaction_id)
            .first()
        )

    def get_approvals(self, transaction_id: str) -> list[ApprovalRecord]:
        return (
            self.session.query(ApprovalRecord)
            .filter(ApprovalRecord.transaction_id == transaction_id)
            .all()
        )

    def list_pending(self) -> list[ApprovalRequestRecord]:
        return (
            self.session.query(ApprovalRequestRecord)
            .filter(ApprovalRequestRecord.state == "pending")
            .order_by(ApprovalRequestRecord.created_at.desc())
            .all()
        )


class AuditRepository:
    """Data access for audit ledger entries."""

    def __init__(self, session: Session):
        self.session = session

    def append(self, record: AuditEntryRecord) -> None:
        self.session.add(record)
        self.session.commit()

    def get_all_ordered(self) -> list[AuditEntryRecord]:
        return (
            self.session.query(AuditEntryRecord)
            .order_by(AuditEntryRecord.entry_id.asc())
            .all()
        )

    def get_latest(self) -> Optional[AuditEntryRecord]:
        return (
            self.session.query(AuditEntryRecord)
            .order_by(AuditEntryRecord.entry_id.desc())
            .first()
        )

    def count(self) -> int:
        return self.session.query(AuditEntryRecord).count()

    def get_recent(self, limit: int = 20) -> list[AuditEntryRecord]:
        return (
            self.session.query(AuditEntryRecord)
            .order_by(AuditEntryRecord.entry_id.desc())
            .limit(limit)
            .all()
        )


class IncidentRepository:
    """Data access for security incidents."""

    def __init__(self, session: Session):
        self.session = session

    def save(self, record: IncidentRecord) -> None:
        self.session.merge(record)
        self.session.commit()

    def get(self, incident_id: str) -> Optional[IncidentRecord]:
        return self.session.get(IncidentRecord, incident_id)

    def list_all(self, limit: int = 50) -> list[IncidentRecord]:
        return (
            self.session.query(IncidentRecord)
            .order_by(IncidentRecord.created_at.desc())
            .limit(limit)
            .all()
        )

    def list_by_transaction(self, transaction_id: str) -> list[IncidentRecord]:
        return (
            self.session.query(IncidentRecord)
            .filter(IncidentRecord.transaction_id == transaction_id)
            .all()
        )


class SignalRepository:
    """Data access for security signals."""

    def __init__(self, session: Session):
        self.session = session

    def save(self, record: SecuritySignalRecord) -> None:
        self.session.add(record)
        self.session.commit()

    def get_by_transaction(self, transaction_id: str) -> list[SecuritySignalRecord]:
        return (
            self.session.query(SecuritySignalRecord)
            .filter(SecuritySignalRecord.transaction_id == transaction_id)
            .all()
        )


class ReceiptRepository:
    """Data access for decision receipts."""

    def __init__(self, session: Session):
        self.session = session

    def save(self, record: DecisionReceiptRecord) -> None:
        self.session.merge(record)
        self.session.commit()

    def get(self, receipt_id: str) -> Optional[DecisionReceiptRecord]:
        return self.session.get(DecisionReceiptRecord, receipt_id)

    def get_by_transaction(self, transaction_id: str) -> Optional[DecisionReceiptRecord]:
        return (
            self.session.query(DecisionReceiptRecord)
            .filter(DecisionReceiptRecord.transaction_id == transaction_id)
            .first()
        )

    def get_latest(self) -> Optional[DecisionReceiptRecord]:
        return (
            self.session.query(DecisionReceiptRecord)
            .order_by(DecisionReceiptRecord.timestamp.desc())
            .first()
        )


class KeyRepository:
    """Data access for key metadata (NOT key material)."""

    def __init__(self, session: Session):
        self.session = session

    def save(self, record: KeyRecord) -> None:
        self.session.merge(record)
        self.session.commit()

    def get(self, key_id: str) -> Optional[KeyRecord]:
        return self.session.get(KeyRecord, key_id)

    def list_all(self) -> list[KeyRecord]:
        return self.session.query(KeyRecord).all()
