"""Repository pattern for database access.

Encapsulates all SQLAlchemy queries. Business/security logic should NOT
live here — repositories are purely data access.

SECURITY NOTE: Never log or return raw query exceptions to callers.
Wrap database errors to prevent information leakage.
"""

import datetime
from typing import Optional

from sqlalchemy.orm import Session

from finguard.storage.models import (
    ActorRecord, TransactionRecord, ApprovalRecord, ApprovalRequestRecord,
    AuditEntryRecord, IncidentRecord, SecuritySignalRecord,
    DecisionReceiptRecord, KeyRecord, NonceRecord,
)

# Maximum rows any single investigation query may return without explicit override.
_INVESTIGATION_DEFAULT_LIMIT = 100
_INVESTIGATION_MAX_LIMIT = 500


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

    def search(
        self,
        actor_id: Optional[str] = None,
        state: Optional[str] = None,
        to_account: Optional[str] = None,
        from_account: Optional[str] = None,
        since: Optional[datetime.datetime] = None,
        until: Optional[datetime.datetime] = None,
        min_amount: Optional[float] = None,
        max_amount: Optional[float] = None,
        offset: int = 0,
        limit: int = _INVESTIGATION_DEFAULT_LIMIT,
    ) -> list[TransactionRecord]:
        """Multi-filter paginated transaction search.

        All filters are additive (AND). Limit is capped at the module maximum
        to prevent unbounded DB scans. offset/limit provide backend pagination.
        """
        limit = min(limit, _INVESTIGATION_MAX_LIMIT)
        q = self.session.query(TransactionRecord)
        if actor_id:
            q = q.filter(TransactionRecord.actor_id == actor_id)
        if state:
            q = q.filter(TransactionRecord.state == state)
        if to_account:
            q = q.filter(TransactionRecord.to_account == to_account)
        if from_account:
            q = q.filter(TransactionRecord.from_account == from_account)
        if since:
            q = q.filter(TransactionRecord.timestamp >= since)
        if until:
            q = q.filter(TransactionRecord.timestamp <= until)
        if min_amount is not None:
            q = q.filter(TransactionRecord.amount >= min_amount)
        if max_amount is not None:
            q = q.filter(TransactionRecord.amount <= max_amount)
        return (
            q.order_by(TransactionRecord.timestamp.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    def count_search(
        self,
        actor_id: Optional[str] = None,
        state: Optional[str] = None,
        to_account: Optional[str] = None,
        from_account: Optional[str] = None,
        since: Optional[datetime.datetime] = None,
        until: Optional[datetime.datetime] = None,
        min_amount: Optional[float] = None,
        max_amount: Optional[float] = None,
    ) -> int:
        """Count total matching rows for search — used to compute pagination metadata."""
        q = self.session.query(TransactionRecord)
        if actor_id:
            q = q.filter(TransactionRecord.actor_id == actor_id)
        if state:
            q = q.filter(TransactionRecord.state == state)
        if to_account:
            q = q.filter(TransactionRecord.to_account == to_account)
        if from_account:
            q = q.filter(TransactionRecord.from_account == from_account)
        if since:
            q = q.filter(TransactionRecord.timestamp >= since)
        if until:
            q = q.filter(TransactionRecord.timestamp <= until)
        if min_amount is not None:
            q = q.filter(TransactionRecord.amount >= min_amount)
        if max_amount is not None:
            q = q.filter(TransactionRecord.amount <= max_amount)
        return q.count()


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

    def get_by_transaction(
        self, transaction_id: str, limit: int = _INVESTIGATION_DEFAULT_LIMIT
    ) -> list[AuditEntryRecord]:
        """Return audit entries related to a specific transaction, bounded."""
        return (
            self.session.query(AuditEntryRecord)
            .filter(AuditEntryRecord.transaction_id == transaction_id)
            .order_by(AuditEntryRecord.entry_id.asc())
            .limit(limit)
            .all()
        )

    def get_by_actor(
        self, actor_id: str, limit: int = _INVESTIGATION_DEFAULT_LIMIT
    ) -> list[AuditEntryRecord]:
        """Return recent audit entries for a specific actor, bounded."""
        limit = min(limit, _INVESTIGATION_MAX_LIMIT)
        return (
            self.session.query(AuditEntryRecord)
            .filter(AuditEntryRecord.actor_id == actor_id)
            .order_by(AuditEntryRecord.entry_id.desc())
            .limit(limit)
            .all()
        )

    def get_by_action(
        self, action: str, limit: int = _INVESTIGATION_DEFAULT_LIMIT
    ) -> list[AuditEntryRecord]:
        """Return audit entries of a specific action type, bounded."""
        return (
            self.session.query(AuditEntryRecord)
            .filter(AuditEntryRecord.action == action)
            .order_by(AuditEntryRecord.entry_id.desc())
            .limit(limit)
            .all()
        )

    def get_by_transaction_ids(
        self,
        transaction_ids: list[str],
        limit: int = _INVESTIGATION_DEFAULT_LIMIT,
    ) -> list[AuditEntryRecord]:
        """Batch fetch audit entries for a set of transaction IDs.

        Uses an IN query rather than N individual queries. Bounded by limit.
        """
        if not transaction_ids:
            return []
        limit = min(limit, _INVESTIGATION_MAX_LIMIT)
        return (
            self.session.query(AuditEntryRecord)
            .filter(AuditEntryRecord.transaction_id.in_(transaction_ids))
            .order_by(AuditEntryRecord.entry_id.asc())
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

    def list_by_actor(
        self, actor_id: str, limit: int = _INVESTIGATION_DEFAULT_LIMIT
    ) -> list[IncidentRecord]:
        """Return incidents involving a specific actor, most recent first, bounded."""
        limit = min(limit, _INVESTIGATION_MAX_LIMIT)
        return (
            self.session.query(IncidentRecord)
            .filter(IncidentRecord.actor_id == actor_id)
            .order_by(IncidentRecord.created_at.desc())
            .limit(limit)
            .all()
        )

    def list_open(self, limit: int = 50) -> list[IncidentRecord]:
        """Return open (non-terminal) incidents, most recent first, bounded."""
        return (
            self.session.query(IncidentRecord)
            .filter(IncidentRecord.state.in_(["open", "investigating", "contained"]))
            .order_by(IncidentRecord.created_at.desc())
            .limit(limit)
            .all()
        )

    def update_state(
        self,
        incident_id: str,
        new_state: str,
        resolved_by: Optional[str] = None,
        resolved_at: Optional[datetime.datetime] = None,
        state_note: Optional[str] = None,
    ) -> Optional[IncidentRecord]:
        """Update incident state in-place. Returns the updated record or None if not found.

        The returned record has all attributes eagerly loaded (expunged from session)
        so callers may access any attribute without a live session.
        """
        record = self.session.get(IncidentRecord, incident_id)
        if record is None:
            return None
        record.state = new_state
        if resolved_by is not None:
            record.resolved_by = resolved_by
        if resolved_at is not None:
            record.resolved_at = resolved_at
        if state_note is not None:
            record.state_note = state_note
        self.session.commit()
        # Eagerly load all columns before expunging so the record is usable
        # without an active session.
        self.session.refresh(record)
        self.session.expunge(record)
        return record


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

    def get_by_transactions(
        self,
        transaction_ids: list[str],
        limit: int = _INVESTIGATION_DEFAULT_LIMIT,
    ) -> list[SecuritySignalRecord]:
        """Batch fetch signals for a set of transaction IDs.

        Uses a single IN query instead of N individual queries. Bounded by limit.
        """
        if not transaction_ids:
            return []
        limit = min(limit, _INVESTIGATION_MAX_LIMIT)
        return (
            self.session.query(SecuritySignalRecord)
            .filter(SecuritySignalRecord.transaction_id.in_(transaction_ids))
            .order_by(SecuritySignalRecord.created_at.asc())
            .limit(limit)
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

    def get_by_transactions(
        self,
        transaction_ids: list[str],
        limit: int = _INVESTIGATION_DEFAULT_LIMIT,
    ) -> list[DecisionReceiptRecord]:
        """Batch fetch receipts for a set of transaction IDs.

        Uses a single IN query. Bounded by limit.
        """
        if not transaction_ids:
            return []
        limit = min(limit, _INVESTIGATION_MAX_LIMIT)
        return (
            self.session.query(DecisionReceiptRecord)
            .filter(DecisionReceiptRecord.transaction_id.in_(transaction_ids))
            .order_by(DecisionReceiptRecord.timestamp.asc())
            .limit(limit)
            .all()
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
