"""Investigation Service for FIN//GUARD.

Provides the programmable API for forensic investigation of incidents,
transactions, actors, and the security timeline.

SECURITY PROPERTIES:
- All lookups validate that the requested resource exists.
- Actor-scoped IDOR protection: callers that supply an ``owner_actor_id``
  constraint receive a SecurityError if the requested record belongs to a
  different actor. This enforces per-actor ownership without a multi-tenant
  org model.
- All collection queries are bounded — no unbounded DB scans.
- No data is fabricated. Every field in a response comes from a real DB row.
"""

import datetime
import json
from dataclasses import dataclass, field
from typing import Any, Optional

from sqlalchemy.orm import Session

from finguard.core.errors import SecurityError
from finguard.storage.database import get_session
from finguard.storage.models import (
    AuditEntryRecord,
    DecisionReceiptRecord,
    IncidentRecord,
    SecuritySignalRecord,
    TransactionRecord,
)
from finguard.storage.repositories import (
    AuditRepository,
    IncidentRepository,
    ReceiptRepository,
    SignalRepository,
    TransactionRepository,
)


# ---------------------------------------------------------------------------
# Result dataclasses — typed containers with no fabricated fields
# ---------------------------------------------------------------------------


@dataclass
class TransactionSummary:
    """Slim transaction summary used in investigation results."""
    transaction_id: str
    actor_id: str
    from_account: str
    to_account: str
    amount: float
    currency: str
    state: str
    timestamp: datetime.datetime
    canonical_hash: Optional[str]
    nonce: str

    @classmethod
    def from_record(cls, r: TransactionRecord) -> "TransactionSummary":
        return cls(
            transaction_id=r.transaction_id,
            actor_id=r.actor_id,
            from_account=r.from_account,
            to_account=r.to_account,
            amount=r.amount,
            currency=r.currency,
            state=r.state,
            timestamp=r.timestamp,
            canonical_hash=r.canonical_hash,
            nonce=r.nonce,
        )


@dataclass
class SignalSummary:
    """Summary of a security signal."""
    signal_id: str
    transaction_id: str
    signal_type: str
    score: int
    description: Optional[str]
    created_at: datetime.datetime

    @classmethod
    def from_record(cls, r: SecuritySignalRecord) -> "SignalSummary":
        return cls(
            signal_id=r.signal_id,
            transaction_id=r.transaction_id,
            signal_type=r.signal_type,
            score=r.score,
            description=r.description,
            created_at=r.created_at,
        )


@dataclass
class AuditSummary:
    """Summary of a single audit ledger entry."""
    entry_id: int
    timestamp: datetime.datetime
    actor_id: Optional[str]
    action: str
    transaction_id: Optional[str]
    result: Optional[str]
    metadata: Optional[dict]

    @classmethod
    def from_record(cls, r: AuditEntryRecord) -> "AuditSummary":
        meta = None
        if r.metadata_json:
            try:
                meta = json.loads(r.metadata_json)
            except Exception:
                meta = {"raw": r.metadata_json}
        return cls(
            entry_id=r.entry_id,
            timestamp=r.timestamp,
            actor_id=r.actor_id,
            action=r.action,
            transaction_id=r.transaction_id,
            result=r.result,
            metadata=meta,
        )


@dataclass
class ReceiptSummary:
    """Summary of a decision receipt."""
    receipt_id: str
    transaction_id: str
    decision: str
    risk_score: Optional[int]
    risk_level: Optional[str]
    reasons: list[str]
    timestamp: datetime.datetime

    @classmethod
    def from_record(cls, r: DecisionReceiptRecord) -> "ReceiptSummary":
        reasons: list[str] = []
        if r.matched_rules:
            try:
                raw = json.loads(r.matched_rules)
                reasons = raw if isinstance(raw, list) else [str(raw)]
            except Exception:
                reasons = [r.matched_rules]
        return cls(
            receipt_id=r.receipt_id,
            transaction_id=r.transaction_id,
            decision=r.decision,
            risk_score=r.risk_score,
            risk_level=r.risk_level,
            reasons=reasons,
            timestamp=r.timestamp,
        )


@dataclass
class IncidentTrace:
    """Full forensic trace for a security incident."""
    incident: IncidentRecord
    transaction: Optional[TransactionSummary]
    signals: list[SignalSummary]
    receipt: Optional[ReceiptSummary]
    audit_entries: list[AuditSummary]


@dataclass
class ActorProfile:
    """Security posture snapshot for an actor."""
    actor_id: str
    recent_transactions: list[TransactionSummary]
    incidents: list[IncidentRecord]
    signals: list[SignalSummary]
    recent_audit: list[AuditSummary]
    total_transactions_in_db: int
    open_incidents: int
    # Risk contributors: signals broken down by type with counts
    risk_contributors: dict[str, int]


@dataclass
class TimelineItem:
    """A single entry in a merged investigation timeline."""
    timestamp: datetime.datetime
    source_type: str   # "transaction" | "signal" | "audit" | "receipt" | "incident"
    source_id: str     # ID of the originating record
    summary: str
    metadata: dict = field(default_factory=dict)


@dataclass
class EventSearchResult:
    """Paginated result from an event search."""
    items: list[TransactionSummary]
    total: int
    page: int
    page_size: int
    has_next: bool


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

_MAX_PAGE_SIZE = 100
_DEFAULT_PAGE_SIZE = 20
_DEFAULT_AUDIT_LIMIT = 50
_DEFAULT_SIGNAL_LIMIT = 50


class InvestigationService:
    """Service layer for forensic investigation.

    All methods accept an optional ``session`` argument for callers that want
    to participate in a larger transaction. When not supplied, the service
    opens and closes its own session.
    """

    def __init__(self, session: Optional[Session] = None):
        self._external_session = session

    def _get_session(self) -> tuple[Session, bool]:
        if self._external_session:
            return self._external_session, False
        return get_session(), True

    # ------------------------------------------------------------------
    # 1. Incident trace
    # ------------------------------------------------------------------

    def get_incident_trace(
        self,
        incident_id: str,
        owner_actor_id: Optional[str] = None,
    ) -> IncidentTrace:
        """Return a full forensic trace for an incident.

        Traces:
            incident → related transaction → signals from that transaction
                     → decision receipt → relevant audit entries

        All collections are bounded. No fabricated fields.

        Args:
            incident_id: The incident to trace.
            owner_actor_id: When supplied, raises SecurityError if the
                incident's actor_id differs — IDOR protection.

        Raises:
            SecurityError: if not found or actor mismatch.
        """
        session, is_local = self._get_session()
        try:
            inc_repo = IncidentRepository(session)
            tx_repo = TransactionRepository(session)
            sig_repo = SignalRepository(session)
            rcpt_repo = ReceiptRepository(session)
            audit_repo = AuditRepository(session)

            inc = inc_repo.get(incident_id)
            if inc is None:
                raise SecurityError(f"Incident '{incident_id}' not found.")

            # IDOR check — only enforce when caller supplies a constraint
            if owner_actor_id and inc.actor_id and inc.actor_id != owner_actor_id:
                raise SecurityError(
                    f"Access denied: incident '{incident_id}' does not belong to actor '{owner_actor_id}'."
                )

            # Related transaction
            tx_summary: Optional[TransactionSummary] = None
            signals: list[SignalSummary] = []
            receipt: Optional[ReceiptSummary] = None
            tx_audit: list[AuditSummary] = []

            if inc.transaction_id:
                tx_rec = tx_repo.get(inc.transaction_id)
                if tx_rec:
                    tx_summary = TransactionSummary.from_record(tx_rec)

                # Signals — bounded batch query (no N+1)
                sig_recs = sig_repo.get_by_transactions(
                    [inc.transaction_id], limit=_DEFAULT_SIGNAL_LIMIT
                )
                signals = [SignalSummary.from_record(s) for s in sig_recs]

                # Decision receipt
                rcpt_rec = rcpt_repo.get_by_transaction(inc.transaction_id)
                if rcpt_rec:
                    receipt = ReceiptSummary.from_record(rcpt_rec)

                # Audit entries for this transaction
                tx_audit_recs = audit_repo.get_by_transaction(inc.transaction_id)
                tx_audit = [AuditSummary.from_record(a) for a in tx_audit_recs]

            # Also include any INCIDENT_TRANSITION audit entries for this incident
            inc_audit_recs = audit_repo.get_by_action("INCIDENT_TRANSITION", limit=_DEFAULT_AUDIT_LIMIT)
            inc_audit = [
                AuditSummary.from_record(a)
                for a in inc_audit_recs
                if a.metadata_json and incident_id in (a.metadata_json or "")
            ]

            # Merge and deduplicate audit entries by entry_id
            seen: set[int] = set()
            merged_audit: list[AuditSummary] = []
            for entry in tx_audit + [AuditSummary.from_record(r) for r in inc_audit_recs
                                      if r.metadata_json and incident_id in (r.metadata_json or "")]:
                if entry.entry_id not in seen:
                    seen.add(entry.entry_id)
                    merged_audit.append(entry)
            merged_audit.sort(key=lambda e: e.timestamp)

            return IncidentTrace(
                incident=inc,
                transaction=tx_summary,
                signals=signals,
                receipt=receipt,
                audit_entries=merged_audit,
            )
        finally:
            if is_local:
                session.close()

    # ------------------------------------------------------------------
    # 2. Event search
    # ------------------------------------------------------------------

    def search_events(
        self,
        actor_id: Optional[str] = None,
        state: Optional[str] = None,
        to_account: Optional[str] = None,
        from_account: Optional[str] = None,
        since: Optional[datetime.datetime] = None,
        until: Optional[datetime.datetime] = None,
        min_amount: Optional[float] = None,
        max_amount: Optional[float] = None,
        page: int = 1,
        page_size: int = _DEFAULT_PAGE_SIZE,
        requesting_actor_id: Optional[str] = None,
    ) -> EventSearchResult:
        """Paginated, filtered event (transaction) search.

        All filter parameters are optional and additive (AND semantics).
        Page is 1-indexed. page_size is capped at _MAX_PAGE_SIZE.

        Security:
            When ``requesting_actor_id`` is supplied, results are scoped to
            that actor only — preventing cross-actor data leakage without an
            explicit ``actor_id`` filter.

        Args:
            actor_id: Filter by initiating actor.
            state: Filter by transaction state.
            to_account: Filter by destination account.
            from_account: Filter by source account.
            since: Include only transactions at or after this UTC datetime.
            until: Include only transactions at or before this UTC datetime.
            min_amount: Minimum transaction amount.
            max_amount: Maximum transaction amount.
            page: 1-based page number.
            page_size: Rows per page (capped at _MAX_PAGE_SIZE).
            requesting_actor_id: When set, auto-scopes all results to this
                actor, regardless of the ``actor_id`` filter argument.

        Returns:
            EventSearchResult with paginated items and metadata.
        """
        # Cap page size
        page_size = max(1, min(page_size, _MAX_PAGE_SIZE))
        page = max(1, page)
        offset = (page - 1) * page_size

        # Tenant isolation: requesting actor overrides or constrains actor filter
        effective_actor_id = actor_id
        if requesting_actor_id:
            if effective_actor_id and effective_actor_id != requesting_actor_id:
                # Cross-actor attempt: caller tried to request a different actor's data
                raise SecurityError(
                    f"Access denied: actor '{requesting_actor_id}' may not query "
                    f"events belonging to actor '{effective_actor_id}'."
                )
            effective_actor_id = requesting_actor_id

        session, is_local = self._get_session()
        try:
            repo = TransactionRepository(session)

            kwargs: dict[str, Any] = dict(
                actor_id=effective_actor_id,
                state=state,
                to_account=to_account,
                from_account=from_account,
                since=since,
                until=until,
                min_amount=min_amount,
                max_amount=max_amount,
            )

            total = repo.count_search(**kwargs)
            records = repo.search(offset=offset, limit=page_size, **kwargs)

            items = [TransactionSummary.from_record(r) for r in records]
            return EventSearchResult(
                items=items,
                total=total,
                page=page,
                page_size=page_size,
                has_next=(offset + len(records)) < total,
            )
        finally:
            if is_local:
                session.close()

    # ------------------------------------------------------------------
    # 3. Actor profile
    # ------------------------------------------------------------------

    def get_actor_profile(
        self,
        actor_id: str,
        requesting_actor_id: Optional[str] = None,
        tx_limit: int = 20,
        incident_limit: int = 20,
        audit_limit: int = 20,
    ) -> ActorProfile:
        """Return the security posture for a specific actor.

        Exposes:
        - Recent transactions (bounded)
        - Related incidents (bounded)
        - All signals fired against this actor's transactions (bounded)
        - Recent audit activity (bounded)
        - Risk contributors by signal type with occurrence counts
        - Open incident count

        IDOR protection: if requesting_actor_id is supplied and differs from
        actor_id, raises SecurityError.

        Args:
            actor_id: The actor to profile.
            requesting_actor_id: The actor making the request.
            tx_limit: Max transactions to include.
            incident_limit: Max incidents to include.
            audit_limit: Max audit entries to include.
        """
        if requesting_actor_id and requesting_actor_id != actor_id:
            raise SecurityError(
                f"Access denied: actor '{requesting_actor_id}' may not profile "
                f"actor '{actor_id}'."
            )

        session, is_local = self._get_session()
        try:
            tx_repo = TransactionRepository(session)
            sig_repo = SignalRepository(session)
            inc_repo = IncidentRepository(session)
            audit_repo = AuditRepository(session)

            transactions = tx_repo.list_by_actor(actor_id, limit=tx_limit)
            tx_ids = [t.transaction_id for t in transactions]

            # Batch signals — single IN query, not N queries
            sig_recs = sig_repo.get_by_transactions(tx_ids, limit=_DEFAULT_SIGNAL_LIMIT)
            signals = [SignalSummary.from_record(s) for s in sig_recs]

            # Risk contributors: count occurrences per signal type
            risk_contributors: dict[str, int] = {}
            for s in signals:
                risk_contributors[s.signal_type] = risk_contributors.get(s.signal_type, 0) + 1

            incidents = inc_repo.list_by_actor(actor_id, limit=incident_limit)
            open_count = sum(1 for i in incidents if i.state in ("open", "investigating", "contained"))

            audit_entries = audit_repo.get_by_actor(actor_id, limit=audit_limit)
            audit_summaries = [AuditSummary.from_record(a) for a in audit_entries]

            total_count = tx_repo.count_search(actor_id=actor_id)

            return ActorProfile(
                actor_id=actor_id,
                recent_transactions=[TransactionSummary.from_record(t) for t in transactions],
                incidents=incidents,
                signals=signals,
                recent_audit=audit_summaries,
                total_transactions_in_db=total_count,
                open_incidents=open_count,
                risk_contributors=risk_contributors,
            )
        finally:
            if is_local:
                session.close()

    # ------------------------------------------------------------------
    # 4. Investigation timeline
    # ------------------------------------------------------------------

    def get_incident_timeline(
        self,
        incident_id: str,
        owner_actor_id: Optional[str] = None,
    ) -> list[TimelineItem]:
        """Build a deterministic chronological timeline for an incident.

        Sources combined (all from real DB records):
        - The incident creation event itself
        - Related transaction timestamp
        - All security signals for the related transaction
        - The decision receipt
        - Relevant audit entries (transaction-scoped + incident lifecycle transitions)

        Every item has a real timestamp from its source record.
        No synthetic/fabricated entries.

        Args:
            incident_id: Target incident.
            owner_actor_id: IDOR constraint — raises SecurityError if mismatch.

        Returns:
            List of TimelineItem sorted by timestamp ascending.
        """
        trace = self.get_incident_trace(incident_id, owner_actor_id=owner_actor_id)
        items: list[TimelineItem] = []

        # 1. Incident creation
        items.append(TimelineItem(
            timestamp=trace.incident.created_at,
            source_type="incident",
            source_id=trace.incident.incident_id,
            summary=f"Incident {trace.incident.incident_id} created "
                    f"(severity={trace.incident.severity}, state={trace.incident.state})",
            metadata={
                "description": trace.incident.description,
                "decision": trace.incident.decision,
            },
        ))

        # 2. Related transaction
        if trace.transaction:
            items.append(TimelineItem(
                timestamp=trace.transaction.timestamp,
                source_type="transaction",
                source_id=trace.transaction.transaction_id,
                summary=f"Transaction {trace.transaction.transaction_id}: "
                        f"{trace.transaction.currency} {trace.transaction.amount:.2f} "
                        f"{trace.transaction.from_account} → {trace.transaction.to_account} "
                        f"[{trace.transaction.state}]",
                metadata={
                    "actor_id": trace.transaction.actor_id,
                    "canonical_hash": trace.transaction.canonical_hash,
                    "nonce": trace.transaction.nonce,
                },
            ))

        # 3. Security signals
        for sig in trace.signals:
            items.append(TimelineItem(
                timestamp=sig.created_at,
                source_type="signal",
                source_id=sig.signal_id,
                summary=f"Signal {sig.signal_type} fired (score +{sig.score})",
                metadata={
                    "transaction_id": sig.transaction_id,
                    "description": sig.description,
                },
            ))

        # 4. Decision receipt
        if trace.receipt:
            items.append(TimelineItem(
                timestamp=trace.receipt.timestamp,
                source_type="receipt",
                source_id=trace.receipt.receipt_id,
                summary=f"Decision: {trace.receipt.decision.upper()} "
                        f"(risk {trace.receipt.risk_score}/{trace.receipt.risk_level})",
                metadata={
                    "reasons": trace.receipt.reasons,
                },
            ))

        # 5. Audit entries
        for audit in trace.audit_entries:
            items.append(TimelineItem(
                timestamp=audit.timestamp,
                source_type="audit",
                source_id=str(audit.entry_id),
                summary=f"Audit: {audit.action} [{audit.result}] by {audit.actor_id or 'system'}",
                metadata=audit.metadata or {},
            ))

        # Sort by timestamp (deterministic: secondary sort by source_id for ties)
        items.sort(key=lambda i: (i.timestamp, i.source_type, i.source_id))
        return items

    # ------------------------------------------------------------------
    # 5. Transaction trace (full forensic)
    # ------------------------------------------------------------------

    def get_transaction_trace(
        self,
        transaction_id: str,
        owner_actor_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Full forensic trace for a single transaction.

        Returns a dict containing the transaction, its signals, receipt,
        related incidents, and audit entries.

        IDOR: if owner_actor_id is supplied and the transaction belongs to a
        different actor, raises SecurityError.
        """
        session, is_local = self._get_session()
        try:
            tx_repo = TransactionRepository(session)
            sig_repo = SignalRepository(session)
            rcpt_repo = ReceiptRepository(session)
            inc_repo = IncidentRepository(session)
            audit_repo = AuditRepository(session)

            tx = tx_repo.get(transaction_id)
            if tx is None:
                raise SecurityError(f"Transaction '{transaction_id}' not found.")

            if owner_actor_id and tx.actor_id != owner_actor_id:
                raise SecurityError(
                    f"Access denied: transaction '{transaction_id}' does not belong "
                    f"to actor '{owner_actor_id}'."
                )

            signals = [
                SignalSummary.from_record(s)
                for s in sig_repo.get_by_transaction(transaction_id)
            ]

            receipt_rec = rcpt_repo.get_by_transaction(transaction_id)
            receipt = ReceiptSummary.from_record(receipt_rec) if receipt_rec else None

            incidents = inc_repo.list_by_transaction(transaction_id)

            audit_recs = audit_repo.get_by_transaction(transaction_id)
            audit_entries = [AuditSummary.from_record(a) for a in audit_recs]

            return {
                "transaction": TransactionSummary.from_record(tx),
                "signals": signals,
                "receipt": receipt,
                "incidents": incidents,
                "audit_entries": audit_entries,
            }
        finally:
            if is_local:
                session.close()
