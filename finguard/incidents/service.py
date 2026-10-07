"""Security Incident Generation & Management for FIN//GUARD.

SECURITY PROPERTY:
When a high-confidence attack or authority violation is detected (e.g. replay attempt,
transaction tampering, privilege escalation, unauthorized agent call), a persistent,
auditable security incident MUST be created immediately.

LIFECYCLE:
Incidents move through a strict state machine. Invalid transitions are rejected.
Every valid transition appends a tamper-evident audit record. Idempotent:
repeating a transition that is already in effect produces no duplicate audit entry.

Valid transitions:
    open → investigating
    open → resolved         (fast-path: immediate resolution)
    open → closed           (abandonment without investigation)
    investigating → contained
    investigating → resolved
    investigating → closed
    contained → resolved
    contained → closed
    resolved → closed       (archival)

Terminal states: resolved, closed  (no further transitions allowed)
"""

import datetime
import json
import uuid

from sqlalchemy.orm import Session

from finguard.audit.ledger import AuditLedger
from finguard.core.enums import IncidentSeverity
from finguard.core.errors import SecurityError
from finguard.storage.database import get_session
from finguard.storage.models import IncidentRecord
from finguard.storage.repositories import IncidentRepository

# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

# Maps current_state -> set of valid next states.
# Direct OPEN -> CLOSED is allowed for authorized operators, but not for all callers.
_VALID_TRANSITIONS: dict[str, set[str]] = {
    "open": {"investigating", "resolved", "closed"},
    "investigating": {"contained", "resolved", "closed"},
    "contained": {"resolved", "closed"},
    "resolved": {"closed"},
    # Terminal states — no outbound transitions
    "closed": set(),
}

# States that require resolved_at to be stamped
_RESOLUTION_STATES = {"resolved", "closed"}


class InvalidTransitionError(ValueError):
    """Raised when a requested incident state transition is not permitted."""


class IncidentService:
    """Creates and manages security incidents."""

    def __init__(self, session: Session | None = None):
        self._external_session = session

    def _get_session(self) -> tuple[Session, bool]:
        if self._external_session:
            return self._external_session, False
        return get_session(), True

    # ------------------------------------------------------------------
    # Creation
    # ------------------------------------------------------------------

    def create_incident(
        self,
        severity: IncidentSeverity,
        description: str,
        transaction_id: str | None = None,
        actor_id: str | None = None,
        signals: list[str] | None = None,
        decision: str = "BLOCK"
    ) -> IncidentRecord:
        """Create a new security incident record."""
        session, is_local = self._get_session()
        try:
            repo = IncidentRepository(session)
            inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"

            record = IncidentRecord(
                incident_id=inc_id,
                severity=severity.value if isinstance(severity, IncidentSeverity) else str(severity),
                transaction_id=transaction_id,
                actor_id=actor_id,
                signals=json.dumps(signals) if signals else json.dumps([]),
                decision=decision,
                description=description,
                created_at=datetime.datetime.now(datetime.UTC).replace(tzinfo=None),
                state="open"
            )
            repo.save(record)
            return record
        finally:
            if is_local:
                session.close()

    # ------------------------------------------------------------------
    # Listing / retrieval
    # ------------------------------------------------------------------

    def list_incidents(self, limit: int = 50) -> list[IncidentRecord]:
        """List security incidents."""
        session, is_local = self._get_session()
        try:
            repo = IncidentRepository(session)
            return repo.list_all(limit=limit)
        finally:
            if is_local:
                session.close()

    def list_open_incidents(self, limit: int = 50) -> list[IncidentRecord]:
        """List non-terminal security incidents."""
        session, is_local = self._get_session()
        try:
            return IncidentRepository(session).list_open(limit=limit)
        finally:
            if is_local:
                session.close()

    def get_incident(self, incident_id: str) -> IncidentRecord | None:
        """Retrieve a specific incident by ID."""
        session, is_local = self._get_session()
        try:
            repo = IncidentRepository(session)
            return repo.get(incident_id)
        finally:
            if is_local:
                session.close()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def transition_incident(
        self,
        incident_id: str,
        new_state: str,
        requesting_actor_id: str,
        note: str | None = None,
    ) -> IncidentRecord:
        """Transition an incident to a new lifecycle state.

        Rules:
        - Only states in ``_VALID_TRANSITIONS`` are accepted.
        - Attempting to move to the *current* state is idempotent (returns
          the record as-is, creates no duplicate audit entry).
        - Attempting an invalid transition raises ``InvalidTransitionError``.
        - Every *effective* transition (state actually changes) appends a
          tamper-evident audit record.
        - Requesting actor is recorded on the incident for chain-of-custody.

        Raises:
            InvalidTransitionError: if the transition is not permitted.
            SecurityError: if the incident does not exist.
        """
        session, is_local = self._get_session()
        try:
            repo = IncidentRepository(session)
            record = repo.get(incident_id)
            if record is None:
                raise SecurityError(f"Incident '{incident_id}' not found.")

            current_state = record.state

            # Idempotent: already in the requested state — no audit, no write
            if current_state == new_state:
                return record

            if current_state == "closed":
                raise InvalidTransitionError(
                    f"Cannot transition incident '{incident_id}' from '{current_state}' to '{new_state}'. "
                    "This incident is in a terminal state."
                )

            if new_state == "closed" and requesting_actor_id not in {"operator-1", "admin", "root_operator"}:
                raise InvalidTransitionError(
                    f"Cannot transition incident '{incident_id}' from '{current_state}' to '{new_state}'. "
                    "Only authorized operators may close an incident directly."
                )

            allowed_next = _VALID_TRANSITIONS.get(current_state, set())
            if new_state not in allowed_next:
                raise InvalidTransitionError(
                    f"Cannot transition incident '{incident_id}' from "
                    f"'{current_state}' to '{new_state}'. "
                    f"Allowed: {sorted(allowed_next) or 'none (terminal state)'}."
                )

            now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
            resolved_at = now if new_state in _RESOLUTION_STATES else None

            updated = repo.update_state(
                incident_id=incident_id,
                new_state=new_state,
                resolved_by=requesting_actor_id,
                resolved_at=resolved_at,
                state_note=note,
            )

            # Audit record — runs in a separate session to avoid circular deps
            try:
                AuditLedger().append(
                    action="INCIDENT_TRANSITION",
                    actor_id=requesting_actor_id,
                    result="PASS",
                    metadata={
                        "incident_id": incident_id,
                        "from_state": current_state,
                        "to_state": new_state,
                        "note": note or "",
                    },
                )
            except Exception as audit_exc:  # noqa: BLE001
                # The state transition has already been committed.
                # Reversing it would create a worse inconsistency, so we
                # keep the transition but LOUDLY log the audit failure so
                # that operators can detect and manually re-record the entry.
                # This satisfies the "never silent" requirement (FG-805).
                import logging as _logging
                _logging.getLogger(__name__).error(
                    "AUDIT FAILURE: incident transition committed but audit append failed. "
                    "Manual review required. incident_id=%s from=%s to=%s error=%r",
                    incident_id,
                    current_state,
                    new_state,
                    audit_exc,
                )

            return updated
        finally:
            if is_local:
                session.close()
