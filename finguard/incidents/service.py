"""Security Incident Generation & Management for FIN//GUARD.

SECURITY PROPERTY:
When a high-confidence attack or authority violation is detected (e.g. replay attempt,
transaction tampering, privilege escalation, unauthorized agent call), a persistent,
auditable security incident MUST be created immediately.
"""

import uuid
import json
import datetime
from typing import Optional, List
from sqlalchemy.orm import Session

from finguard.core.enums import IncidentSeverity
from finguard.storage.database import get_session
from finguard.storage.models import IncidentRecord
from finguard.storage.repositories import IncidentRepository


class IncidentService:
    """Creates and manages security incidents."""

    def __init__(self, session: Optional[Session] = None):
        self._external_session = session

    def _get_session(self) -> tuple[Session, bool]:
        if self._external_session:
            return self._external_session, False
        return get_session(), True

    def create_incident(
        self,
        severity: IncidentSeverity,
        description: str,
        transaction_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        signals: Optional[List[str]] = None,
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
                created_at=datetime.datetime.now(datetime.timezone.utc),
                state="open"
            )
            repo.save(record)
            return record
        finally:
            if is_local:
                session.close()

    def list_incidents(self, limit: int = 50) -> List[IncidentRecord]:
        """List security incidents."""
        session, is_local = self._get_session()
        try:
            repo = IncidentRepository(session)
            return repo.list_all(limit=limit)
        finally:
            if is_local:
                session.close()

    def get_incident(self, incident_id: str) -> Optional[IncidentRecord]:
        """Retrieve a specific incident by ID."""
        session, is_local = self._get_session()
        try:
            repo = IncidentRepository(session)
            return repo.get(incident_id)
        finally:
            if is_local:
                session.close()
