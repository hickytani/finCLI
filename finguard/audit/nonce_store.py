"""Persistent Nonce Store for Replay Protection.

SECURITY PROPERTY:
Nonces must be unique across all transactions. Attempting to execute or sign
a transaction with a previously recorded nonce MUST be detected and rejected as
a REPLAY_ATTEMPT, persisting across process restarts.
"""

from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError as SqlIntegrityError
from finguard.storage.database import get_session
from finguard.storage.repositories import NonceRepository


class NonceStore:
    """Persistent SQLite-backed nonce store for replay protection."""

    def __init__(self, session: Optional[Session] = None):
        self._external_session = session

    def _get_session(self) -> tuple[Session, bool]:
        if self._external_session:
            return self._external_session, False
        return get_session(), True

    def has_used(self, nonce: str) -> bool:
        """Check if nonce has already been registered in persistent store."""
        session, is_local = self._get_session()
        try:
            repo = NonceRepository(session)
            return repo.exists(nonce)
        finally:
            if is_local:
                session.close()

    def record(self, nonce: str, transaction_id: str) -> bool:
        """Atomically record a nonce. Returns False if another caller won the race."""
        session, is_local = self._get_session()
        try:
            repo = NonceRepository(session)
            try:
                repo.register(nonce, transaction_id)
                return True
            except SqlIntegrityError:
                session.rollback()
                return False
        finally:
            if is_local:
                session.close()
