"""Destination risk classifier for FIN//GUARD.

Classifies destinations as known, new, blocked, or high-risk.
A new destination generates a security signal for risk evaluation.
"""

from sqlalchemy.orm import Session
from finguard.storage.models import TransactionRecord


class DestinationTracker:
    """Tracks destination history and classifies destination risk."""

    def __init__(self, session: Session):
        self.session = session

    def is_new_destination(self, actor_id: str, to_account: str) -> bool:
        """Check if to_account has ever been used by actor_id before.

        Returns True if first-seen destination.
        """
        count = (
            self.session.query(TransactionRecord)
            .filter(
                TransactionRecord.actor_id == actor_id,
                TransactionRecord.to_account == to_account,
                TransactionRecord.state == "signed",
            )
            .count()
        )
        return count == 0
