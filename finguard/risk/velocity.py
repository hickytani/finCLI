"""Velocity tracking engine for FIN//GUARD.

Tracks transaction frequency and cumulative amount within time windows
to detect velocity spikes and potential abuse.
"""

import datetime
from sqlalchemy.orm import Session
from finguard.storage.repositories import TransactionRepository


class VelocityTracker:
    """Calculates transaction velocity metrics for actors."""

    def __init__(self, session: Session):
        self.repo = TransactionRepository(session)

    def get_velocity_metrics(self, actor_id: str, window_seconds: int = 600, current_time: datetime.datetime | None = None) -> tuple[int, float]:
        """Compute transaction count and cumulative amount in the time window.

        Args:
            actor_id: Actor identifier.
            window_seconds: Time window duration in seconds.
            current_time: Reference timestamp for deterministic testing.

        Returns:
            Tuple of (count, cumulative_amount).
        """
        now = current_time or datetime.datetime.now(datetime.timezone.utc)
        if now.tzinfo is not None:
            # Strip timezone for SQLite comparison if naive datetime is used in DB
            now = now.replace(tzinfo=None)

        since = now - datetime.timedelta(seconds=window_seconds)

        count = self.repo.count_in_window(actor_id, since)
        total_amount = self.repo.sum_in_window(actor_id, since)

        return count, total_amount
