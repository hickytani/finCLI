"""Temporal anomaly analyzer for FIN//GUARD.

Detects transactions occurring outside defined normal operating hours.
"""

import datetime


class TemporalAnalyzer:
    """Analyzes transaction timestamp for temporal anomalies."""

    def __init__(self, start_hour: int = 9, end_hour: int = 18):
        self.start_hour = start_hour
        self.end_hour = end_hour

    def is_off_hours(self, timestamp: datetime.datetime) -> bool:
        """Check if timestamp falls outside operating hours (e.g. 09:00 - 18:00)."""
        hour = timestamp.hour
        return hour < self.start_hour or hour >= self.end_hour
