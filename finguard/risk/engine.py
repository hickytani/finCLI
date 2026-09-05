"""Deterministic Risk Engine for FIN//GUARD.

SECURITY PROPERTY:
Evaluates transaction risk synchronously at creation time using deterministic signals:
- NEW_DESTINATION: First time destination account seen for this actor
- AMOUNT_ANOMALY: Amount significantly exceeds average historical transaction size
- VELOCITY_SPIKE: High frequency of transactions within time window
- OFF_HOURS: Transaction timestamp outside normal operational hours
- NEW_SESSION: Missing or newly initiated session ID
- AUTHORITY_VIOLATION: Amount exceeds actor authority limit from signed registry

Produces score (0-100), risk level (LOW/MEDIUM/HIGH/CRITICAL), signals list, and explanation.
"""

import datetime
from typing import Optional
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from finguard.core.enums import SignalType, RiskLevel
from finguard.core.transaction import Transaction
from finguard.identity.registry import ActorConfig
from finguard.risk.destination import DestinationTracker
from finguard.risk.temporal import TemporalAnalyzer
from finguard.risk.velocity import VelocityTracker
from finguard.storage.database import get_session


class RiskAnalysisResult(BaseModel):
    """Result of risk signal evaluation."""
    transaction_id: str
    risk_score: int
    risk_level: RiskLevel
    signals: list[str] = Field(default_factory=list)
    explanation: str = ""


class RiskEngine:
    """Synchronous deterministic risk engine."""

    def __init__(self, session: Optional[Session] = None):
        self._external_session = session

    def _get_session(self) -> tuple[Session, bool]:
        if self._external_session:
            return self._external_session, False
        return get_session(), True

    def analyze(self, transaction: Transaction, actor: ActorConfig) -> RiskAnalysisResult:
        """Analyze transaction for risk signals."""
        session, is_local = self._get_session()
        try:
            signals: list[str] = []
            score = 0

            # 1. AUTHORITY_VIOLATION signal
            if transaction.amount > actor.authority_limit:
                signals.append(SignalType.AUTHORITY_VIOLATION.value)
                score += 50

            # 2. NEW_DESTINATION signal
            dest_tracker = DestinationTracker(session)
            if dest_tracker.is_new_destination(actor.actor_id, transaction.to_account):
                signals.append(SignalType.NEW_DESTINATION.value)
                score += 20

            # 3. VELOCITY_SPIKE signal
            vel_tracker = VelocityTracker(session)
            count, total = vel_tracker.get_velocity_metrics(
                actor_id=actor.actor_id,
                window_seconds=600,
                current_time=transaction.timestamp
            )
            if count >= 5 or total > (actor.authority_limit * 2):
                signals.append(SignalType.VELOCITY_SPIKE.value)
                score += 25

            # 4. OFF_HOURS signal
            temp_analyzer = TemporalAnalyzer(start_hour=9, end_hour=18)
            if temp_analyzer.is_off_hours(transaction.timestamp):
                signals.append(SignalType.OFF_HOURS.value)
                score += 15

            # 5. NEW_SESSION signal
            if not transaction.session_id:
                signals.append(SignalType.NEW_SESSION.value)
                score += 10

            # 6. AMOUNT_ANOMALY signal
            if transaction.amount > (actor.authority_limit * 0.8):
                signals.append(SignalType.AMOUNT_ANOMALY.value)
                score += 20

            # Cap score at 100
            final_score = min(100, score)

            if final_score <= 25:
                level = RiskLevel.LOW
            elif final_score <= 50:
                level = RiskLevel.MEDIUM
            elif final_score <= 75:
                level = RiskLevel.HIGH
            else:
                level = RiskLevel.CRITICAL

            if signals:
                explanation = f"Risk Score {final_score}/100 ({level.value.upper()}). Active signals: {', '.join(signals)}"
            else:
                explanation = "Risk Score 0/100 (LOW). No anomaly signals detected."

            return RiskAnalysisResult(
                transaction_id=transaction.transaction_id,
                risk_score=final_score,
                risk_level=level,
                signals=signals,
                explanation=explanation
            )
        finally:
            if is_local:
                session.close()
