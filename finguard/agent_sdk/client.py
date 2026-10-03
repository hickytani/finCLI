"""Bounded SDK: proposals enter through the structured-intent boundary."""
from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from finguard.decision import DecisionResult
from finguard.storage.database import get_session
from finguard.storage.repositories import TransactionRepository

if TYPE_CHECKING:
    from finguard.agent.intent import StructuredIntent


class FinGuardAgentClient:
    def __init__(self, actor_id: str = "treasury-agent", session_id: str | None = None):
        self.actor_id, self.session_id = actor_id, session_id or "agent-sdk"

    def create_transaction(
        self,
        amount: str | int,
        currency: str,
        destination: str,
        purpose: str,
        metadata: dict[str, Any] | None = None,
        from_account: str = "treasury",
        ai_assessment: dict[str, Any] | None = None,
    ) -> DecisionResult:
        """Submit an untrusted request; AI fields are evidence only, never authority."""
        context = dict(metadata or {})
        context.pop("purpose", None)
        intent = {
            "schema_version": 1,
            "intent_id": str(uuid.uuid4()),
            "correlation_id": str(uuid.uuid4()),
            "action": "propose_transaction",
            "capability": "transaction.propose",
            "from_account": from_account,
            "recipient": destination,
            "amount": amount,
            "currency": currency.upper(),
            "reason": purpose,
            "context": context,
        }
        return self.submit_intent(intent, ai_assessment=ai_assessment)

    def submit_intent(
        self,
        intent: StructuredIntent | dict[str, Any] | str | bytes,
        *,
        ai_assessment: dict[str, Any] | None = None,
    ) -> DecisionResult:
        """Submit a raw agent proposal through strict validation and the core."""
        from finguard.agent.intent import StructuredIntentBoundary

        return StructuredIntentBoundary(
            actor_id=self.actor_id,
            session_id=self.session_id,
        ).submit(intent, ai_assessment=ai_assessment)

    def inspect_transaction(self, transaction_id: str):
        session = get_session()
        try:
            record = TransactionRepository(session).get(transaction_id)
            return None if not record else {"transaction_id": record.transaction_id, "state": record.state, "hash": record.canonical_hash}
        finally:
            session.close()

    check_status = inspect_transaction

    def analyze_transaction(self, **kwargs):
        return self.create_transaction(**kwargs)

    def request_approval(self, transaction_id: str):
        # Only returns state; approval itself is intentionally not an agent capability.
        return self.inspect_transaction(transaction_id)
