"""Bounded SDK: exposes requests and inspection, never signing or approval."""
from finguard.core.enums import ActorType, Currency
from finguard.core.transaction import Transaction
from finguard.decision import DecisionEngine
from finguard.storage.database import get_session
from finguard.storage.repositories import TransactionRepository


class FinGuardAgentClient:
    def __init__(self, actor_id: str = "treasury-agent", session_id: str | None = None):
        self.actor_id, self.session_id = actor_id, session_id or "agent-sdk"

    def create_transaction(self, amount: float, currency: str, destination: str, purpose: str, metadata: dict | None = None, from_account: str = "treasury", ai_assessment: dict | None = None):
        """Submit an untrusted request; AI fields are evidence only, never authority."""
        tx = Transaction(actor_id=self.actor_id, session_id=self.session_id, from_account=from_account, to_account=destination, amount=amount, currency=Currency(currency.upper()), metadata={**(metadata or {}), "purpose": purpose}, initiating_actor_type=ActorType.AGENT.value)
        return DecisionEngine().decide(tx, ai_assessment=ai_assessment)

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
