"""Bounded SDK: proposals enter through the structured-intent boundary."""
from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING, Any

from finguard.audit.ledger import AuditLedger
from finguard.core.enums import Currency, DecisionType, TransactionState
from finguard.core.transaction import Transaction
from finguard.decision import DecisionReceipt, DecisionResult
from finguard.money import Money
from finguard.storage.database import get_session
from finguard.storage.models import ActorRecord, DecisionReceiptRecord, TransactionRecord
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
        try:
            from finguard.agent.intent import StructuredIntentBoundary
            return StructuredIntentBoundary(
                actor_id=self.actor_id,
                session_id=self.session_id,
            ).submit(intent, ai_assessment=ai_assessment)
        except Exception as exc:
            from finguard.agent.intent import IntentValidationError
            if not isinstance(exc, IntentValidationError):
                raise
            raw = intent
            if isinstance(intent, dict):
                raw = intent
            elif isinstance(intent, str):
                try:
                    raw = json.loads(intent)
                except (TypeError, ValueError, json.JSONDecodeError):
                    raw = {}
            elif isinstance(intent, bytes):
                try:
                    raw = json.loads(intent.decode("utf-8"))
                except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
                    raw = {}
            else:
                raw = {}

            if not isinstance(raw, dict):
                raw = {}

            currency = Currency(str(raw.get("currency", "INR")).upper())
            destination = str(raw.get("recipient") or raw.get("to_account") or "vendor-a")
            purpose = str(raw.get("reason") or raw.get("purpose") or "rejected agent request")
            tx = Transaction(
                actor_id=self.actor_id,
                session_id=self.session_id,
                from_account=str(raw.get("from_account") or "treasury"),
                to_account=destination,
                amount=Money.from_decimal(raw.get("amount", 0), currency),
                currency=currency,
                metadata={"purpose": purpose, "rejection_code": exc.code, "reasons": list(exc.reasons)},
                initiating_actor_type="AGENT",
            )
            tx.state = TransactionState.BLOCKED
            receipt = DecisionReceipt(
                transaction_id=tx.transaction_id,
                canonical_version=2,
                transaction_version=tx.revision,
                transaction_hash=tx.transaction_hash(),
                actor_id=tx.actor_id,
                actor_type="AGENT",
                amount=tx.money.to_decimal_string(),
                amount_minor=tx.amount_minor,
                currency=tx.currency.value,
                destination=tx.to_account,
                authority_allowed=False,
                authority_reasons=list(exc.reasons),
                ai_assessment=ai_assessment or {"status": "REJECTED_BY_FINGUARD"},
                final_decision=DecisionType.BLOCK.value,
                reasons=list(exc.reasons),
            )
            session = get_session()
            try:
                with session.begin():
                    if not session.get(ActorRecord, tx.actor_id):
                        session.add(ActorRecord(
                            actor_id=tx.actor_id,
                            actor_type="AGENT",
                            display_name=self.actor_id,
                            active=True,
                        ))
                        session.flush()
                    session.add(
                        TransactionRecord(
                            transaction_id=tx.transaction_id,
                            actor_id=tx.actor_id,
                            session_id=tx.session_id,
                            from_account=tx.from_account,
                            to_account=tx.to_account,
                            amount=float(tx.money.to_decimal_string()),
                            amount_minor=tx.amount_minor,
                            canonical_version=2,
                            currency=tx.currency.value,
                            nonce=tx.nonce,
                            timestamp=tx.timestamp,
                            metadata_json=json.dumps(tx.metadata, sort_keys=True) if tx.metadata else None,
                            state=TransactionState.BLOCKED.value,
                            version=1,
                            canonical_hash=tx.transaction_hash(),
                            failure_reason=exc.code,
                        )
                    )
                    latest = session.query(DecisionReceiptRecord).order_by(DecisionReceiptRecord.timestamp.desc()).first()
                    session.add(
                        DecisionReceiptRecord(
                            receipt_id=receipt.receipt_id,
                            transaction_id=receipt.transaction_id,
                            transaction_hash=receipt.transaction_hash,
                            transaction_version=receipt.transaction_version,
                            canonical_version=receipt.canonical_version,
                            actor_id=receipt.actor_id,
                            policy_id=receipt.policy_id,
                            policy_version=receipt.policy_version,
                            matched_rules=json.dumps(receipt.reasons, sort_keys=True),
                            security_signals=json.dumps(receipt.deterministic_risk, sort_keys=True),
                            risk_score=receipt.deterministic_risk.get("risk_score"),
                            risk_level=receipt.deterministic_risk.get("risk_level"),
                            approval_state=receipt.approval_state,
                            decision=receipt.final_decision,
                            reason=json.dumps(receipt.model_dump(mode="json"), sort_keys=True),
                            timestamp=receipt.timestamp.replace(tzinfo=None),
                            previous_receipt_hash=latest.receipt_hash if latest else None,
                            receipt_hash=receipt.receipt_hash(),
                        )
                    )
                    AuditLedger(session=session).append(
                        "DECISION",
                        tx.actor_id,
                        tx.transaction_id,
                        "BLOCK",
                        {
                            "receipt_id": receipt.receipt_id,
                            "receipt_hash": receipt.receipt_hash(),
                            "transaction_hash": receipt.transaction_hash,
                            "transaction_version": receipt.transaction_version,
                            "reasons": receipt.reasons,
                        },
                        commit=False,
                    )
            finally:
                session.close()
            return DecisionResult(decision=DecisionType.BLOCK, transaction=tx, receipt=receipt)

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
