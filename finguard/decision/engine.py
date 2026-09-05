"""Central transaction authorization pipeline.

No caller (CLI, SDK, or agent) is an authority.  This module is the only
supported entry point for creating an authorization decision.  AI/ML inputs
are advisory signals; identity, authority, policy, nonce, and approvals remain
deterministic controls.
"""

import datetime
import json
import uuid
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError as SqlIntegrityError

from finguard.approvals.service import ApprovalService
from finguard.audit.ledger import AuditLedger
from finguard.core.canonical import canonical_serialize
from finguard.core.enums import DecisionType, TransactionState
from finguard.core.transaction import Transaction
from finguard.crypto.hashing import sha256_hash
from finguard.identity.registry import IdentityRegistry
from finguard.policy.engine import PolicyEngine
from finguard.risk.engine import RiskEngine
from finguard.storage.database import get_session
from finguard.storage.models import ActorRecord, DecisionReceiptRecord, TransactionRecord
from finguard.storage.repositories import ActorRepository, NonceRepository, ReceiptRepository, TransactionRepository


class DecisionReceipt(BaseModel):
    receipt_version: str = "2.0"
    receipt_id: str = Field(default_factory=lambda: f"RCT-{uuid.uuid4().hex[:12].upper()}")
    transaction_id: str
    transaction_hash: str
    actor_id: str
    actor_type: str | None = None
    amount: float | None = None
    destination: str | None = None
    authority_allowed: bool = False
    authority_reasons: list[str] = Field(default_factory=list)
    policy_id: str | None = None
    policy_version: str | None = None
    policy_hash: str | None = None
    policy_integrity: str = "VALID"
    deterministic_risk: dict[str, Any] = Field(default_factory=dict)
    ml_assessment: dict[str, Any] = Field(default_factory=lambda: {"status": "NOT_CONFIGURED"})
    ai_assessment: dict[str, Any] = Field(default_factory=lambda: {"status": "NOT_PROVIDED"})
    approval_requirement: int = 0
    approval_state: str = "not_required"
    final_decision: str
    reasons: list[str] = Field(default_factory=list)
    timestamp: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))

    def receipt_hash(self) -> str:
        return sha256_hash(canonical_serialize(self.model_dump(mode="json")))


class DecisionResult(BaseModel):
    decision: DecisionType
    transaction: Transaction
    receipt: DecisionReceipt


class DecisionEngine:
    """Evaluates and persists a transaction once, with a receipt and audit evidence."""

    def __init__(self, registry: IdentityRegistry | None = None, policy_engine: PolicyEngine | None = None):
        self.registry = registry or IdentityRegistry()
        self.policy_engine = policy_engine or PolicyEngine()

    def decide(self, transaction: Transaction, ai_assessment: dict[str, Any] | None = None) -> DecisionResult:
        """Fail closed for every invalid identity, replay, persistence, or evaluator error."""
        actor = None
        reasons: list[str] = []
        try:
            actor = self.registry.get_actor(transaction.actor_id)
            if not actor:
                raise ValueError("Unknown identity")
            if transaction.initiating_actor_type and transaction.initiating_actor_type != actor.actor_type.value:
                raise ValueError("Actor type claim does not match signed identity")

            policy_hash = sha256_hash(canonical_serialize(self.policy_engine.policy.model_dump(mode="json")))
            authority_allowed = transaction.amount <= actor.authority_limit and (
                not actor.allowed_destinations or "*" in actor.allowed_destinations or transaction.to_account in actor.allowed_destinations
            ) and actor.active
            authority_reasons = ["Authority checks passed"] if authority_allowed else ["Signed identity authority violation"]

            # Atomic nonce claim: the UNIQUE constraint is the replay boundary.
            session = get_session()
            try:
                if not ActorRepository(session).get(actor.actor_id):
                    ActorRepository(session).save(ActorRecord(actor_id=actor.actor_id, actor_type=actor.actor_type.value, display_name=actor.display_name, active=actor.active))
                session.add(TransactionRecord(transaction_id=transaction.transaction_id, actor_id=transaction.actor_id, session_id=transaction.session_id, from_account=transaction.from_account, to_account=transaction.to_account, amount=transaction.amount, currency=transaction.currency.value, nonce=transaction.nonce, timestamp=transaction.timestamp, metadata_json=json.dumps(transaction.metadata, sort_keys=True) if transaction.metadata else None, state=TransactionState.CREATED.value, canonical_hash=transaction.transaction_hash(), policy_version=transaction.policy_version))
                session.add(__import__("finguard.storage.models", fromlist=["NonceRecord"]).NonceRecord(nonce=transaction.nonce, transaction_id=transaction.transaction_id))
                session.commit()
            except SqlIntegrityError as exc:
                session.rollback()
                raise ValueError("Replay or persistence integrity violation") from exc
            finally:
                session.close()

            risk = RiskEngine().analyze(transaction, actor)
            policy = self.policy_engine.evaluate(transaction, actor, risk.model_dump())
            decision = DecisionType.BLOCK if not authority_allowed else policy.decision_type
            reasons = authority_reasons + policy.reasons
            state = {DecisionType.BLOCK: TransactionState.BLOCKED, DecisionType.REQUIRE_APPROVAL: TransactionState.PENDING_APPROVAL, DecisionType.ALLOW: TransactionState.CREATED}[decision]
            transaction.state = state
            approval_state = "not_required"
            if decision == DecisionType.REQUIRE_APPROVAL:
                ApprovalService().create_approval_request(transaction, policy.required_approvals, transaction.actor_id)
                approval_state = "pending"
            self._set_state(transaction.transaction_id, state)
            receipt = DecisionReceipt(transaction_id=transaction.transaction_id, transaction_hash=transaction.transaction_hash(), actor_id=actor.actor_id, actor_type=actor.actor_type.value, amount=transaction.amount, destination=transaction.to_account, authority_allowed=authority_allowed, authority_reasons=authority_reasons, policy_id=policy.policy_id, policy_version=str(policy.policy_version), policy_hash=policy_hash, deterministic_risk=risk.model_dump(mode="json"), ai_assessment=ai_assessment or {"status": "NOT_PROVIDED"}, approval_requirement=policy.required_approvals, approval_state=approval_state, final_decision=decision.value, reasons=reasons)
        except Exception as exc:
            # Never convert an exception to ALLOW. A receipt is still emitted where possible.
            transaction.state = TransactionState.BLOCKED
            reason = f"FAIL_CLOSED: {type(exc).__name__}: {exc}"
            receipt = DecisionReceipt(transaction_id=transaction.transaction_id, transaction_hash=transaction.transaction_hash(), actor_id=transaction.actor_id, actor_type=actor.actor_type.value if actor else None, amount=transaction.amount, destination=transaction.to_account, authority_allowed=False, authority_reasons=[reason], policy_integrity="UNKNOWN", ai_assessment=ai_assessment or {"status": "NOT_PROVIDED"}, final_decision=DecisionType.BLOCK.value, reasons=[reason])
            decision = DecisionType.BLOCK
            self._set_state(transaction.transaction_id, TransactionState.BLOCKED, tolerate_missing=True)
        # Unknown identities cannot satisfy the receipt table's transaction FK;
        # audit still records the attempted decision without inventing an actor.
        try:
            self._persist_receipt(receipt)
        except Exception:
            decision = DecisionType.BLOCK
        try:
            AuditLedger().append("DECISION", transaction.actor_id, transaction.transaction_id, receipt.final_decision.upper(), {"receipt_id": receipt.receipt_id, "receipt_hash": receipt.receipt_hash(), "reasons": receipt.reasons})
        except Exception:
            # Audit is evidence-bearing: retain fail-closed decision even if the evidence store failed.
            decision = DecisionType.BLOCK
        return DecisionResult(decision=decision, transaction=transaction, receipt=receipt)

    @staticmethod
    def _set_state(transaction_id: str, state: TransactionState, tolerate_missing: bool = False) -> None:
        session = get_session()
        try:
            record = TransactionRepository(session).get(transaction_id)
            if record:
                record.state = state.value
                TransactionRepository(session).save(record)
            elif not tolerate_missing:
                raise ValueError("Transaction persistence failure")
        finally:
            session.close()

    @staticmethod
    def _persist_receipt(receipt: DecisionReceipt) -> None:
        session = get_session()
        try:
            latest = ReceiptRepository(session).get_latest()
            ReceiptRepository(session).save(DecisionReceiptRecord(receipt_id=receipt.receipt_id, transaction_id=receipt.transaction_id, transaction_hash=receipt.transaction_hash, actor_id=receipt.actor_id, policy_id=receipt.policy_id, policy_version=receipt.policy_version, matched_rules=json.dumps(receipt.reasons), security_signals=json.dumps(receipt.deterministic_risk), risk_score=receipt.deterministic_risk.get("risk_score"), risk_level=receipt.deterministic_risk.get("risk_level"), approval_state=receipt.approval_state, decision=receipt.final_decision, reason=json.dumps(receipt.model_dump(mode="json"), sort_keys=True), timestamp=receipt.timestamp.replace(tzinfo=None), previous_receipt_hash=latest.receipt_hash if latest else None, receipt_hash=receipt.receipt_hash()))
        finally:
            session.close()
