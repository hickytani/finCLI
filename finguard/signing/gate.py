"""Final authorization revalidation immediately before Ed25519 signing."""
import json

from finguard.approvals.service import ApprovalService
from finguard.audit.ledger import AuditLedger
from finguard.core.canonical import canonical_serialize
from finguard.core.enums import Currency, DecisionType, TransactionState
from finguard.core.errors import SecurityError
from finguard.core.state_machine import InvalidTransitionError, TransactionStateMachine
from finguard.core.transaction import Transaction
from finguard.crypto.hashing import sha256_hash
from finguard.crypto.keystore import Keystore
from finguard.crypto.signing import sign_canonical_bytes
from finguard.decision import DecisionEngine
from finguard.risk.engine import RiskEngine
from finguard.storage.database import get_session
from finguard.storage.repositories import AuditRepository, ReceiptRepository, TransactionRepository


class SigningGate:
    """The only application-level route from an authorized request to a signature."""

    def sign(self, transaction_id: str, key_id: str, password: str) -> str:
        session = get_session()
        try:
            rec = TransactionRepository(session).get(transaction_id)
            if not rec:
                raise SecurityError("Transaction not found")
            if rec.canonical_version != 2:
                raise SecurityError("Legacy transaction must be resubmitted before signing")
            try:
                TransactionStateMachine.validate_transition(rec.state, TransactionState.SIGNED)
            except InvalidTransitionError as exc:
                raise SecurityError("Transaction state does not permit signing") from exc
            # Reconstruct Transaction preferring exact minor units to avoid float round-trip
            if rec.amount_minor is None:
                raise SecurityError("Legacy transaction must be resubmitted before signing")
            from finguard.money import Money
            _gate_amount = Money(minor_units=rec.amount_minor, currency=rec.currency)
            tx = Transaction(transaction_id=rec.transaction_id, actor_id=rec.actor_id, session_id=rec.session_id, from_account=rec.from_account, to_account=rec.to_account, amount=_gate_amount, currency=Currency(rec.currency), nonce=rec.nonce, timestamp=rec.timestamp, metadata=json.loads(rec.metadata_json) if rec.metadata_json else None, idempotency_key=rec.idempotency_key, policy_version=rec.policy_version, state=TransactionState(rec.state))
            receipt_record = ReceiptRepository(session).get_by_transaction(transaction_id)
            if not receipt_record:
                raise SecurityError("No DecisionEngine receipt; direct signing is forbidden")
            receipt = json.loads(receipt_record.reason)
            ledger_valid, _, ledger_reason = AuditLedger(session=session).verify_integrity()
            if not ledger_valid:
                raise SecurityError(f"Decision audit ledger integrity check failed: {ledger_reason}")
            decision_entries = [
                entry for entry in AuditRepository(session).get_by_transaction(transaction_id)
                if entry.action == "DECISION"
            ]
            if len(decision_entries) != 1:
                raise SecurityError("Expected exactly one decision audit entry before signing")
            decision_evidence = json.loads(decision_entries[0].metadata_json or "{}")
            computed_receipt_hash = sha256_hash(canonical_serialize(receipt))
            if (
                decision_evidence.get("receipt_id") != receipt_record.receipt_id
                or decision_evidence.get("receipt_hash") != computed_receipt_hash
                or receipt_record.receipt_hash != computed_receipt_hash
            ):
                raise SecurityError("Decision receipt does not match its audit evidence")
        finally:
            session.close()

        # Integrity of the original decision evidence and all current controls.
        if rec.canonical_hash != tx.transaction_hash() or receipt["transaction_hash"] != tx.transaction_hash():
            raise SecurityError("Transaction integrity / authorization hash mismatch")
        registry = DecisionEngine().registry
        actor = registry.get_actor(tx.actor_id)
        if not actor or receipt.get("actor_type") != actor.actor_type.value:
            raise SecurityError("Identity or actor type changed")
        policy = DecisionEngine().policy_engine
        policy_hash = sha256_hash(canonical_serialize(policy.policy.model_dump(mode="json")))
        if receipt.get("policy_hash") != policy_hash or receipt.get("policy_version") != str(policy.policy.version):
            raise SecurityError("Policy changed since authorization")
        from decimal import Decimal
        from finguard.money import Money
        if tx.currency != actor.authority_currency:
            raise SecurityError("Transaction currency does not match actor authority currency")
        actor_limit_minor = Money.from_decimal(actor.authority_limit, actor.authority_currency).minor_units
        current_policy = policy.evaluate(tx, actor)
        if current_policy.decision_type == DecisionType.BLOCK or not (tx.amount_minor <= actor_limit_minor):
            raise SecurityError("Current authority or policy blocks transaction")
        if receipt.get("final_decision") == DecisionType.BLOCK.value:
            raise SecurityError("Blocked decisions cannot be signed")
        if current_policy.decision_type == DecisionType.REQUIRE_APPROVAL and not ApprovalService().verify_approval_integrity(tx):
            raise SecurityError("Required approval is invalid, stale, or mismatched")
        # A stored nonce must still belong to this exact transaction.
        session = get_session()
        try:
            from finguard.storage.repositories import NonceRepository
            nonce = NonceRepository(session).session.get(__import__("finguard.storage.models", fromlist=["NonceRecord"]).NonceRecord, tx.nonce)
            if not nonce or nonce.transaction_id != tx.transaction_id:
                raise SecurityError("Nonce replay state inconsistent")
            rec = TransactionRepository(session).get(transaction_id)
            if rec.state == TransactionState.SIGNED.value:
                raise SecurityError("Transaction is already signed")
            try:
                TransactionStateMachine.validate_transition(rec.state, TransactionState.SIGNED)
            except InvalidTransitionError as exc:
                raise SecurityError("Transaction state does not permit signing") from exc
            signature = sign_canonical_bytes(tx.canonical_bytes(), Keystore().load_private_key(key_id, password))
            rec.signature, rec.signing_key_id, rec.state = signature, key_id, TransactionState.SIGNED.value
            TransactionRepository(session).save(rec)
        finally:
            session.close()
        AuditLedger().append("SIGNING_GATE", tx.actor_id, tx.transaction_id, "SIGNED", {"key_id": key_id, "hash": tx.transaction_hash()})
        return signature
