"""Atomic, local-only settlement for transactions already signed by FinGuard.

The simulator is intentionally not an agent tool. It accepts only a stored
transaction ID and independently verifies the signed canonical transaction.
"""
import json
import uuid

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError as SqlIntegrityError
from sqlalchemy.exc import OperationalError

from finguard.approvals.service import ApprovalService
from finguard.audit.ledger import AuditLedger
from finguard.core.canonical import canonical_serialize
from finguard.core.enums import ActorType, Currency, TransactionState
from finguard.core.errors import SecurityError
from finguard.core.state_machine import TransactionStateMachine
from finguard.core.transaction import Transaction
from finguard.crypto.hashing import sha256_hash
from finguard.crypto.keystore import Keystore
from finguard.crypto.signing import verify_signature
from finguard.decision import DecisionEngine
from finguard.storage.database import get_session
from finguard.storage.models import SimulatorAccountRecord, SimulatorExecutionRecord
from finguard.storage.repositories import (
    ApprovalRepository,
    AuditRepository,
    ReceiptRepository,
    TransactionRepository,
)


class SimulatorError(SecurityError):
    """A refused synthetic settlement; no money movement occurred."""


class FinancialSimulator:
    """Settlement boundary for virtual INR accounts, never a real payment rail."""

    DEFAULT_ACCOUNTS = {
        "treasury": 1_000_000_000,  # 10,000,000.00 INR in paise
        "vendor-a": 0,
        "vendor-b": 0,
    }

    def bootstrap(self) -> None:
        """Idempotently create demo accounts; never overwrite existing balances."""
        session = get_session()
        try:
            for account_id, bal_minor in self.DEFAULT_ACCOUNTS.items():
                if not session.get(SimulatorAccountRecord, account_id):
                    session.add(SimulatorAccountRecord(account_id=account_id, currency="INR", balance_minor=bal_minor))
            session.commit()
        finally:
            session.close()

    def balances(self) -> list[dict]:
        self.bootstrap()
        session = get_session()
        try:
            return [
                {"account_id": account.account_id, "currency": account.currency, "balance_minor": account.balance_minor}
                for account in session.query(SimulatorAccountRecord).order_by(SimulatorAccountRecord.account_id).all()
            ]
        finally:
            session.close()

    @staticmethod
    def _verify_authority_evidence(session, record, transaction: Transaction) -> None:
        receipt_record = ReceiptRepository(session).get_by_transaction(record.transaction_id)
        if receipt_record is None:
            raise SimulatorError("Decision evidence is missing")

        try:
            receipt = json.loads(receipt_record.reason)
            receipt_hash = sha256_hash(canonical_serialize(receipt))
        except (TypeError, ValueError) as exc:
            raise SimulatorError("Decision evidence is invalid") from exc
        if (
            receipt_record.transaction_hash != transaction.transaction_hash()
            or receipt_record.transaction_version != receipt.get("transaction_version")
            or receipt.get("transaction_id") != transaction.transaction_id
            or receipt.get("transaction_hash") != transaction.transaction_hash()
            or receipt_record.receipt_hash != receipt_hash
            or receipt.get("authority_allowed") is not True
            or receipt.get("final_decision") not in {"allow", "require_approval"}
        ):
            raise SimulatorError("Decision evidence does not authorize this transaction")

        valid_ledger, _, reason = AuditLedger(session=session).verify_integrity()
        if not valid_ledger:
            raise SimulatorError(f"Decision audit evidence is invalid: {reason}")
        decision_entries = [
            entry
            for entry in AuditRepository(session).get_by_transaction(record.transaction_id)
            if entry.action == "DECISION"
        ]
        if len(decision_entries) != 1:
            raise SimulatorError("Decision audit evidence is missing or ambiguous")
        decision_evidence = json.loads(decision_entries[0].metadata_json or "{}")
        if (
            decision_evidence.get("receipt_id") != receipt_record.receipt_id
            or decision_evidence.get("receipt_hash") != receipt_hash
            or decision_evidence.get("transaction_hash") != transaction.transaction_hash()
            or decision_evidence.get("transaction_version") != receipt_record.transaction_version
        ):
            raise SimulatorError("Decision receipt is not bound to its audit evidence")

        signing_entries = [
            entry
            for entry in AuditRepository(session).get_by_transaction(record.transaction_id)
            if entry.action == "SIGNING_GATE"
        ]
        if len(signing_entries) != 1:
            raise SimulatorError("Signing audit evidence is missing or ambiguous")
        signing_evidence = json.loads(signing_entries[0].metadata_json or "{}")
        signer = next(
            (
                actor
                for actor in DecisionEngine().registry.list_actors()
                if actor.public_key == Keystore().get_public_key(record.signing_key_id)
                and actor.actor_id == signing_evidence.get("signer_actor_id")
            ),
            None,
        )
        if (
            signer is None
            or
            signing_evidence.get("hash") != transaction.transaction_hash()
            or signing_evidence.get("key_id") != record.signing_key_id
            or signing_evidence.get("signed_version") != record.signed_version
        ):
            raise SimulatorError("Signing evidence does not match the signed transaction version")

        decision_engine = DecisionEngine()
        policy = decision_engine.policy_engine
        policy_hash = sha256_hash(canonical_serialize(policy.policy.model_dump(mode="json")))
        actor = decision_engine.registry.get_actor(transaction.actor_id)
        if (
            not actor
            or receipt.get("actor_type") != actor.actor_type.value
            or receipt.get("policy_hash") != policy_hash
            or receipt.get("policy_version") != str(policy.policy.version)
        ):
            raise SimulatorError("Decision identity or policy authorization is stale")

        approval_request = ApprovalRepository(session).get_request(record.transaction_id)
        if approval_request:
            if (
                approval_request.transaction_hash != transaction.transaction_hash()
                or approval_request.transaction_version != receipt_record.transaction_version
                or approval_request.transaction_version + 1 != transaction.revision
            ):
                raise SimulatorError("Approval request is not bound to the signed transaction version")
        elif receipt_record.transaction_version != transaction.revision:
            raise SimulatorError("Decision is not bound to the signed transaction version")

        from finguard.money import Money
        source_allowed = transaction.from_account in actor.allowed_source_accounts or (
            "*" in actor.allowed_source_accounts and actor.actor_type != ActorType.AGENT
        )
        destination_allowed = transaction.to_account in actor.allowed_destinations or (
            "*" in actor.allowed_destinations and actor.actor_type != ActorType.AGENT
        )
        limit_minor = Money.from_decimal(actor.authority_limit, actor.authority_currency).minor_units
        if (
            not source_allowed
            or not destination_allowed
            or transaction.currency != actor.authority_currency
            or not (transaction.amount_minor <= limit_minor)
        ):
            raise SimulatorError("Current authority does not authorize this transaction")

        current_policy = policy.evaluate(transaction, actor)
        if current_policy.decision_type.value == "block":
            raise SimulatorError("Current policy does not authorize this transaction")
        approval_required = (
            receipt.get("final_decision") == "require_approval"
            or current_policy.decision_type.value == "require_approval"
        )
        if approval_required and not ApprovalService(session=session).verify_approval_integrity(transaction):
            raise SimulatorError("Approval evidence is missing, stale, or invalid")

    def execute(self, transaction_id: str) -> dict:
        """Settle one valid signed transaction atomically using exact minor unit arithmetic."""
        self.bootstrap()
        session = get_session()
        try:
            record = TransactionRepository(session).get(transaction_id)
            if not record:
                raise SimulatorError("Transaction not found")
            if record.state != TransactionState.SIGNED.value:
                raise SimulatorError("Only a SigningGate-signed transaction may execute")
            TransactionStateMachine.validate_transition(record.state, TransactionState.EXECUTED)
            if record.signed_version is None or record.version != record.signed_version:
                raise SimulatorError("Signed transaction version is stale")
            if record.canonical_version != 2:
                raise SimulatorError("Legacy transaction cannot be executed")
            if session.query(SimulatorExecutionRecord).filter_by(transaction_id=transaction_id).first():
                raise SimulatorError("Transaction was already executed")
            if not record.signature or not record.signing_key_id:
                raise SimulatorError("Signed transaction is missing signature evidence")

            if record.amount_minor is None:
                raise SimulatorError("Legacy transaction must be resubmitted before execution")
            from finguard.money import Money
            tx = Transaction(
                transaction_id=record.transaction_id, actor_id=record.actor_id, session_id=record.session_id,
                from_account=record.from_account, to_account=record.to_account,
                amount=Money(minor_units=record.amount_minor, currency=record.currency),
                currency=Currency(record.currency), nonce=record.nonce, timestamp=record.timestamp,
                metadata=json.loads(record.metadata_json) if record.metadata_json else None,
                idempotency_key=record.idempotency_key, policy_version=record.policy_version,
                state=TransactionState(record.state), revision=record.signed_version - 1,
            )
            if record.canonical_hash != tx.transaction_hash():
                raise SimulatorError("Stored transaction no longer matches its canonical authorization hash")
            self._verify_authority_evidence(session, record, tx)
            try:
                verify_signature(tx.canonical_bytes(), record.signature, bytes.fromhex(Keystore().get_public_key(record.signing_key_id)))
            except Exception as exc:
                raise SimulatorError("Transaction signature is invalid") from exc

            debit = session.execute(
                update(SimulatorAccountRecord)
                .where(SimulatorAccountRecord.account_id == tx.from_account, SimulatorAccountRecord.currency == tx.currency.value,
                       SimulatorAccountRecord.active.is_(True), SimulatorAccountRecord.balance_minor >= tx.amount_minor)
                .values(balance_minor=SimulatorAccountRecord.balance_minor - tx.amount_minor)
            )
            if debit.rowcount != 1:
                session.rollback()
                raise SimulatorError("Source account is unavailable or has insufficient synthetic funds")
            credit = session.execute(
                update(SimulatorAccountRecord)
                .where(SimulatorAccountRecord.account_id == tx.to_account, SimulatorAccountRecord.currency == tx.currency.value,
                       SimulatorAccountRecord.active.is_(True))
                .values(balance_minor=SimulatorAccountRecord.balance_minor + tx.amount_minor)
            )
            if credit.rowcount != 1:
                session.rollback()
                raise SimulatorError("Destination account is unavailable or currency-incompatible")
            session.add(SimulatorExecutionRecord(
                execution_id=f"SIM-{uuid.uuid4().hex[:12].upper()}", transaction_id=tx.transaction_id,
                transaction_hash=tx.transaction_hash(), signature=record.signature,
            ))
            if not TransactionRepository(session).compare_and_swap_state(
                transaction_id,
                expected_version=record.version,
                new_state=TransactionState.EXECUTED,
                commit=False,
            ):
                session.rollback()
                raise SimulatorError("Transaction changed during execution; settlement was rejected")
            session.commit()
        except (SqlIntegrityError, OperationalError) as exc:
            session.rollback()
            raise SimulatorError("Concurrent or replayed execution was rejected") from exc
        finally:
            session.close()

        evidence = {"transaction_hash": tx.transaction_hash(), "source": tx.from_account, "destination": tx.to_account, "amount": tx.money.to_decimal_string(), "amount_minor": tx.amount_minor, "currency": tx.currency.value}
        AuditLedger().append("SIMULATOR_EXECUTE", tx.actor_id, tx.transaction_id, "EXECUTED", evidence)
        return {"status": "executed", "transaction_id": tx.transaction_id, **evidence}
