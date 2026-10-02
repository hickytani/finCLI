"""Atomic, local-only settlement for transactions already signed by FinGuard.

The simulator is intentionally not an agent tool. It accepts only a stored
transaction ID and independently verifies the signed canonical transaction.
"""
import json
import uuid

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError as SqlIntegrityError

from finguard.audit.ledger import AuditLedger
from finguard.core.enums import Currency, TransactionState
from finguard.core.errors import SecurityError
from finguard.core.transaction import Transaction
from finguard.crypto.keystore import Keystore
from finguard.crypto.signing import verify_signature
from finguard.storage.database import get_session
from finguard.storage.models import SimulatorAccountRecord, SimulatorExecutionRecord
from finguard.storage.repositories import TransactionRepository


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
            )
            if record.canonical_hash != tx.transaction_hash():
                raise SimulatorError("Stored transaction no longer matches its canonical authorization hash")
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
            record.state = TransactionState.EXECUTED.value
            session.commit()
        except SqlIntegrityError as exc:
            session.rollback()
            raise SimulatorError("Concurrent or replayed execution was rejected") from exc
        finally:
            session.close()

        evidence = {"transaction_hash": tx.transaction_hash(), "source": tx.from_account, "destination": tx.to_account, "amount": tx.money.to_decimal_string(), "amount_minor": tx.amount_minor, "currency": tx.currency.value}
        AuditLedger().append("SIMULATOR_EXECUTE", tx.actor_id, tx.transaction_id, "EXECUTED", evidence)
        return {"status": "executed", "transaction_id": tx.transaction_id, **evidence}
