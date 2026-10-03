import pytest

from finguard.agent_sdk import FinGuardAgentClient
from finguard.core.enums import DecisionType
from finguard.core.transaction import Transaction
from finguard.decision import DecisionEngine
from finguard.storage.database import get_session
from finguard.storage.models import (
    AuditEntryRecord,
    DecisionReceiptRecord,
    NonceRecord,
    TransactionRecord,
)


def test_authority_violation_blocks():
    result = FinGuardAgentClient().create_transaction(50000, "INR", "vendor-a", "test")
    assert result.decision == DecisionType.BLOCK
    assert result.receipt.authority_allowed is False


def test_unknown_identity_fails_closed():
    tx = Transaction(actor_id="not-real", from_account="treasury", to_account="vendor-a", amount=1)
    assert DecisionEngine().decide(tx).decision == DecisionType.BLOCK


def test_sdk_has_no_sign_or_self_approve():
    client = FinGuardAgentClient()
    assert not hasattr(client, "sign_transaction")
    assert not hasattr(client, "self_approve")


def test_decision_blocks_actor_authority_currency_mismatch():
    from finguard.core.enums import Currency
    from finguard.identity.registry import IdentityRegistry

    registry = IdentityRegistry()
    tx = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="1.00", currency=Currency.USD,
    )
    decision = DecisionEngine(registry=registry).decide(tx)
    assert decision.decision == DecisionType.BLOCK
    assert decision.receipt.authority_allowed is False


def test_successful_decision_commits_state_nonce_receipt_and_audit_together():
    transaction = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a", amount="12.00"
    )

    result = DecisionEngine().decide(transaction)

    session = get_session()
    try:
        stored_transaction = session.get(TransactionRecord, transaction.transaction_id)
        assert stored_transaction is not None
        assert stored_transaction.state == result.transaction.state.value
        assert session.get(NonceRecord, transaction.nonce) is not None
        stored_receipt = session.query(DecisionReceiptRecord).filter_by(
            transaction_id=transaction.transaction_id
        ).one()
        assert stored_receipt.receipt_hash == result.receipt.receipt_hash()
        decision_entries = session.query(AuditEntryRecord).filter_by(
            transaction_id=transaction.transaction_id, action="DECISION"
        ).all()
        assert len(decision_entries) == 1
        assert result.receipt.receipt_hash() in decision_entries[0].metadata_json
    finally:
        session.close()


@pytest.mark.parametrize(
    "failure_stage",
    [
        "after_validation",
        "after_lifecycle_transition",
        "after_receipt_evidence",
        "before_commit",
    ],
)
def test_decision_failure_rolls_back_all_security_state(monkeypatch, failure_stage):
    transaction = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="12.00", idempotency_key="decision-crash-retry",
    )
    retry_request = Transaction(
        transaction_id=transaction.transaction_id,
        actor_id=transaction.actor_id,
        session_id=transaction.session_id,
        from_account=transaction.from_account,
        to_account=transaction.to_account,
        amount=transaction.money,
        currency=transaction.currency,
        nonce=transaction.nonce,
        timestamp=transaction.timestamp,
        metadata=transaction.metadata,
        idempotency_key=transaction.idempotency_key,
        policy_version=transaction.policy_version,
    )

    def inject(stage):
        if stage == failure_stage:
            raise RuntimeError(f"injected failure: {stage}")

    monkeypatch.setattr(DecisionEngine, "_decision_checkpoint", staticmethod(inject))
    result = DecisionEngine().decide(transaction)
    assert result.decision == DecisionType.BLOCK

    session = get_session()
    try:
        assert session.get(TransactionRecord, transaction.transaction_id) is None
        assert session.get(NonceRecord, transaction.nonce) is None
        assert session.query(DecisionReceiptRecord).filter_by(
            transaction_id=transaction.transaction_id
        ).count() == 0
        assert session.query(AuditEntryRecord).filter_by(
            transaction_id=transaction.transaction_id, action="DECISION"
        ).count() == 0
    finally:
        session.close()

    monkeypatch.setattr(DecisionEngine, "_decision_checkpoint", staticmethod(lambda _stage: None))
    retry = DecisionEngine().decide(retry_request)
    assert retry.decision == DecisionType.ALLOW
    session = get_session()
    try:
        assert session.get(TransactionRecord, transaction.transaction_id) is not None
        assert session.get(NonceRecord, transaction.nonce) is not None
        assert session.query(DecisionReceiptRecord).filter_by(
            transaction_id=transaction.transaction_id
        ).count() == 1
        assert session.query(AuditEntryRecord).filter_by(
            transaction_id=transaction.transaction_id, action="DECISION"
        ).count() == 1
    finally:
        session.close()
