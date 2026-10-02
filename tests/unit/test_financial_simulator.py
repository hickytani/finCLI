"""End-to-end tests for the FinGuard-controlled local financial simulator."""
import pytest

from finguard.core.enums import ActorType, Currency
from finguard.core.transaction import Transaction
from finguard.crypto.keystore import Keystore
from finguard.decision import DecisionEngine
from finguard.signing import SigningGate
from finguard.simulator import FinancialSimulator, SimulatorError
from finguard.storage.database import get_session
from finguard.storage.models import AuditEntryRecord, SimulatorExecutionRecord, TransactionRecord


def _operator_transaction(amount="500.00"):
    return Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a", amount=amount,
        currency=Currency.INR, initiating_actor_type=ActorType.HUMAN_OPERATOR.value,
    )


def test_only_signed_transaction_can_move_synthetic_money(bind_actor_key):
    simulator = FinancialSimulator()
    before = {item["account_id"]: item["balance_minor"] for item in simulator.balances()}
    result = DecisionEngine().decide(_operator_transaction())
    with pytest.raises(SimulatorError, match="SigningGate-signed"):
        simulator.execute(result.transaction.transaction_id)
    assert {item["account_id"]: item["balance_minor"] for item in simulator.balances()} == before

    Keystore().create_keypair("operator-key", "test-password")
    bind_actor_key("operator-1", "operator-key")
    SigningGate().sign(result.transaction.transaction_id, "operator-key", "test-password")
    settlement = simulator.execute(result.transaction.transaction_id)
    after = {item["account_id"]: item["balance_minor"] for item in simulator.balances()}

    assert settlement["status"] == "executed"
    assert result.receipt.amount_minor == 50000
    assert result.receipt.transaction_hash == result.transaction.transaction_hash()
    assert after["treasury"] == before["treasury"] - 50000
    assert after["vendor-a"] == before["vendor-a"] + 50000
    assert settlement["amount_minor"] == 50000
    assert sum(after.values()) == sum(before.values())


def test_simulator_rejects_replayed_execution(bind_actor_key):
    simulator = FinancialSimulator()
    result = DecisionEngine().decide(_operator_transaction())
    Keystore().create_keypair("operator-key", "test-password")
    bind_actor_key("operator-1", "operator-key")
    SigningGate().sign(result.transaction.transaction_id, "operator-key", "test-password")
    first = simulator.execute(result.transaction.transaction_id)
    after_first = {item["account_id"]: item["balance_minor"] for item in simulator.balances()}
    replay = simulator.execute(result.transaction.transaction_id)
    after_replay = {item["account_id"]: item["balance_minor"] for item in simulator.balances()}

    assert replay == first
    assert after_replay == after_first
    session = get_session()
    try:
        assert session.query(SimulatorExecutionRecord).filter_by(transaction_id=result.transaction.transaction_id).count() == 1
        assert session.query(AuditEntryRecord).filter_by(
            transaction_id=result.transaction.transaction_id, action="SIMULATOR_EXECUTE"
        ).count() == 1
    finally:
        session.close()


def test_execution_replay_rejects_missing_committed_audit_evidence(bind_actor_key):
    simulator = FinancialSimulator()
    result = DecisionEngine().decide(_operator_transaction())
    Keystore().create_keypair("execution-evidence-key", "test-password")
    bind_actor_key("operator-1", "execution-evidence-key")
    SigningGate().sign(result.transaction.transaction_id, "execution-evidence-key", "test-password")
    first = simulator.execute(result.transaction.transaction_id)
    after_execution = {
        item["account_id"]: item["balance_minor"] for item in simulator.balances()
    }

    session = get_session()
    try:
        session.query(AuditEntryRecord).filter_by(
            transaction_id=result.transaction.transaction_id, action="SIMULATOR_EXECUTE"
        ).delete()
        session.commit()
    finally:
        session.close()

    with pytest.raises(SimulatorError, match="audit evidence"):
        simulator.execute(result.transaction.transaction_id)
    assert {
        item["account_id"]: item["balance_minor"] for item in simulator.balances()
    } == after_execution
    assert first["status"] == "executed"


@pytest.mark.parametrize(
    "failure_stage",
    [
        "after_validation",
        "after_financial_mutation",
        "after_execution_record",
        "after_lifecycle_transition",
        "after_receipt_evidence",
        "before_commit",
    ],
)
def test_execution_failure_rolls_back_reloads_and_can_retry(
    bind_actor_key, monkeypatch, failure_stage
):
    import finguard.simulator.service as simulator_service

    simulator = FinancialSimulator()
    result = DecisionEngine().decide(_operator_transaction())
    Keystore().create_keypair("fault-injection-key", "test-password")
    bind_actor_key("operator-1", "fault-injection-key")
    SigningGate().sign(result.transaction.transaction_id, "fault-injection-key", "test-password")
    before = {item["account_id"]: item["balance_minor"] for item in simulator.balances()}

    def inject(stage):
        if stage == failure_stage:
            raise RuntimeError(f"injected failure: {stage}")

    monkeypatch.setattr(simulator_service, "_execution_checkpoint", inject)
    with pytest.raises(RuntimeError, match="injected failure"):
        simulator.execute(result.transaction.transaction_id)

    session = get_session()
    try:
        transaction = session.get(TransactionRecord, result.transaction.transaction_id)
        assert transaction is not None
        assert transaction.state == "signed"
        assert session.query(SimulatorExecutionRecord).filter_by(
            transaction_id=result.transaction.transaction_id
        ).count() == 0
        assert session.query(AuditEntryRecord).filter_by(
            transaction_id=result.transaction.transaction_id, action="SIMULATOR_EXECUTE"
        ).count() == 0
    finally:
        session.close()
    assert {item["account_id"]: item["balance_minor"] for item in simulator.balances()} == before

    monkeypatch.setattr(simulator_service, "_execution_checkpoint", lambda _stage: None)
    retry = simulator.execute(result.transaction.transaction_id)
    assert retry["status"] == "executed"
    assert retry["transaction_hash"] == result.receipt.transaction_hash
    session = get_session()
    try:
        transaction = session.get(TransactionRecord, result.transaction.transaction_id)
        assert transaction is not None
        assert transaction.state == "executed"
        assert session.query(SimulatorExecutionRecord).filter_by(
            transaction_id=result.transaction.transaction_id
        ).count() == 1
        assert session.query(AuditEntryRecord).filter_by(
            transaction_id=result.transaction.transaction_id, action="SIMULATOR_EXECUTE"
        ).count() == 1
    finally:
        session.close()


def test_simulator_rechecks_transaction_signature_before_execution(bind_actor_key):
    simulator = FinancialSimulator()
    result = DecisionEngine().decide(_operator_transaction())
    Keystore().create_keypair("operator-key", "test-password")
    bind_actor_key("operator-1", "operator-key")
    SigningGate().sign(result.transaction.transaction_id, "operator-key", "test-password")
    from finguard.storage.database import get_session
    from finguard.storage.repositories import TransactionRepository
    session = get_session()
    try:
        record = TransactionRepository(session).get(result.transaction.transaction_id)
        record.signature = "00" * 64
        TransactionRepository(session).save(record)
    finally:
        session.close()
    with pytest.raises(SimulatorError, match="signature is invalid"):
        simulator.execute(result.transaction.transaction_id)
