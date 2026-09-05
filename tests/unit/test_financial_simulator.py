"""End-to-end tests for the FinGuard-controlled local financial simulator."""
import pytest

from finguard.core.enums import ActorType, Currency, TransactionState
from finguard.core.transaction import Transaction
from finguard.core.errors import SecurityError
from finguard.crypto.keystore import Keystore
from finguard.decision import DecisionEngine
from finguard.signing import SigningGate
from finguard.simulator import FinancialSimulator, SimulatorError


def _operator_transaction(amount=500.0):
    return Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a", amount=amount,
        currency=Currency.INR, initiating_actor_type=ActorType.HUMAN_OPERATOR.value,
    )


def test_only_signed_transaction_can_move_synthetic_money():
    simulator = FinancialSimulator()
    before = {item["account_id"]: item["balance"] for item in simulator.balances()}
    result = DecisionEngine().decide(_operator_transaction())
    with pytest.raises(SimulatorError, match="SigningGate-signed"):
        simulator.execute(result.transaction.transaction_id)

    Keystore().create_keypair("operator-key", "test-password")
    SigningGate().sign(result.transaction.transaction_id, "operator-key", "test-password")
    settlement = simulator.execute(result.transaction.transaction_id)
    after = {item["account_id"]: item["balance"] for item in simulator.balances()}

    assert settlement["status"] == "executed"
    assert after["treasury"] == before["treasury"] - 500.0
    assert after["vendor-a"] == before["vendor-a"] + 500.0


def test_simulator_rejects_replayed_execution():
    simulator = FinancialSimulator()
    result = DecisionEngine().decide(_operator_transaction())
    Keystore().create_keypair("operator-key", "test-password")
    SigningGate().sign(result.transaction.transaction_id, "operator-key", "test-password")
    simulator.execute(result.transaction.transaction_id)
    with pytest.raises(SimulatorError, match="signed transaction"):
        simulator.execute(result.transaction.transaction_id)


def test_simulator_rechecks_transaction_signature_before_execution():
    simulator = FinancialSimulator()
    result = DecisionEngine().decide(_operator_transaction())
    Keystore().create_keypair("operator-key", "test-password")
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
