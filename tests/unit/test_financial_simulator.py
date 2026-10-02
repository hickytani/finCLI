"""End-to-end tests for the FinGuard-controlled local financial simulator."""
import pytest

from finguard.core.enums import ActorType, Currency
from finguard.core.transaction import Transaction
from finguard.crypto.keystore import Keystore
from finguard.decision import DecisionEngine
from finguard.signing import SigningGate
from finguard.simulator import FinancialSimulator, SimulatorError


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
    simulator.execute(result.transaction.transaction_id)
    with pytest.raises(SimulatorError, match="signed transaction"):
        simulator.execute(result.transaction.transaction_id)


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
