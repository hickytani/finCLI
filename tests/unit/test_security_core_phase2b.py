import threading

import pytest

from finguard.approvals.service import ApprovalService
from finguard.audit.nonce_store import NonceStore
from finguard.core.enums import ActorType, Currency
from finguard.core.errors import SecurityError
from finguard.core.transaction import Transaction
from finguard.crypto.keystore import Keystore
from finguard.decision import DecisionEngine
from finguard.identity.registry import IdentityRegistry
from finguard.signing import SigningGate
from finguard.storage.database import get_session
from finguard.storage.repositories import TransactionRepository


def _agent_transaction(amount=100.0):
    return Transaction(actor_id="treasury-agent", session_id="test", from_account="treasury", to_account="vendor-a", amount=amount, currency=Currency.INR, initiating_actor_type=ActorType.AGENT.value)


def test_direct_signing_without_decision_receipt_is_rejected():
    with pytest.raises(SecurityError, match="Transaction not found"):
        SigningGate().sign("TX-NOT-AUTHORIZED", "missing", "password")


def test_agent_cannot_approve_own_transaction():
    result = DecisionEngine().decide(_agent_transaction())
    key = Keystore()
    key.create_keypair("agent-key", "test-password")
    agent = IdentityRegistry().get_actor("treasury-agent")
    with pytest.raises(SecurityError, match="cannot approve"):
        ApprovalService().approve_transaction(result.transaction.transaction_id, agent, "agent-key", "test-password")


def test_transaction_mutation_blocks_final_signing():
    result = DecisionEngine().decide(_agent_transaction())
    keys = Keystore()
    keys.create_keypair("approver-key", "test-password")
    keys.create_keypair("signer-key", "test-password")
    ApprovalService().approve_transaction(result.transaction.transaction_id, IdentityRegistry().get_actor("approver-1"), "approver-key", "test-password")
    session = get_session()
    try:
        record = TransactionRepository(session).get(result.transaction.transaction_id)
        record.amount = 999.0
        TransactionRepository(session).save(record)
    finally:
        session.close()
    with pytest.raises(SecurityError, match="integrity"):
        SigningGate().sign(result.transaction.transaction_id, "signer-key", "test-password")


def test_approval_for_one_transaction_cannot_be_used_for_another():
    first, second = DecisionEngine().decide(_agent_transaction()), DecisionEngine().decide(_agent_transaction())
    keys = Keystore()
    keys.create_keypair("approver-key", "test-password")
    ApprovalService().approve_transaction(first.transaction.transaction_id, IdentityRegistry().get_actor("approver-1"), "approver-key", "test-password")
    assert ApprovalService().verify_approval_integrity(second.transaction) is False


def test_concurrent_nonce_allows_exactly_one_winner():
    results = []
    lock = threading.Lock()
    def claim():
        value = NonceStore().record("concurrent-nonce", "TX-CONCURRENT")
        with lock:
            results.append(value)
    threads = [threading.Thread(target=claim) for _ in range(5)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert results.count(True) == 1
    assert results.count(False) == 4


def test_policy_modification_invalidates_old_authorization(tmp_path, monkeypatch):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("""policy_id: test-policy\nversion: 1\nmax_amount: {amount: 50000}\nallowed_destinations: [vendor-a, vendor-b]\napproval: {required_above: 20000, required_approvals: 1}\nagent: {max_amount: 10000, allowed_destinations: [vendor-a, vendor-b]}\n""", encoding="utf-8")
    monkeypatch.setenv("FINGUARD_POLICY_PATH", str(policy_path))
    result = DecisionEngine().decide(_agent_transaction())
    keys = Keystore()
    keys.create_keypair("approver-key", "test-password")
    keys.create_keypair("signer-key", "test-password")
    ApprovalService().approve_transaction(result.transaction.transaction_id, IdentityRegistry().get_actor("approver-1"), "approver-key", "test-password")
    policy_path.write_text(policy_path.read_text(encoding="utf-8").replace("version: 1", "version: 2"), encoding="utf-8")
    with pytest.raises(SecurityError, match="Policy changed"):
        SigningGate().sign(result.transaction.transaction_id, "signer-key", "test-password")


def test_same_nonce_second_request_is_blocked():
    first = _agent_transaction()
    assert DecisionEngine().decide(first).decision.value == "require_approval"
    second = _agent_transaction()
    second.nonce = first.nonce
    assert DecisionEngine().decide(second).decision.value == "block"
