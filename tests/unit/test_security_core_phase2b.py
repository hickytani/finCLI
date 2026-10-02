import datetime
import threading
import json

import pytest

from finguard.approvals.service import ApprovalService
from finguard.audit.nonce_store import NonceStore
from finguard.core.enums import ActorType, Currency
from finguard.core.errors import SecurityError
from finguard.core.transaction import Transaction
from finguard.core.canonical import canonical_serialize
from finguard.crypto.hashing import sha256_hash
from finguard.crypto.keystore import Keystore
from finguard.decision import DecisionEngine
from finguard.identity.registry import IdentityRegistry
from finguard.signing import SigningGate
from finguard.storage.database import get_session
from finguard.storage.models import DecisionReceiptRecord, TransactionRecord
from finguard.storage.repositories import TransactionRepository


def _agent_transaction(amount="100.00"):
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
        record.amount_minor = 99900  # tamper exact minor units — changes canonical hash
        TransactionRepository(session).save(record)
    finally:
        session.close()
    with pytest.raises(SecurityError, match="integrity"):
        SigningGate().sign(result.transaction.transaction_id, "signer-key", "test-password")


def test_coordinated_transaction_and_receipt_row_edit_cannot_authorize_new_amount():
    tx = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="100.00", currency=Currency.INR,
    )
    result = DecisionEngine().decide(tx)
    assert result.decision.value == "allow"
    Keystore().create_keypair("tamper-check-key", "test-password")

    session = get_session()
    try:
        record = TransactionRepository(session).get(tx.transaction_id)
        receipt = session.query(DecisionReceiptRecord).filter_by(transaction_id=tx.transaction_id).one()
        tampered_tx = Transaction(
            transaction_id=tx.transaction_id, actor_id=tx.actor_id,
            from_account=tx.from_account, to_account=tx.to_account,
            amount="200.00", currency=Currency.INR, nonce=tx.nonce,
            timestamp=tx.timestamp, metadata=tx.metadata,
        )
        record.amount_minor = tampered_tx.amount_minor
        record.canonical_hash = tampered_tx.transaction_hash()
        receipt_body = json.loads(receipt.reason)
        receipt_body.update({
            "amount": tampered_tx.money.to_decimal_string(),
            "amount_minor": tampered_tx.amount_minor,
            "transaction_hash": tampered_tx.transaction_hash(),
        })
        receipt.reason = json.dumps(receipt_body, sort_keys=True)
        receipt.transaction_hash = tampered_tx.transaction_hash()
        receipt.receipt_hash = sha256_hash(canonical_serialize(receipt_body))
        session.commit()
    finally:
        session.close()

    with pytest.raises(SecurityError, match="audit evidence"):
        SigningGate().sign(tx.transaction_id, "tamper-check-key", "test-password")


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


def test_agent_cannot_select_an_unauthorized_source_account():
    forged = _agent_transaction()
    forged.from_account = "vendor-a"
    decision = DecisionEngine().decide(forged)
    assert decision.decision.value == "block"
    assert "source account" in " ".join(decision.receipt.reasons).lower()


def test_decision_engine_denies_empty_destination_allowlist():
    registry = IdentityRegistry()
    actor = registry.get_actor("treasury-agent")
    assert actor is not None
    actor.allowed_destinations = []
    decision = DecisionEngine(registry=registry).decide(_agent_transaction())
    assert decision.decision.value == "block"
    assert decision.receipt.authority_allowed is False


def test_decision_engine_rejects_agent_wildcards_and_audits_operator_wildcard():
    registry = IdentityRegistry()
    agent = registry.get_actor("treasury-agent")
    assert agent is not None
    agent.allowed_source_accounts = ["*"]
    agent.allowed_destinations = ["*"]
    blocked = DecisionEngine(registry=registry).decide(_agent_transaction())
    assert blocked.decision.value == "block"
    with pytest.raises(ValueError, match="not an account identifier"):
        Transaction(
            actor_id="treasury-agent", from_account="*", to_account="vendor-a",
            amount="10.00", currency=Currency.INR,
        )

    operator_tx = Transaction(
        actor_id="operator-1", from_account="new-source", to_account="vendor-a",
        amount="10.00", currency=Currency.INR, initiating_actor_type=ActorType.HUMAN_OPERATOR.value,
    )
    allowed = DecisionEngine(registry=registry).decide(operator_tx)
    assert allowed.decision.value == "allow"
    assert any("WILDCARD_AUTHORITY_USED" in reason for reason in allowed.receipt.authority_reasons)


def test_idempotency_key_round_trips_through_decision_sign_and_execution():
    tx = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="125.00", currency=Currency.INR, idempotency_key="invoice-2026-42",
        policy_version="policy-1", metadata={"purpose": "invoice", "confidence": 0.97},
        timestamp=datetime.datetime(
            2026, 1, 1, 17, tzinfo=datetime.timezone(datetime.timedelta(hours=5))
        ),
    )
    assert tx.timestamp.hour == 12
    assert tx.timestamp.utcoffset().total_seconds() == 0
    result = DecisionEngine().decide(tx)
    assert result.decision.value == "allow"
    assert result.receipt.transaction_hash == tx.transaction_hash()

    session = get_session()
    try:
        record = TransactionRepository(session).get(tx.transaction_id)
        assert record.idempotency_key == "invoice-2026-42"
        assert record.policy_version == "policy-1"
        assert json.loads(record.metadata_json) == {"purpose": "invoice", "confidence": 0.97}
        assert record.canonical_hash == tx.transaction_hash()
    finally:
        session.close()

    Keystore().create_keypair("roundtrip-key", "test-password")
    signature = SigningGate().sign(tx.transaction_id, "roundtrip-key", "test-password")
    assert signature

    from finguard.simulator import FinancialSimulator
    executed = FinancialSimulator().execute(tx.transaction_id)
    assert executed["amount_minor"] == tx.amount_minor
