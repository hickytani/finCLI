import datetime
import json
import multiprocessing
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import event

from finguard.approvals.service import ApprovalService
from finguard.audit.ledger import AuditLedger
from finguard.audit.nonce_store import NonceStore
from finguard.core.canonical import canonical_serialize
from finguard.core.enums import ActorType, Currency
from finguard.core.errors import SecurityError
from finguard.core.transaction import Transaction
from finguard.crypto.hashing import sha256_hash
from finguard.crypto.keystore import Keystore
from finguard.crypto.signing import verify_signature
from finguard.decision import DecisionEngine
from finguard.identity.registry import IdentityRegistry
from finguard.signing import SigningGate
from finguard.simulator import FinancialSimulator
from finguard.storage.database import get_session
from finguard.storage.models import (
    ApprovalRecord,
    ApprovalRequestRecord,
    AuditEntryRecord,
    DecisionReceiptRecord,
    SimulatorExecutionRecord,
)
from finguard.storage.repositories import TransactionRepository


def _execute_transaction_process(transaction_id, start_barrier, result_queue):
    try:
        start_barrier.wait(timeout=30)
        result_queue.put(("ok", FinancialSimulator().execute(transaction_id)))
    except SecurityError as exc:
        result_queue.put(("error", type(exc).__name__, str(exc)))


def _sign_transaction_process(transaction_id, key_id, password, start_barrier, result_queue):
    try:
        start_barrier.wait(timeout=30)
        signature = SigningGate().sign(transaction_id, key_id, password)
        result_queue.put(("ok", signature))
    except SecurityError as exc:
        result_queue.put(("error", type(exc).__name__, str(exc)))


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


def test_approval_rejects_key_not_bound_to_approver_identity():
    result = DecisionEngine().decide(_agent_transaction())
    Keystore().create_keypair("unbound-approver-key", "test-password")

    with pytest.raises(SecurityError, match="no public key bound"):
        ApprovalService().approve_transaction(
            result.transaction.transaction_id,
            IdentityRegistry().get_actor("approver-1"),
            "unbound-approver-key",
            "test-password",
        )


def test_signing_rejects_key_not_bound_to_authorized_signer_identity():
    result = DecisionEngine().decide(Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="125.00", currency=Currency.INR,
    ))
    Keystore().create_keypair("unbound-signer-key", "test-password")

    with pytest.raises(SecurityError, match="not bound to an authorized signer"):
        SigningGate().sign(result.transaction.transaction_id, "unbound-signer-key", "test-password")


def test_transaction_mutation_blocks_final_signing(bind_actor_key):
    result = DecisionEngine().decide(_agent_transaction())
    keys = Keystore()
    keys.create_keypair("approver-key", "test-password")
    keys.create_keypair("signer-key", "test-password")
    approver = bind_actor_key("approver-1", "approver-key")
    bind_actor_key("operator-1", "signer-key")
    ApprovalService().approve_transaction(result.transaction.transaction_id, approver, "approver-key", "test-password")
    session = get_session()
    try:
        record = TransactionRepository(session).get(result.transaction.transaction_id)
        record.amount_minor = 99900  # tamper exact minor units — changes canonical hash
        TransactionRepository(session).save(record)
    finally:
        session.close()
    with pytest.raises(SecurityError, match="integrity"):
        SigningGate().sign(result.transaction.transaction_id, "signer-key", "test-password")


def test_coordinated_transaction_and_receipt_row_edit_cannot_authorize_new_amount(bind_actor_key):
    tx = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="100.00", currency=Currency.INR,
    )
    result = DecisionEngine().decide(tx)
    assert result.decision.value == "allow"
    Keystore().create_keypair("tamper-check-key", "test-password")
    bind_actor_key("operator-1", "tamper-check-key")

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


def test_approval_for_one_transaction_cannot_be_used_for_another(bind_actor_key):
    first, second = DecisionEngine().decide(_agent_transaction()), DecisionEngine().decide(_agent_transaction())
    keys = Keystore()
    keys.create_keypair("approver-key", "test-password")
    approver = bind_actor_key("approver-1", "approver-key")
    ApprovalService().approve_transaction(first.transaction.transaction_id, approver, "approver-key", "test-password")
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


def test_policy_modification_invalidates_old_authorization(tmp_path, monkeypatch, bind_actor_key):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("""policy_id: test-policy\nversion: 1\nmax_amount: {amount: 50000}\nallowed_destinations: [vendor-a, vendor-b]\napproval: {required_above: 20000, required_approvals: 1}\nagent: {max_amount: 10000, allowed_destinations: [vendor-a, vendor-b]}\n""", encoding="utf-8")
    monkeypatch.setenv("FINGUARD_POLICY_PATH", str(policy_path))
    result = DecisionEngine().decide(_agent_transaction())
    keys = Keystore()
    keys.create_keypair("approver-key", "test-password")
    keys.create_keypair("signer-key", "test-password")
    approver = bind_actor_key("approver-1", "approver-key")
    bind_actor_key("operator-1", "signer-key")
    ApprovalService().approve_transaction(result.transaction.transaction_id, approver, "approver-key", "test-password")
    policy_path.write_text(policy_path.read_text(encoding="utf-8").replace("version: 1", "version: 2"), encoding="utf-8")
    with pytest.raises(SecurityError, match="Policy changed"):
        SigningGate().sign(result.transaction.transaction_id, "signer-key", "test-password")


def test_same_nonce_second_request_is_blocked():
    first = _agent_transaction()
    assert DecisionEngine().decide(first).decision.value == "require_approval"
    second = _agent_transaction()
    second.nonce = first.nonce
    assert DecisionEngine().decide(second).decision.value == "block"


def test_idempotent_decision_retry_returns_original_result_without_mutating_transaction():
    tx = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="125.00", currency=Currency.INR, idempotency_key="retry-key-1",
    )
    engine = DecisionEngine()
    first = engine.decide(tx)
    retry_tx = Transaction(
        transaction_id=tx.transaction_id, actor_id=tx.actor_id,
        from_account=tx.from_account, to_account=tx.to_account,
        amount=tx.money, currency=tx.currency, nonce=tx.nonce,
        timestamp=tx.timestamp, metadata=tx.metadata,
        idempotency_key=tx.idempotency_key, policy_version=tx.policy_version,
    )

    retry = engine.decide(retry_tx)

    assert retry.decision == first.decision
    assert retry.receipt.receipt_id == first.receipt.receipt_id
    assert retry.receipt.transaction_hash == first.receipt.transaction_hash
    assert retry.transaction.state == first.transaction.state
    assert retry.transaction.version == first.transaction.version
    session = get_session()
    try:
        record = TransactionRepository(session).get(tx.transaction_id)
        assert record is not None
        assert record.state == first.transaction.state.value
    finally:
        session.close()


def test_idempotency_key_reuse_with_changed_payload_preserves_original_transaction():
    tx = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="125.00", currency=Currency.INR, idempotency_key="retry-key-2",
    )
    engine = DecisionEngine()
    original = engine.decide(tx)
    changed = Transaction(
        transaction_id=tx.transaction_id, actor_id=tx.actor_id,
        from_account=tx.from_account, to_account=tx.to_account,
        amount="126.00", currency=tx.currency, nonce=tx.nonce,
        timestamp=tx.timestamp, idempotency_key=tx.idempotency_key,
    )

    with pytest.raises(ValueError, match="reused for a different transaction payload"):
        engine.decide(changed)

    session = get_session()
    try:
        record = TransactionRepository(session).get(tx.transaction_id)
        assert record is not None
        assert record.state == original.transaction.state.value
        assert record.canonical_hash == original.receipt.transaction_hash
        assert session.query(DecisionReceiptRecord).filter_by(transaction_id=tx.transaction_id).count() == 1
    finally:
        session.close()


def test_execution_rejects_signed_transaction_when_decision_receipt_is_missing(bind_actor_key):
    tx = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="125.00", currency=Currency.INR,
    )
    result = DecisionEngine().decide(tx)
    assert result.decision.value == "allow"
    Keystore().create_keypair("receipt-removal-key", "test-password")
    bind_actor_key("operator-1", "receipt-removal-key")
    SigningGate().sign(tx.transaction_id, "receipt-removal-key", "test-password")

    session = get_session()
    try:
        receipt = session.query(DecisionReceiptRecord).filter_by(transaction_id=tx.transaction_id).one()
        session.delete(receipt)
        session.commit()
    finally:
        session.close()

    with pytest.raises(SecurityError, match="Decision evidence"):
        FinancialSimulator().execute(tx.transaction_id)


def test_signing_rejects_transaction_version_changed_after_approval(bind_actor_key):
    result = DecisionEngine().decide(_agent_transaction())
    keys = Keystore()
    keys.create_keypair("version-approver-key", "test-password")
    keys.create_keypair("version-signer-key", "test-password")
    approver = bind_actor_key("approver-1", "version-approver-key")
    bind_actor_key("operator-1", "version-signer-key")
    ApprovalService().approve_transaction(
        result.transaction.transaction_id,
        approver,
        "version-approver-key",
        "test-password",
    )

    session = get_session()
    try:
        record = TransactionRepository(session).get(result.transaction.transaction_id)
        record.version += 1
        session.commit()
    finally:
        session.close()

    with pytest.raises(SecurityError, match="approval"):
        SigningGate().sign(result.transaction.transaction_id, "version-signer-key", "test-password")


def test_execution_rejects_signed_transaction_when_approval_is_missing(bind_actor_key):
    result = DecisionEngine().decide(_agent_transaction())
    keys = Keystore()
    keys.create_keypair("approval-removal-key", "test-password")
    keys.create_keypair("approval-removal-signer", "test-password")
    approver = bind_actor_key("approver-1", "approval-removal-key")
    bind_actor_key("operator-1", "approval-removal-signer")
    ApprovalService().approve_transaction(
        result.transaction.transaction_id,
        approver,
        "approval-removal-key",
        "test-password",
    )
    SigningGate().sign(result.transaction.transaction_id, "approval-removal-signer", "test-password")

    session = get_session()
    try:
        session.query(ApprovalRequestRecord).filter_by(
            transaction_id=result.transaction.transaction_id
        ).delete()
        session.query(ApprovalRecord).filter_by(
            transaction_id=result.transaction.transaction_id
        ).delete()
        session.commit()
    finally:
        session.close()

    with pytest.raises(SecurityError, match="signed transaction version"):
        FinancialSimulator().execute(result.transaction.transaction_id)


def test_forged_approved_state_without_approval_signature_cannot_be_signed(bind_actor_key):
    result = DecisionEngine().decide(_agent_transaction())
    Keystore().create_keypair("forged-approval-signer", "test-password")
    bind_actor_key("operator-1", "forged-approval-signer")
    session = get_session()
    try:
        record = TransactionRepository(session).get(result.transaction.transaction_id)
        request = session.query(ApprovalRequestRecord).filter_by(
            transaction_id=result.transaction.transaction_id
        ).one()
        record.state = "approved"
        record.version += 1
        request.state = "approved"
        request.current_approvals = request.required_approvals
        session.commit()
    finally:
        session.close()

    with pytest.raises(SecurityError, match="approval"):
        SigningGate().sign(result.transaction.transaction_id, "forged-approval-signer", "test-password")


def test_execution_rejects_transaction_mutation_after_signing(bind_actor_key):
    tx = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="125.00", currency=Currency.INR,
    )
    DecisionEngine().decide(tx)
    Keystore().create_keypair("post-sign-mutation-key", "test-password")
    bind_actor_key("operator-1", "post-sign-mutation-key")
    SigningGate().sign(tx.transaction_id, "post-sign-mutation-key", "test-password")
    session = get_session()
    try:
        record = TransactionRepository(session).get(tx.transaction_id)
        record.to_account = "vendor-b"
        session.commit()
    finally:
        session.close()

    with pytest.raises(SecurityError, match="canonical authorization hash"):
        FinancialSimulator().execute(tx.transaction_id)


def test_execution_rejects_stale_signed_lifecycle_version(bind_actor_key):
    transaction = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="125.00", currency=Currency.INR,
    )
    DecisionEngine().decide(transaction)
    Keystore().create_keypair("stale-version-signer", "test-password")
    bind_actor_key("operator-1", "stale-version-signer")
    SigningGate().sign(transaction.transaction_id, "stale-version-signer", "test-password")

    session = get_session()
    try:
        record = TransactionRepository(session).get(transaction.transaction_id)
        assert record is not None
        record.version += 1
        session.commit()
    finally:
        session.close()

    simulator = FinancialSimulator()
    before = {item["account_id"]: item["balance_minor"] for item in simulator.balances()}
    with pytest.raises(SecurityError, match="Signed transaction version is stale"):
        simulator.execute(transaction.transaction_id)
    assert {item["account_id"]: item["balance_minor"] for item in simulator.balances()} == before


def test_signature_from_another_transaction_cannot_authorize_execution(bind_actor_key):
    first = DecisionEngine().decide(Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="125.00", currency=Currency.INR,
    ))
    second = DecisionEngine().decide(Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-b",
        amount="125.00", currency=Currency.INR,
    ))
    Keystore().create_keypair("signature-substitution-key", "test-password")
    bind_actor_key("operator-1", "signature-substitution-key")
    first_signature = SigningGate().sign(
        first.transaction.transaction_id,
        "signature-substitution-key",
        "test-password",
    )
    SigningGate().sign(second.transaction.transaction_id, "signature-substitution-key", "test-password")
    session = get_session()
    try:
        record = TransactionRepository(session).get(second.transaction.transaction_id)
        record.signature = first_signature
        session.commit()
    finally:
        session.close()

    with pytest.raises(SecurityError, match="signature is invalid"):
        FinancialSimulator().execute(second.transaction.transaction_id)


def test_approved_transaction_completes_bound_decision_approval_sign_execution_chain(bind_actor_key):
    result = DecisionEngine().decide(_agent_transaction())
    assert result.decision.value == "require_approval"
    keys = Keystore()
    keys.create_keypair("chain-approver-key", "test-password")
    keys.create_keypair("chain-signer-key", "test-password")
    approver = bind_actor_key("approver-1", "chain-approver-key")
    bind_actor_key("operator-1", "chain-signer-key")
    ApprovalService().approve_transaction(
        result.transaction.transaction_id,
        approver,
        "chain-approver-key",
        "test-password",
    )
    SigningGate().sign(result.transaction.transaction_id, "chain-signer-key", "test-password")

    execution = FinancialSimulator().execute(result.transaction.transaction_id)

    assert execution["status"] == "executed"
    assert execution["transaction_hash"] == result.receipt.transaction_hash


def test_concurrent_signing_has_exactly_one_cas_winner(bind_actor_key):
    tx = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="125.00", currency=Currency.INR,
    )
    result = DecisionEngine().decide(tx)
    Keystore().create_keypair("concurrent-signer", "test-password")
    bind_actor_key("operator-1", "concurrent-signer")
    barrier = threading.Barrier(2)

    def sign() -> bool:
        barrier.wait()
        try:
            SigningGate().sign(tx.transaction_id, "concurrent-signer", "test-password")
            return True
        except SecurityError:
            return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: sign(), range(2)))

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 1
    session = get_session()
    try:
        record = TransactionRepository(session).get(result.transaction.transaction_id)
        assert record is not None
        assert record.state == "signed"
        assert record.signed_version == record.version
        assert record.signature
    finally:
        session.close()


def test_approval_audit_failure_rolls_back_approval_and_state(bind_actor_key, monkeypatch):
    result = DecisionEngine().decide(_agent_transaction())
    Keystore().create_keypair("atomic-approval-key", "test-password")
    approver = bind_actor_key("approver-1", "atomic-approval-key")

    def fail_approval_evidence(self, action, *args, **kwargs):
        if action == "APPROVAL":
            raise RuntimeError("injected approval evidence failure")
        return original_append(self, action, *args, **kwargs)

    original_append = AuditLedger.append
    monkeypatch.setattr(AuditLedger, "append", fail_approval_evidence)
    with pytest.raises(RuntimeError, match="approval evidence failure"):
        ApprovalService().approve_transaction(
            result.transaction.transaction_id,
            approver,
            "atomic-approval-key",
            "test-password",
        )

    session = get_session()
    try:
        transaction = TransactionRepository(session).get(result.transaction.transaction_id)
        request = session.query(ApprovalRequestRecord).filter_by(
            transaction_id=result.transaction.transaction_id
        ).one()
        assert transaction is not None
        assert transaction.state == "pending_approval"
        assert request.current_approvals == 0
        assert request.state == "pending"
        assert session.query(ApprovalRecord).filter_by(
            transaction_id=result.transaction.transaction_id
        ).count() == 0
        assert session.query(AuditEntryRecord).filter_by(
            transaction_id=result.transaction.transaction_id, action="APPROVAL"
        ).count() == 0
    finally:
        session.close()

    monkeypatch.setattr(AuditLedger, "append", original_append)
    ApprovalService().approve_transaction(
        result.transaction.transaction_id,
        approver,
        "atomic-approval-key",
        "test-password",
    )
    session = get_session()
    try:
        request = session.query(ApprovalRequestRecord).filter_by(
            transaction_id=result.transaction.transaction_id
        ).one()
        assert request.current_approvals == 1
        assert session.query(ApprovalRecord).filter_by(
            transaction_id=result.transaction.transaction_id
        ).count() == 1
        assert session.query(AuditEntryRecord).filter_by(
            transaction_id=result.transaction.transaction_id, action="APPROVAL"
        ).count() == 1
    finally:
        session.close()


def test_signing_audit_failure_rolls_back_signature_and_state(bind_actor_key, monkeypatch):
    tx = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="125.00", currency=Currency.INR,
    )
    result = DecisionEngine().decide(tx)
    Keystore().create_keypair("atomic-signing-key", "test-password")
    bind_actor_key("operator-1", "atomic-signing-key")

    def fail_signing_evidence(self, action, *args, **kwargs):
        if action == "SIGNING_GATE":
            raise RuntimeError("injected signing evidence failure")
        return original_append(self, action, *args, **kwargs)

    original_append = AuditLedger.append
    monkeypatch.setattr(AuditLedger, "append", fail_signing_evidence)
    with pytest.raises(RuntimeError, match="signing evidence failure"):
        SigningGate().sign(result.transaction.transaction_id, "atomic-signing-key", "test-password")

    session = get_session()
    try:
        record = TransactionRepository(session).get(tx.transaction_id)
        assert record is not None
        assert record.state == "created"
        assert record.signature is None
        assert record.signing_key_id is None
        assert record.signed_version is None
        assert session.query(AuditEntryRecord).filter_by(
            transaction_id=tx.transaction_id, action="SIGNING_GATE"
        ).count() == 0
    finally:
        session.close()

    monkeypatch.setattr(AuditLedger, "append", original_append)
    signature = SigningGate().sign(
        result.transaction.transaction_id, "atomic-signing-key", "test-password"
    )
    assert signature
    session = get_session()
    try:
        record = TransactionRepository(session).get(tx.transaction_id)
        assert record is not None
        assert record.state == "signed"
        assert record.signature == signature
        assert record.signed_version == record.version
        assert session.query(AuditEntryRecord).filter_by(
            transaction_id=tx.transaction_id, action="SIGNING_GATE"
        ).count() == 1
    finally:
        session.close()


def test_concurrent_execution_moves_funds_exactly_once(bind_actor_key):
    tx = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="125.00", currency=Currency.INR,
    )
    DecisionEngine().decide(tx)
    Keystore().create_keypair("concurrent-execution-signer", "test-password")
    bind_actor_key("operator-1", "concurrent-execution-signer")
    SigningGate().sign(tx.transaction_id, "concurrent-execution-signer", "test-password")
    simulator = FinancialSimulator()
    before = {item["account_id"]: item["balance_minor"] for item in simulator.balances()}
    barrier = threading.Barrier(2)

    def execute() -> dict | None:
        barrier.wait()
        try:
            return simulator.execute(tx.transaction_id)
        except SecurityError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _: execute(), range(2)))

    successful_results = [outcome for outcome in outcomes if outcome is not None]
    assert successful_results
    assert all(outcome == successful_results[0] for outcome in successful_results)
    after = {item["account_id"]: item["balance_minor"] for item in simulator.balances()}
    assert after["treasury"] == before["treasury"] - tx.amount_minor
    assert after["vendor-a"] == before["vendor-a"] + tx.amount_minor
    session = get_session()
    try:
        assert session.query(SimulatorExecutionRecord).filter_by(transaction_id=tx.transaction_id).count() == 1
        assert session.query(AuditEntryRecord).filter_by(
            transaction_id=tx.transaction_id, action="SIMULATOR_EXECUTE"
        ).count() == 1
    finally:
        session.close()


def test_processes_concurrently_execute_one_transaction_exactly_once(bind_actor_key):
    transaction = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="125.00", currency=Currency.INR,
    )
    DecisionEngine().decide(transaction)
    Keystore().create_keypair("process-execution-signer", "test-password")
    bind_actor_key("operator-1", "process-execution-signer")
    SigningGate().sign(transaction.transaction_id, "process-execution-signer", "test-password")

    simulator = FinancialSimulator()
    before = {item["account_id"]: item["balance_minor"] for item in simulator.balances()}
    context = multiprocessing.get_context("spawn")
    start_barrier = context.Barrier(2)
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_execute_transaction_process,
            args=(transaction.transaction_id, start_barrier, result_queue),
        )
        for _ in range(2)
    ]
    try:
        for process in processes:
            process.start()
        outcomes = [result_queue.get(timeout=45) for _ in processes]
        for process in processes:
            process.join(timeout=45)
        assert all(not process.is_alive() and process.exitcode == 0 for process in processes)
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        result_queue.close()

    assert all(outcome[0] == "ok" for outcome in outcomes), outcomes
    assert outcomes[0][1] == outcomes[1][1]
    after = {item["account_id"]: item["balance_minor"] for item in simulator.balances()}
    assert after["treasury"] == before["treasury"] - transaction.amount_minor
    assert after["vendor-a"] == before["vendor-a"] + transaction.amount_minor

    session = get_session()
    try:
        stored = TransactionRepository(session).get(transaction.transaction_id)
        assert stored is not None
        assert stored.state == "executed"
        assert session.query(SimulatorExecutionRecord).filter_by(
            transaction_id=transaction.transaction_id
        ).count() == 1
        assert session.query(AuditEntryRecord).filter_by(
            transaction_id=transaction.transaction_id, action="SIMULATOR_EXECUTE"
        ).count() == 1
    finally:
        session.close()


def test_processes_concurrently_sign_one_transaction_exactly_once(bind_actor_key):
    transaction = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="125.00", currency=Currency.INR,
    )
    DecisionEngine().decide(transaction)
    Keystore().create_keypair("process-signing-signer", "test-password")
    bind_actor_key("operator-1", "process-signing-signer")

    context = multiprocessing.get_context("spawn")
    start_barrier = context.Barrier(2)
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_sign_transaction_process,
            args=(
                transaction.transaction_id,
                "process-signing-signer",
                "test-password",
                start_barrier,
                result_queue,
            ),
        )
        for _ in range(2)
    ]
    try:
        for process in processes:
            process.start()
        outcomes = [result_queue.get(timeout=60) for _ in processes]
        for process in processes:
            process.join(timeout=60)
        assert all(not process.is_alive() and process.exitcode == 0 for process in processes)
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        result_queue.close()

    assert [outcome[0] for outcome in outcomes].count("ok") == 1, outcomes
    assert [outcome[0] for outcome in outcomes].count("error") == 1, outcomes
    session = get_session()
    try:
        record = TransactionRepository(session).get(transaction.transaction_id)
        assert record is not None
        assert record.state == "signed"
        assert record.signature
        assert record.signed_version == record.version
        assert verify_signature(
            transaction.canonical_bytes(),
            record.signature,
            bytes.fromhex(Keystore().get_public_key("process-signing-signer")),
        )
        assert session.query(AuditEntryRecord).filter_by(
            transaction_id=transaction.transaction_id, action="SIGNING_GATE"
        ).count() == 1
    finally:
        session.close()


def test_execution_starts_begin_immediate_before_reading_transaction(bind_actor_key):
    from finguard.storage.database import get_engine

    transaction = Transaction(
        actor_id="operator-1", from_account="treasury", to_account="vendor-a",
        amount="125.00", currency=Currency.INR,
    )
    DecisionEngine().decide(transaction)
    Keystore().create_keypair("immediate-execution-signer", "test-password")
    bind_actor_key("operator-1", "immediate-execution-signer")
    SigningGate().sign(transaction.transaction_id, "immediate-execution-signer", "test-password")

    statements = []

    def record_statement(connection, cursor, statement, parameters, context, executemany):
        statements.append((statement.strip().upper(), connection.connection.driver_connection.in_transaction))

    engine = get_engine()
    event.listen(engine, "after_cursor_execute", record_statement)
    try:
        FinancialSimulator().execute(transaction.transaction_id)
    finally:
        event.remove(engine, "after_cursor_execute", record_statement)

    immediate_positions = [
        index for index, (statement, active) in enumerate(statements)
        if statement == "BEGIN IMMEDIATE" and active
    ]
    transaction_read_positions = [
        index for index, (statement, _) in enumerate(statements)
        if statement.startswith("SELECT") and "FROM TRANSACTIONS" in statement
    ]
    assert len(immediate_positions) == 1
    assert transaction_read_positions
    assert immediate_positions[0] < transaction_read_positions[0]


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


def test_idempotency_key_round_trips_through_decision_sign_and_execution(bind_actor_key):
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
    bind_actor_key("operator-1", "roundtrip-key")
    signature = SigningGate().sign(tx.transaction_id, "roundtrip-key", "test-password")
    assert signature

    from finguard.simulator import FinancialSimulator
    executed = FinancialSimulator().execute(tx.transaction_id)
    assert executed["amount_minor"] == tx.amount_minor
