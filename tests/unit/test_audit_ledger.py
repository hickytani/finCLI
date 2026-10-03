"""Unit tests for audit ledger hash chaining and attestation verification."""

import json
import multiprocessing

import pytest
from sqlalchemy.exc import OperationalError

from finguard.audit.ledger import AuditLedger, canonical_checkpoint_bytes
from finguard.core.errors import SecurityError
from finguard.crypto.keystore import Keystore
from finguard.crypto.signing import generate_keypair, public_key_to_hex, sign_canonical_bytes
from finguard.storage.database import get_session
from finguard.storage.models import AuditCheckpointRecord, AuditEntryRecord


def _append_ledger_entry_process(index, barrier, result_queue):
    try:
        barrier.wait()
        entry = AuditLedger().append(
            action="PROCESS_APPEND",
            actor_id=f"operator-{index}",
            result="PASS",
        )
        result_queue.put(("ok", entry.seq))
    except (OperationalError, RuntimeError, ValueError) as exc:
        result_queue.put(("error", str(exc)))


def _checkpoint_signer(bind_actor_key, key_id="ledger-checkpoint-key"):
    public_key = Keystore().create_keypair(key_id, "checkpoint-test-password")
    actor = bind_actor_key("operator-1", key_id)
    assert actor.public_key == public_key
    return public_key


def test_audit_ledger_append_and_verify_integrity():
    ledger = AuditLedger()

    # Append test entries
    ledger.append(action="TEST_ACTION_1", actor_id="op-1", result="PASS")
    ledger.append(action="TEST_ACTION_2", actor_id="agent-1", result="BLOCKED")

    is_valid, failing_id, _reason = ledger.verify_integrity()
    assert is_valid is True
    assert failing_id is None


def test_audit_ledger_generate_and_verify_attestation():
    ledger = AuditLedger()
    report = ledger.generate_attestation()

    assert report["attestation_type"] == "FIN//GUARD Audit Ledger Verification"
    assert report["integrity_result"] == "PASS"
    assert "signature" in report
    assert "chain_root_hash" in report

    # Verify signature
    assert AuditLedger.verify_attestation(report) is True


def test_attestation_cannot_choose_its_own_trust_key():
    forged_private, forged_public = generate_keypair()
    forged = {
        "attestation_type": "FIN//GUARD Audit Ledger Verification",
        "timestamp": "2026-09-06T00:00:00+00:00",
        "chain_root_hash": "forged",
        "entry_count": 0,
        "integrity_result": "PASS",
        "attestor_pubkey": public_key_to_hex(forged_public),
    }
    forged["signature"] = sign_canonical_bytes(json.dumps(forged, sort_keys=True).encode(), forged_private)

    assert AuditLedger.verify_attestation(forged) is False


def test_signed_checkpoints_bind_ordered_ledger_prefix_and_are_idempotent(bind_actor_key):
    ledger = AuditLedger()
    first = ledger.append("FIRST")
    public_key_hex = _checkpoint_signer(bind_actor_key)

    checkpoint_one = ledger.create_checkpoint(
        "ledger-checkpoint-key", "checkpoint-test-password", "operator-1"
    )
    assert checkpoint_one["seq"] == first.seq == 1
    assert checkpoint_one["head_hash"] == first.entry_hash
    assert checkpoint_one["previous_checkpoint_hash"] == ledger.GENESIS_CHECKPOINT_HASH
    assert AuditLedger.verify_checkpoint_artifact(checkpoint_one, public_key_hex)
    checkpoint_body = {
        key: checkpoint_one[key]
        for key in (
            "checkpoint_version",
            "seq",
            "head_hash",
            "previous_checkpoint_hash",
            "created_at",
            "signer_actor_id",
            "key_id",
            "algorithm",
        )
    }
    assert canonical_checkpoint_bytes(checkpoint_body) == canonical_checkpoint_bytes(
        dict(reversed(list(checkpoint_body.items())))
    )
    assert not AuditLedger.verify_checkpoint_artifact(checkpoint_one, "00" * 32)
    assert ledger.verify_integrity()[0] is True

    assert ledger.create_checkpoint(
        "ledger-checkpoint-key", "checkpoint-test-password", "operator-1"
    ) == checkpoint_one

    second = ledger.append("SECOND")
    checkpoint_two = ledger.create_checkpoint(
        "ledger-checkpoint-key", "checkpoint-test-password", "operator-1"
    )
    assert checkpoint_two["seq"] == second.seq == 2
    assert checkpoint_two["previous_checkpoint_hash"] == checkpoint_one["checkpoint_hash"]
    assert AuditLedger.verify_checkpoint_artifact(
        checkpoint_two,
        public_key_hex,
        expected_previous_checkpoint_hash=checkpoint_one["checkpoint_hash"],
    )
    assert ledger.verify_integrity()[0] is True

    Keystore().create_keypair("second-checkpoint-key", "checkpoint-test-password")
    bind_actor_key("approver-1", "second-checkpoint-key")
    with pytest.raises(SecurityError, match="different checkpoint"):
        ledger.create_checkpoint("second-checkpoint-key", "checkpoint-test-password", "approver-1")


def test_exported_checkpoint_bundle_verifies_without_a_database_session(bind_actor_key):
    ledger = AuditLedger()
    ledger.append("EXPORTED_EVIDENCE", metadata={"purpose": "offline verification"})
    public_key_hex = _checkpoint_signer(bind_actor_key)
    checkpoint = ledger.create_checkpoint(
        "ledger-checkpoint-key", "checkpoint-test-password", "operator-1"
    )

    session = get_session()
    try:
        entries = [
            {
                "seq": entry.seq,
                "timestamp": entry.timestamp.isoformat(),
                "actor_id": entry.actor_id,
                "action": entry.action,
                "transaction_id": entry.transaction_id,
                "result": entry.result,
                "metadata_json": entry.metadata_json,
                "previous_hash": entry.previous_hash,
                "entry_hash": entry.entry_hash,
            }
            for entry in session.query(AuditEntryRecord).order_by(AuditEntryRecord.seq).all()
        ]
    finally:
        session.close()

    assert AuditLedger.verify_checkpoint_bundle(checkpoint, entries, public_key_hex)
    entries[0]["result"] = "ALTERED"
    assert not AuditLedger.verify_checkpoint_bundle(checkpoint, entries, public_key_hex)


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        ("entry_content", "Entry content hash mismatch"),
        ("delete_entry", "sequence gap or reorder"),
        ("reorder_entries", "hash mismatch"),
        ("checkpoint_sequence", "Checkpoint"),
        ("previous_checkpoint", "previous-evidence hash"),
        ("signature", "signature is invalid"),
    ],
)
def test_signed_checkpoint_verification_detects_tampering(
    bind_actor_key, tamper, message
):
    ledger = AuditLedger()
    ledger.append("FIRST")
    ledger.append("SECOND")
    _checkpoint_signer(bind_actor_key)
    ledger.create_checkpoint("ledger-checkpoint-key", "checkpoint-test-password", "operator-1")

    session = get_session()
    try:
        entries = session.query(AuditEntryRecord).order_by(AuditEntryRecord.seq).all()
        checkpoints = (
            session.query(AuditCheckpointRecord)
            .order_by(AuditCheckpointRecord.seq)
            .all()
        )
        if tamper == "entry_content":
            entries[0].result = "TAMPERED"
        elif tamper == "delete_entry":
            session.delete(entries[0])
        elif tamper == "reorder_entries":
            entries[0].seq = 3
            session.flush()
            entries[1].seq = 1
            session.flush()
            entries[0].seq = 2
        elif tamper == "checkpoint_sequence":
            checkpoints[0].seq = 99
        elif tamper == "previous_checkpoint":
            checkpoints[0].previous_checkpoint_hash = "f" * 64
        elif tamper == "signature":
            checkpoints[0].signature = "00" + checkpoints[0].signature[2:]
        session.commit()
    finally:
        session.close()

    valid, _, reason = ledger.verify_integrity()
    assert valid is False
    assert message.lower() in reason.lower()


@pytest.mark.parametrize(
    "failure_stage",
    ["after_ledger_validation", "after_checkpoint_insert", "before_commit"],
)
def test_checkpoint_failure_rolls_back_and_exact_retry_creates_one_checkpoint(
    bind_actor_key, monkeypatch, failure_stage
):
    ledger = AuditLedger()
    ledger.append("ATOMIC_CHECKPOINT")
    _checkpoint_signer(bind_actor_key)

    def inject(stage):
        if stage == failure_stage:
            raise RuntimeError(f"injected checkpoint failure: {stage}")

    monkeypatch.setattr(AuditLedger, "_checkpoint_checkpoint", staticmethod(inject))
    with pytest.raises(RuntimeError, match="injected checkpoint failure"):
        ledger.create_checkpoint("ledger-checkpoint-key", "checkpoint-test-password", "operator-1")

    session = get_session()
    try:
        assert session.query(AuditCheckpointRecord).count() == 0
        assert session.query(AuditEntryRecord).count() == 1
    finally:
        session.close()

    monkeypatch.setattr(AuditLedger, "_checkpoint_checkpoint", staticmethod(lambda _stage: None))
    checkpoint = ledger.create_checkpoint(
        "ledger-checkpoint-key", "checkpoint-test-password", "operator-1"
    )
    replay = ledger.create_checkpoint(
        "ledger-checkpoint-key", "checkpoint-test-password", "operator-1"
    )
    assert replay == checkpoint
    session = get_session()
    try:
        assert session.query(AuditCheckpointRecord).count() == 1
    finally:
        session.close()
    assert ledger.verify_integrity()[0] is True


def test_checkpoint_rejects_key_not_bound_to_signer_identity():
    ledger = AuditLedger()
    ledger.append("UNBOUND_CHECKPOINT")
    Keystore().create_keypair("unbound-checkpoint-key", "checkpoint-test-password")

    with pytest.raises(SecurityError, match="active registered signer"):
        ledger.create_checkpoint(
            "unbound-checkpoint-key", "checkpoint-test-password", "operator-1"
        )


def test_processes_append_distinct_contiguous_ledger_sequences():
    process_count = 4
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(process_count)
    result_queue = context.Queue()
    processes = [
        context.Process(
            target=_append_ledger_entry_process,
            args=(index, barrier, result_queue),
        )
        for index in range(process_count)
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
    assert sorted(outcome[1] for outcome in outcomes) == list(range(1, process_count + 1))
    valid, _, _ = AuditLedger().verify_integrity()
    assert valid is True
