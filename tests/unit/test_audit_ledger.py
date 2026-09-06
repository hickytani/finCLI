"""Unit tests for audit ledger hash chaining and attestation verification."""

from finguard.audit.ledger import AuditLedger
from finguard.crypto.signing import generate_keypair, public_key_to_hex, sign_canonical_bytes
import json


def test_audit_ledger_append_and_verify_integrity():
    ledger = AuditLedger()

    # Append test entries
    e1 = ledger.append(action="TEST_ACTION_1", actor_id="op-1", result="PASS")
    e2 = ledger.append(action="TEST_ACTION_2", actor_id="agent-1", result="BLOCKED")

    is_valid, failing_id, reason = ledger.verify_integrity()
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
