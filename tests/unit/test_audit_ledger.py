"""Unit tests for audit ledger hash chaining and attestation verification."""

from finguard.audit.ledger import AuditLedger


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
