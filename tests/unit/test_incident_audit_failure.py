"""FG-805 regression test: incident audit failure must never be silent.

After an incident state transition is committed, if the audit ledger
append fails, the failure MUST be logged at ERROR level. It must NOT
be swallowed silently.
"""
from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

from finguard.core.enums import IncidentSeverity
from finguard.incidents.service import IncidentService


def test_audit_failure_is_logged_loudly_not_swallowed(tmp_path, caplog):
    """FG-805: If the audit ledger append fails after a committed state
    transition, the error is logged at ERROR level, not silently dropped.
    """
    service = IncidentService()
    inc = service.create_incident(
        severity=IncidentSeverity.HIGH,
        description="Test incident for audit-failure assertion",
    )
    incident_id = inc.incident_id

    # Patch AuditLedger.append to raise a RuntimeError
    with caplog.at_level(logging.ERROR, logger="finguard.incidents.service"), patch(
        "finguard.incidents.service.AuditLedger"
    ) as mock_ledger_cls:
        mock_ledger = MagicMock()
        mock_ledger.append.side_effect = RuntimeError("simulated audit DB failure")
        mock_ledger_cls.return_value = mock_ledger

        # The transition itself should still succeed
        updated = service.transition_incident(
            incident_id=incident_id,
            new_state="investigating",
            requesting_actor_id="operator-1",
            note="audit-failure test",
        )

    assert updated.state == "investigating", "Transition must still commit despite audit failure"

    # The audit failure must have been logged at ERROR level
    error_records = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert error_records, (
        "Expected an ERROR log record when audit append fails, but none was found. "
        "FG-805: audit failures must NEVER be silent."
    )
    assert any("AUDIT FAILURE" in r.getMessage() for r in error_records), (
        "ERROR log must mention 'AUDIT FAILURE' for operator visibility."
    )
    assert any(incident_id in r.getMessage() for r in error_records), (
        "ERROR log must include the incident_id so operators can correlate it."
    )
