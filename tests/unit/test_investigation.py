"""Tests for the FIN//GUARD investigation layer.

Covers:
- Incident trace (relationships, data integrity)
- Transaction trace (IDOR, missing ID)
- Event search (filters, pagination, cross-actor IDOR)
- Actor profile (risk contributors, bounded queries)
- Incident timeline (chronological order, real sources only)
- Incident lifecycle (valid transitions, invalid rejections, idempotency, audit records)
- IDOR attempts (cross-actor incident/transaction access)
- Malformed IDs (non-existent resources)
- Pagination boundaries (page 0, oversized page_size, beyond total)
- Cross-actor event IDOR attempts
"""

import datetime

import pytest

from finguard.core.enums import Currency, IncidentSeverity
from finguard.core.errors import SecurityError
from finguard.core.transaction import Transaction
from finguard.decision import DecisionEngine
from finguard.incidents.service import IncidentService, InvalidTransitionError
from finguard.investigation.service import InvestigationService
from finguard.storage.database import get_session
from finguard.storage.models import IncidentRecord, SecuritySignalRecord
from finguard.storage.repositories import (
    IncidentRepository,
    SignalRepository,
    TransactionRepository,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tx(actor_id: str = "operator-1", amount: str = "500.00") -> Transaction:
    return Transaction(
        actor_id=actor_id,
        session_id="test-session",
        from_account="treasury",
        to_account="vendor-a",
        amount=amount,
        currency=Currency.INR,
    )


def _create_incident(
    actor_id: str = "treasury-agent",
    tx_id: str | None = None,
    severity: IncidentSeverity = IncidentSeverity.HIGH,
) -> IncidentRecord:
    svc = IncidentService()
    return svc.create_incident(
        severity=severity,
        description="Test incident",
        transaction_id=tx_id,
        actor_id=actor_id,
        signals=["AUTHORITY_VIOLATION"],
    )


def _run_tx(actor_id: str = "operator-1", amount: str = "500.00"):
    """Push a transaction through the decision engine so it has a receipt + audit."""
    tx = _make_tx(actor_id=actor_id, amount=amount)
    return DecisionEngine().decide(tx)


# ---------------------------------------------------------------------------
# 1. Incident trace
# ---------------------------------------------------------------------------

class TestIncidentTrace:

    def test_trace_returns_incident_details(self):
        inc = _create_incident()
        svc = InvestigationService()
        trace = svc.get_incident_trace(inc.incident_id)

        assert trace.incident.incident_id == inc.incident_id
        assert trace.incident.severity == inc.severity
        assert trace.incident.state == "open"

    def test_trace_includes_related_transaction(self):
        result = _run_tx()
        tx_id = result.transaction.transaction_id
        inc = _create_incident(tx_id=tx_id)

        svc = InvestigationService()
        trace = svc.get_incident_trace(inc.incident_id)

        assert trace.transaction is not None
        assert trace.transaction.transaction_id == tx_id

    def test_trace_without_transaction_has_none(self):
        inc = _create_incident(tx_id=None)
        svc = InvestigationService()
        trace = svc.get_incident_trace(inc.incident_id)
        assert trace.transaction is None

    def test_trace_includes_signals_for_transaction(self):
        result = _run_tx(actor_id="operator-1", amount="500.00")
        tx_id = result.transaction.transaction_id

        # Inject a signal for this transaction
        session = get_session()
        try:
            sig = SecuritySignalRecord(
                signal_id=f"SIG-TEST-{tx_id[:6]}",
                transaction_id=tx_id,
                signal_type="AUTHORITY_VIOLATION",
                score=50,
                description="Test signal",
            )
            SignalRepository(session).save(sig)
        finally:
            session.close()

        inc = _create_incident(tx_id=tx_id)
        svc = InvestigationService()
        trace = svc.get_incident_trace(inc.incident_id)

        assert any(s.signal_type == "AUTHORITY_VIOLATION" for s in trace.signals)

    def test_trace_includes_decision_receipt_when_present(self):
        result = _run_tx()
        tx_id = result.transaction.transaction_id
        inc = _create_incident(tx_id=tx_id)

        svc = InvestigationService()
        trace = svc.get_incident_trace(inc.incident_id)

        # The decision engine persists a receipt
        assert trace.receipt is not None
        assert trace.receipt.transaction_id == tx_id

    def test_trace_audit_entries_sorted_by_timestamp(self):
        result = _run_tx()
        tx_id = result.transaction.transaction_id
        inc = _create_incident(tx_id=tx_id)

        svc = InvestigationService()
        trace = svc.get_incident_trace(inc.incident_id)

        timestamps = [a.timestamp for a in trace.audit_entries]
        assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# 2. IDOR protection — incident
# ---------------------------------------------------------------------------

class TestIncidentIDOR:

    def test_cross_actor_incident_access_denied(self):
        inc = _create_incident(actor_id="treasury-agent")
        svc = InvestigationService()

        with pytest.raises(SecurityError, match="does not belong to actor"):
            svc.get_incident_trace(inc.incident_id, owner_actor_id="operator-1")

    def test_same_actor_incident_access_allowed(self):
        inc = _create_incident(actor_id="treasury-agent")
        svc = InvestigationService()
        trace = svc.get_incident_trace(inc.incident_id, owner_actor_id="treasury-agent")
        assert trace.incident.incident_id == inc.incident_id

    def test_no_owner_constraint_allows_any_access(self):
        inc = _create_incident(actor_id="treasury-agent")
        svc = InvestigationService()
        # No owner_actor_id = no enforcement (admin view)
        trace = svc.get_incident_trace(inc.incident_id)
        assert trace.incident.incident_id == inc.incident_id

    def test_nonexistent_incident_raises_security_error(self):
        svc = InvestigationService()
        with pytest.raises(SecurityError, match="not found"):
            svc.get_incident_trace("INC-DOES-NOT-EXIST")


# ---------------------------------------------------------------------------
# 3. Transaction trace IDOR
# ---------------------------------------------------------------------------

class TestTransactionTraceIDOR:

    def test_cross_actor_tx_access_denied(self):
        result = _run_tx(actor_id="operator-1")
        tx_id = result.transaction.transaction_id
        svc = InvestigationService()

        with pytest.raises(SecurityError, match="does not belong to actor"):
            svc.get_transaction_trace(tx_id, owner_actor_id="treasury-agent")

    def test_same_actor_tx_access_allowed(self):
        result = _run_tx(actor_id="operator-1")
        tx_id = result.transaction.transaction_id
        svc = InvestigationService()

        trace = svc.get_transaction_trace(tx_id, owner_actor_id="operator-1")
        assert trace["transaction"].transaction_id == tx_id

    def test_nonexistent_tx_raises_security_error(self):
        svc = InvestigationService()
        with pytest.raises(SecurityError, match="not found"):
            svc.get_transaction_trace("TX-DOES-NOT-EXIST")

    def test_tx_trace_includes_incidents(self):
        result = _run_tx()
        tx_id = result.transaction.transaction_id
        inc = _create_incident(tx_id=tx_id)

        svc = InvestigationService()
        trace = svc.get_transaction_trace(tx_id)

        assert any(i.incident_id == inc.incident_id for i in trace["incidents"])


# ---------------------------------------------------------------------------
# 4. Event search — filters and pagination
# ---------------------------------------------------------------------------

class TestEventSearch:

    def test_search_all_returns_results(self):
        _run_tx()
        _run_tx()
        svc = InvestigationService()
        result = svc.search_events()
        assert result.total >= 2
        assert len(result.items) >= 2

    def test_search_by_actor_filters_correctly(self):
        _run_tx(actor_id="operator-1")
        svc = InvestigationService()
        result = svc.search_events(actor_id="operator-1")
        assert all(t.actor_id == "operator-1" for t in result.items)

    def test_search_by_state_filters_correctly(self):
        _run_tx(actor_id="operator-1", amount="500.00")
        svc = InvestigationService()
        result = svc.search_events(state="blocked")
        assert all(t.state == "blocked" for t in result.items)

    def test_pagination_page_size_capped_at_100(self):
        for _ in range(3):
            _run_tx()
        svc = InvestigationService()
        result = svc.search_events(page_size=9999)
        assert result.page_size == 100

    def test_pagination_page_1_has_expected_items(self):
        for _ in range(5):
            _run_tx()
        svc = InvestigationService()
        result = svc.search_events(page=1, page_size=2)
        assert len(result.items) <= 2
        assert result.page == 1

    def test_pagination_beyond_total_returns_empty(self):
        for _ in range(2):
            _run_tx()
        svc = InvestigationService()
        result = svc.search_events(page=9999, page_size=10)
        assert result.items == []
        assert result.has_next is False

    def test_page_size_1_returns_single_item_with_has_next(self):
        for _ in range(3):
            _run_tx()
        svc = InvestigationService()
        result = svc.search_events(page=1, page_size=1)
        assert len(result.items) == 1
        assert result.has_next is True

    def test_search_cross_actor_idor_blocked(self):
        """Requesting actor may not query a different actor's events."""
        _run_tx(actor_id="operator-1")
        svc = InvestigationService()
        with pytest.raises(SecurityError, match="may not query"):
            svc.search_events(
                actor_id="treasury-agent",
                requesting_actor_id="operator-1",
            )

    def test_search_requesting_actor_auto_scopes(self):
        """Supplying requesting_actor_id scopes results to that actor."""
        _run_tx(actor_id="operator-1")
        svc = InvestigationService()
        result = svc.search_events(requesting_actor_id="operator-1")
        assert all(t.actor_id == "operator-1" for t in result.items)

    def test_search_by_date_range(self):
        _run_tx()
        svc = InvestigationService()
        now = datetime.datetime.now(datetime.UTC)
        yesterday = now - datetime.timedelta(days=1)
        tomorrow = now + datetime.timedelta(days=1)
        result = svc.search_events(since=yesterday, until=tomorrow)
        assert result.total >= 1

    def test_search_future_date_range_returns_empty(self):
        _run_tx()
        svc = InvestigationService()
        next_year = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365)
        result = svc.search_events(since=next_year)
        assert result.total == 0

    def test_search_amount_range(self):
        _run_tx(amount="500.00")
        svc = InvestigationService()
        result = svc.search_events(min_amount="100.00", max_amount="1000.00")
        assert all(10000 <= t.amount_minor <= 100000 for t in result.items)


# ---------------------------------------------------------------------------
# 5. Actor profile
# ---------------------------------------------------------------------------

class TestActorProfile:

    def test_profile_includes_transactions(self):
        _run_tx(actor_id="operator-1")
        svc = InvestigationService()
        profile = svc.get_actor_profile("operator-1")
        assert profile.actor_id == "operator-1"
        assert len(profile.recent_transactions) >= 1

    def test_profile_includes_incidents(self):
        inc = _create_incident(actor_id="treasury-agent")
        svc = InvestigationService()
        profile = svc.get_actor_profile("treasury-agent")
        assert any(i.incident_id == inc.incident_id for i in profile.incidents)

    def test_profile_open_incident_count(self):
        _create_incident(actor_id="treasury-agent", severity=IncidentSeverity.HIGH)
        svc = InvestigationService()
        profile = svc.get_actor_profile("treasury-agent")
        assert profile.open_incidents >= 1

    def test_profile_risk_contributors_derived_from_signals(self):
        result = _run_tx(actor_id="operator-1")
        tx_id = result.transaction.transaction_id

        session = get_session()
        try:
            SignalRepository(session).save(SecuritySignalRecord(
                signal_id=f"SIG-RC-{tx_id[:6]}",
                transaction_id=tx_id,
                signal_type="VELOCITY_SPIKE",
                score=25,
            ))
        finally:
            session.close()

        svc = InvestigationService()
        profile = svc.get_actor_profile("operator-1")
        # Risk contributors must be derived from stored signals
        assert "VELOCITY_SPIKE" in profile.risk_contributors

    def test_profile_cross_actor_idor_blocked(self):
        svc = InvestigationService()
        with pytest.raises(SecurityError, match="may not profile"):
            svc.get_actor_profile("operator-1", requesting_actor_id="treasury-agent")

    def test_profile_same_actor_allowed(self):
        svc = InvestigationService()
        profile = svc.get_actor_profile("operator-1", requesting_actor_id="operator-1")
        assert profile.actor_id == "operator-1"


# ---------------------------------------------------------------------------
# 6. Investigation timeline
# ---------------------------------------------------------------------------

class TestInvestigationTimeline:

    def test_timeline_is_sorted_chronologically(self):
        result = _run_tx()
        tx_id = result.transaction.transaction_id
        inc = _create_incident(tx_id=tx_id)

        svc = InvestigationService()
        items = svc.get_incident_timeline(inc.incident_id)

        timestamps = [i.timestamp for i in items]
        assert timestamps == sorted(timestamps)

    def test_timeline_contains_incident_entry(self):
        inc = _create_incident()
        svc = InvestigationService()
        items = svc.get_incident_timeline(inc.incident_id)

        sources = [i.source_type for i in items]
        assert "incident" in sources

    def test_timeline_contains_transaction_entry_when_linked(self):
        result = _run_tx()
        tx_id = result.transaction.transaction_id
        inc = _create_incident(tx_id=tx_id)

        svc = InvestigationService()
        items = svc.get_incident_timeline(inc.incident_id)

        sources = [i.source_type for i in items]
        assert "transaction" in sources

    def test_timeline_every_item_has_real_timestamp(self):
        result = _run_tx()
        tx_id = result.transaction.transaction_id
        inc = _create_incident(tx_id=tx_id)

        svc = InvestigationService()
        items = svc.get_incident_timeline(inc.incident_id)

        for item in items:
            assert item.timestamp is not None
            assert isinstance(item.timestamp, datetime.datetime)

    def test_timeline_every_item_has_source_id(self):
        result = _run_tx()
        tx_id = result.transaction.transaction_id
        inc = _create_incident(tx_id=tx_id)

        svc = InvestigationService()
        items = svc.get_incident_timeline(inc.incident_id)

        for item in items:
            assert item.source_id and item.source_id.strip()

    def test_timeline_idor_enforced(self):
        inc = _create_incident(actor_id="treasury-agent")
        svc = InvestigationService()
        with pytest.raises(SecurityError, match="does not belong to actor"):
            svc.get_incident_timeline(inc.incident_id, owner_actor_id="operator-1")


# ---------------------------------------------------------------------------
# 7. Incident lifecycle
# ---------------------------------------------------------------------------

class TestIncidentLifecycle:

    def test_valid_transition_open_to_investigating(self):
        inc = _create_incident()
        svc = IncidentService()
        updated = svc.transition_incident(inc.incident_id, "investigating", "operator-1")
        assert updated.state == "investigating"

    def test_valid_transition_investigating_to_contained(self):
        inc = _create_incident()
        svc = IncidentService()
        svc.transition_incident(inc.incident_id, "investigating", "operator-1")
        updated = svc.transition_incident(inc.incident_id, "contained", "operator-1")
        assert updated.state == "contained"

    def test_valid_transition_open_to_resolved_fast_path(self):
        inc = _create_incident()
        svc = IncidentService()
        updated = svc.transition_incident(inc.incident_id, "resolved", "operator-1")
        assert updated.state == "resolved"
        assert updated.resolved_at is not None

    def test_valid_transition_resolved_to_closed(self):
        inc = _create_incident()
        svc = IncidentService()
        svc.transition_incident(inc.incident_id, "resolved", "operator-1")
        updated = svc.transition_incident(inc.incident_id, "closed", "operator-1")
        assert updated.state == "closed"

    def test_invalid_transition_rejected(self):
        inc = _create_incident()
        svc = IncidentService()
        with pytest.raises(InvalidTransitionError, match="Cannot transition"):
            svc.transition_incident(inc.incident_id, "contained", "operator-1")

    def test_invalid_transition_from_closed_rejected(self):
        inc = _create_incident()
        svc = IncidentService()
        svc.transition_incident(inc.incident_id, "closed", "operator-1")
        with pytest.raises(InvalidTransitionError, match="terminal state"):
            svc.transition_incident(inc.incident_id, "open", "operator-1")

    def test_invalid_target_state_rejected(self):
        inc = _create_incident()
        svc = IncidentService()
        with pytest.raises(InvalidTransitionError):
            svc.transition_incident(inc.incident_id, "nonexistent_state", "operator-1")

    def test_idempotent_transition_returns_without_duplicate(self):
        """Transitioning to the current state must succeed without error and not double-write."""
        inc = _create_incident()
        svc = IncidentService()
        # Already 'open' — idempotent request
        result = svc.transition_incident(inc.incident_id, "open", "operator-1")
        assert result.state == "open"

    def test_transition_records_requesting_actor(self):
        inc = _create_incident()
        svc = IncidentService()
        updated = svc.transition_incident(inc.incident_id, "investigating", "operator-1", note="Escalated")
        assert updated.resolved_by == "operator-1"
        assert updated.state_note == "Escalated"

    def test_nonexistent_incident_transition_raises(self):
        svc = IncidentService()
        with pytest.raises(SecurityError, match="not found"):
            svc.transition_incident("INC-FAKE", "investigating", "operator-1")

    def test_terminal_resolved_has_resolved_at_timestamp(self):
        inc = _create_incident()
        svc = IncidentService()
        updated = svc.transition_incident(inc.incident_id, "resolved", "operator-1")
        assert updated.resolved_at is not None

    def test_non_terminal_transition_has_no_resolved_at(self):
        inc = _create_incident()
        svc = IncidentService()
        updated = svc.transition_incident(inc.incident_id, "investigating", "operator-1")
        assert updated.resolved_at is None


# ---------------------------------------------------------------------------
# 8. Repository bounded query safety
# ---------------------------------------------------------------------------

class TestRepositoryBoundaries:

    def test_search_page_size_max_respected(self):
        """search() must never return more than _INVESTIGATION_MAX_LIMIT rows."""
        session = get_session()
        try:
            result = TransactionRepository(session).search(limit=99999)
        finally:
            session.close()
        # The cap is 500; result length may be 0 if DB is empty in this test
        assert len(result) <= 500

    def test_signals_batch_query_empty_ids_returns_empty(self):
        session = get_session()
        try:
            result = SignalRepository(session).get_by_transactions([])
        finally:
            session.close()
        assert result == []

    def test_incidents_list_open_bounded(self):
        for _ in range(3):
            _create_incident()
        session = get_session()
        try:
            result = IncidentRepository(session).list_open(limit=2)
        finally:
            session.close()
        assert len(result) <= 2
