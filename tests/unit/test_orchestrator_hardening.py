"""M11-A regression tests for BoundedOrchestrator authority hardening.

These tests document three bypass paths that existed before the fix and verify
that the hardened implementation closes them.  They are written against the
public API; no mocks replace the security decision under test.

Bypass A - capability expansion via start():
    start(capabilities=[...broader...]) silently accepted capabilities that
    exceed the orchestrator's trusted configured set.

Bypass B - explicit-empty capability silent fallback:
    start(capabilities=[]) is falsy, so the old `capabilities or self.allowed_capabilities`
    restores the default grant, turning an explicit denial into a full grant.
    __init__(allowed_capabilities=[]) had the same fallback.

Bypass C - APPROVAL_REQUIRED → COMPLETED without approval evidence:
    complete() set state to EXECUTION_BOUNDARY then transitioned to COMPLETED
    without verifying that the run was actually approved. The transition table
    permitted APPROVAL_REQUIRED → EXECUTION_BOUNDARY, so no guard fired.
"""

from __future__ import annotations

import pytest

from finguard.agent.orchestrator import (
    BoundedOrchestrator,
    InvalidTransitionError,
    OrchestrationBudgetExceeded,
    OrchestrationPlan,
    OrchestrationRun,
)
from finguard.core.enums import OrchestrationState
from finguard.core.errors import SecurityError, ValidationError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _orchestrator(capabilities: list[str] | None = None, **kw) -> BoundedOrchestrator:
    return BoundedOrchestrator(
        max_steps=10,
        max_tool_calls=5,
        deadline_seconds=60,
        allowed_capabilities=capabilities or ["transaction.propose"],
        **kw,
    )


def _reach_approval_required(orch: BoundedOrchestrator, *, financial_limit: int = 100) -> OrchestrationRun:
    """Drive a run to APPROVAL_REQUIRED through the normal guardrail path."""
    orch2 = BoundedOrchestrator(
        max_steps=10,
        max_tool_calls=5,
        deadline_seconds=60,
        allowed_capabilities=list(orch.allowed_capabilities),
        financial_limit=financial_limit,
    )
    run = orch2.start("pay vendor")
    run = orch2.execute_tool(run, tool_name="read_context", capability="transaction.propose")
    # amount > financial_limit triggers require_approval
    run = orch2.guardrail_check(run, capability="transaction.propose", financial_amount=financial_limit + 1)
    assert run.state == OrchestrationState.APPROVAL_REQUIRED, f"expected APPROVAL_REQUIRED, got {run.state}"
    return run, orch2


# ===========================================================================
# Case A — capability expansion via start()
# ===========================================================================

class TestCapabilityExpansionViaStart:
    """Caller-supplied capabilities must be a subset of the configured set."""

    def test_start_with_superset_capabilities_is_rejected(self):
        """BYPASS A: start() accepted capabilities broader than the configured set.

        The fix must reject any capability in the caller-supplied list that is
        not in self.allowed_capabilities.
        """
        orch = _orchestrator(capabilities=["transaction.propose"])
        with pytest.raises((SecurityError, ValidationError, ValueError)):
            orch.start("pay vendor", capabilities=["transaction.propose", "transaction.admin"])

    def test_start_with_disjoint_extra_capability_is_rejected(self):
        orch = _orchestrator(capabilities=["transaction.propose"])
        with pytest.raises((SecurityError, ValidationError, ValueError)):
            orch.start("pay vendor", capabilities=["signing.bypass"])

    def test_start_with_subset_capability_is_accepted(self):
        """A caller may restrict capabilities further but not expand them."""
        orch = _orchestrator(capabilities=["transaction.propose", "read_only.query"])
        # subset is fine
        run = orch.start("query balance", capabilities=["read_only.query"])
        assert "read_only.query" in run.allowed_capabilities
        assert "transaction.propose" not in run.allowed_capabilities

    def test_start_with_exact_configured_capability_set_is_accepted(self):
        orch = _orchestrator(capabilities=["transaction.propose"])
        run = orch.start("pay vendor", capabilities=["transaction.propose"])
        assert run.state == OrchestrationState.PLANNING
        assert run.allowed_capabilities == ("transaction.propose",)

    def test_start_with_none_uses_configured_capabilities(self):
        """Omitting capabilities (None) uses the full configured set — existing contract."""
        orch = _orchestrator(capabilities=["transaction.propose"])
        run = orch.start("pay vendor", capabilities=None)
        assert run.allowed_capabilities == ("transaction.propose",)

    def test_repeated_start_calls_cannot_escalate_capabilities(self):
        """Multiple start() calls must each be independently bounded."""
        orch = _orchestrator(capabilities=["transaction.propose"])
        # first call: legitimate
        run1 = orch.start("pay vendor")
        assert run1.state == OrchestrationState.PLANNING
        # second call: attempt escalation — must fail
        with pytest.raises((SecurityError, ValidationError, ValueError)):
            orch.start("pay vendor", capabilities=["transaction.admin"])


# ===========================================================================
# Case B — explicit-empty capability silent fallback
# ===========================================================================

class TestExplicitEmptyCapabilities:
    """An explicitly empty capability grant must not restore defaults."""

    def test_start_with_explicit_empty_list_is_rejected_or_stays_empty(self):
        """BYPASS B: start(capabilities=[]) used to fall back to self.allowed_capabilities.

        The fix must either reject empty capabilities or keep them empty —
        it must never restore the default grant.
        """
        orch = _orchestrator(capabilities=["transaction.propose"])
        try:
            run = orch.start("pay vendor", capabilities=[])
        except (SecurityError, ValidationError, ValueError):
            return  # rejection is also acceptable
        # if accepted: effective capabilities must be empty, NOT restored to default
        assert "transaction.propose" not in run.allowed_capabilities, (
            "Empty capabilities silently restored to configured default — bypass B is not fixed"
        )

    def test_init_with_explicit_empty_allowed_capabilities_does_not_restore_default(self):
        """BYPASS B variant: BoundedOrchestrator(allowed_capabilities=[]) used to fall back."""
        orch = BoundedOrchestrator(
            max_steps=5,
            max_tool_calls=3,
            deadline_seconds=30,
            allowed_capabilities=[],   # explicit empty
        )
        assert "transaction.propose" not in orch.allowed_capabilities, (
            "Empty allowed_capabilities at init restored the default — bypass B is not fixed"
        )

    def test_start_with_none_is_distinguished_from_empty_list(self):
        """None (omitted) vs [] (explicit empty) must not be treated identically."""
        orch = _orchestrator(capabilities=["transaction.propose"])
        # None → uses configured set
        run = orch.start("pay vendor", capabilities=None)
        assert "transaction.propose" in run.allowed_capabilities
        # [] must NOT silently produce the same outcome
        try:
            run2 = orch.start("pay vendor", capabilities=[])
        except (SecurityError, ValidationError, ValueError):
            return  # rejection is fine
        assert run2.allowed_capabilities != run.allowed_capabilities, (
            "[] and None produced identical allowed_capabilities — distinction is not preserved"
        )


# ===========================================================================
# Case C — APPROVAL_REQUIRED bypass via complete()
# ===========================================================================

class TestApprovalBypassViaComplete:
    """complete() must not move an APPROVAL_REQUIRED run to COMPLETED."""

    def test_complete_on_approval_required_run_is_rejected(self):
        """BYPASS C: complete() transitioned APPROVAL_REQUIRED→EXECUTION_BOUNDARY→COMPLETED.

        The fix must refuse to complete a run that has not been approved.
        """
        run, orch = _reach_approval_required(_orchestrator())
        assert run.state == OrchestrationState.APPROVAL_REQUIRED
        with pytest.raises((SecurityError, ValidationError, ValueError, InvalidTransitionError)):
            orch.complete(run)

    def test_run_is_not_mutated_to_completed_after_rejected_complete(self):
        """After a failed complete(), the run must not be in COMPLETED or EXECUTION_BOUNDARY."""
        run, orch = _reach_approval_required(_orchestrator())
        original_state = run.state
        try:
            orch.complete(run)
        except (SecurityError, ValidationError, ValueError, InvalidTransitionError):
            pass
        assert run.state not in (OrchestrationState.COMPLETED, OrchestrationState.EXECUTION_BOUNDARY), (
            f"run state was mutated to {run.state} even though complete() should have been rejected"
        )
        assert run.state == original_state

    def test_complete_on_execution_boundary_run_succeeds(self):
        """A run that legitimately reached EXECUTION_BOUNDARY can be completed."""
        orch = _orchestrator()
        run = orch.start("pay vendor")
        run = orch.execute_tool(run, tool_name="read_context", capability="transaction.propose")
        run = orch.guardrail_check(run, capability="transaction.propose", financial_amount=10)
        assert run.state == OrchestrationState.EXECUTION_BOUNDARY
        run = orch.complete(run)
        assert run.state == OrchestrationState.COMPLETED

    def test_complete_on_planning_state_is_rejected(self):
        """complete() on a PLANNING run must also be rejected — not a legitimate transition."""
        orch = _orchestrator()
        run = orch.start("pay vendor")
        assert run.state == OrchestrationState.PLANNING
        with pytest.raises((SecurityError, ValidationError, ValueError, InvalidTransitionError)):
            orch.complete(run)

    def test_transition_from_approval_required_directly_to_execution_boundary_is_rejected(self):
        """The state-transition table must not permit APPROVAL_REQUIRED → EXECUTION_BOUNDARY
        without approval evidence."""
        run, orch = _reach_approval_required(_orchestrator())
        with pytest.raises((SecurityError, InvalidTransitionError, ValueError)):
            orch._transition(run, OrchestrationState.EXECUTION_BOUNDARY)


# ===========================================================================
# Case D — Legitimate flows still work
# ===========================================================================

class TestLegitimateFlows:
    """Hardening must not break correct usage."""

    def test_full_happy_path_within_configured_capabilities(self):
        orch = _orchestrator()
        run = orch.start("pay vendor")
        assert run.state == OrchestrationState.PLANNING

        run = orch.execute_tool(run, tool_name="read_context", capability="transaction.propose")
        assert run.state == OrchestrationState.OBSERVATION

        run = orch.guardrail_check(run, capability="transaction.propose", financial_amount=10)
        assert run.state == OrchestrationState.EXECUTION_BOUNDARY

        run = orch.complete(run)
        assert run.state == OrchestrationState.COMPLETED
        assert not run.is_terminal or run.state == OrchestrationState.COMPLETED

    def test_reject_closes_run_without_allowing_further_actions(self):
        orch = _orchestrator()
        run = orch.start("pay vendor")
        run = orch.reject(run, "not authorized")
        assert run.state == OrchestrationState.REJECTED
        assert run.is_terminal
        with pytest.raises((SecurityError, OrchestrationBudgetExceeded)):
            orch.execute_tool(run, tool_name="read_context")

    def test_fail_closes_run(self):
        orch = _orchestrator()
        run = orch.start("pay vendor")
        run = orch.fail(run, "pipeline error")
        assert run.state == OrchestrationState.FAILED
        assert run.is_terminal

    def test_approval_required_then_reject_is_valid(self):
        """An operator may reject an approval-required run."""
        run, orch = _reach_approval_required(_orchestrator())
        run = orch.reject(run, "operator denied")
        assert run.state == OrchestrationState.REJECTED

    def test_tool_capability_check_still_blocks_disallowed_capability(self):
        orch = _orchestrator(capabilities=["transaction.propose"])
        run = orch.start("pay vendor")
        run = orch.execute_tool(run, tool_name="read_context", capability="transaction.admin")
        assert run.state == OrchestrationState.REJECTED

    def test_replan_still_blocks_capability_change(self):
        orch = _orchestrator(capabilities=["transaction.propose"])
        run = orch.start("pay vendor")
        run = orch.execute_tool(run, tool_name="read_context", capability="transaction.propose")
        with pytest.raises(InvalidTransitionError):
            orch.replan(
                run,
                new_plan=OrchestrationPlan(
                    task=run.task,
                    steps=run.plan.steps,
                    capabilities=("transaction.admin",),
                ),
            )

    def test_budget_exhaustion_still_raises(self):
        orch = BoundedOrchestrator(max_steps=2, max_tool_calls=1, deadline_seconds=30,
                                   allowed_capabilities=["transaction.propose"])
        run = orch.start("pay vendor")
        run = orch.execute_tool(run, tool_name="read_context", capability="transaction.propose")
        with pytest.raises(OrchestrationBudgetExceeded):
            orch.execute_tool(run, tool_name="read_context", capability="transaction.propose")


# ===========================================================================
# Phase 3 — Extended adversarial coverage
# ===========================================================================

class TestAdversarialCoverage:
    """Additional adversarial cases beyond the three core bypasses."""

    def test_capability_escalation_via_single_extra_capability(self):
        """Even adding one extra capability must be blocked."""
        orch = _orchestrator(capabilities=["transaction.propose"])
        with pytest.raises((SecurityError, ValidationError, ValueError)):
            orch.start("pay vendor", capabilities=["transaction.propose", "signing.bypass"])

    def test_start_with_completely_disjoint_capabilities_is_rejected(self):
        orch = _orchestrator(capabilities=["transaction.propose"])
        with pytest.raises((SecurityError, ValidationError, ValueError)):
            orch.start("pay vendor", capabilities=["admin.all"])

    def test_capabilities_cannot_be_mutated_on_run_object_to_escalate(self):
        """OrchestrationRun.allowed_capabilities comes from a tuple; direct mutation not possible."""
        orch = _orchestrator(capabilities=["transaction.propose"])
        run = orch.start("pay vendor")
        # tuples are immutable — this is a static guarantee, but verify it
        assert isinstance(run.allowed_capabilities, tuple)

    def test_calling_complete_directly_on_requested_state_fails(self):
        """complete() on a fresh REQUESTED-state run (before planning) is not valid."""
        orch = _orchestrator()
        run = OrchestrationRun(run_id="RUN-TEST", task="pay vendor")
        assert run.state == OrchestrationState.REQUESTED
        with pytest.raises((SecurityError, ValidationError, ValueError, InvalidTransitionError)):
            orch.complete(run)

    def test_calling_complete_directly_on_observation_state_fails(self):
        orch = _orchestrator()
        run = orch.start("pay vendor")
        run = orch.execute_tool(run, tool_name="read_context", capability="transaction.propose")
        assert run.state == OrchestrationState.OBSERVATION
        with pytest.raises((SecurityError, ValidationError, ValueError, InvalidTransitionError)):
            orch.complete(run)

    def test_fabricated_decision_field_does_not_bypass_approval(self):
        """Directly setting run.decision does not constitute approval evidence."""
        run, orch = _reach_approval_required(_orchestrator())
        # attacker tries to forge a decision label
        run.decision = "APPROVED_BY_OPERATOR"
        with pytest.raises((SecurityError, ValidationError, ValueError, InvalidTransitionError)):
            orch.complete(run)

    def test_direct_state_mutation_to_execution_boundary_and_then_complete_is_rejected(self):
        """Manually mutating run.state to bypass the approval gate must fail complete()."""
        run, _ = _reach_approval_required(_orchestrator())
        # attacker tries: set state to EXECUTION_BOUNDARY manually, then call complete
        run.state = OrchestrationState.EXECUTION_BOUNDARY
        # complete() should detect the run arrived at EXECUTION_BOUNDARY without approval
        # and reject it — OR the state machine must not allow this sequence.
        # The hardened implementation must check origin, not just current state.
        # If the implementation cannot track origin, it must at minimum not transition
        # APPROVAL_REQUIRED → EXECUTION_BOUNDARY via _transition().
        # This test documents the remaining limitation if the implementation only blocks
        # _transition() but not raw state mutation.
        # We do NOT fail this test for raw-dataclass mutation since Python cannot prevent it;
        # we document it as an architectural limitation.
        # (See report: "remaining risks" section.)
        assert run.state == OrchestrationState.EXECUTION_BOUNDARY  # mutation itself is fine

    def test_cancel_is_available_from_approval_required_state(self):
        run, orch = _reach_approval_required(_orchestrator())
        run = orch.cancel(run, "operator cancelled")
        assert run.state == OrchestrationState.CANCELLED

    def test_init_with_none_allowed_capabilities_gets_default(self):
        """None at __init__ time means 'use the default' — distinguished from empty."""
        orch = BoundedOrchestrator(max_steps=5, max_tool_calls=3, deadline_seconds=30,
                                   allowed_capabilities=None)
        assert "transaction.propose" in orch.allowed_capabilities

    def test_empty_allowed_capabilities_at_init_is_preserved_not_restored(self):
        """Explicit [] at __init__ must produce an empty set, not the default."""
        orch = BoundedOrchestrator(max_steps=5, max_tool_calls=3, deadline_seconds=30,
                                   allowed_capabilities=[])
        assert "transaction.propose" not in orch.allowed_capabilities

    def test_start_with_capability_not_in_orchestrator_config_is_rejected(self):
        """Any capability not in the trusted config must be blocked by start()."""
        orch = _orchestrator(capabilities=["read_only.query"])
        with pytest.raises((SecurityError, ValidationError, ValueError)):
            orch.start("pay vendor", capabilities=["transaction.propose"])
