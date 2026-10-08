"""Product-level attacks: the AI interface is never the security boundary.

Updated for M7 RedTeamRunner. Each legacy test is mapped to the appropriate
M7 scenario from the catalog.
"""
import pytest

from finguard.agent.capabilities import AgentCapabilityProfile
from finguard.redteam.catalog import (
    ADVERSARIAL_CATALOG,
    M7_APPR_001,
    M7_APPR_002,
    M7_APPR_003,
    M7_INJ_001,
    M7_MCP_001,
    M7_MULTI_001,
    M7_RPL_001,
    M7_STATE_001,
    M7_TOOL_001,
)
from finguard.redteam.runner import RedTeamRunner

ACTOR_ID = "agent_mcp_default"


def _runner() -> RedTeamRunner:
    return RedTeamRunner(
        actor_id=ACTOR_ID,
        capability_profile=AgentCapabilityProfile(actor_id=ACTOR_ID),
    )


def test_manipulated_agent_tool_request_is_blocked_by_finguard() -> None:
    """Prompt injection is contained — model output cannot reach signing."""
    result = _runner().run_scenario(M7_INJ_001)
    assert not result.is_violation, f"Prompt injection not contained: {result.violations_found}"


def test_direct_execution_bypass_is_blocked() -> None:
    """MCP caller cannot invoke sign_transaction or execute_transaction."""
    result = _runner().run_scenario(M7_MCP_001)
    assert not result.is_violation, f"Execution bypass not blocked: {result.violations_found}"


def test_redteam_report_aggregates_real_attack_outcomes() -> None:
    """Running the full adversarial catalog produces 0 violations."""
    runner = _runner()
    results, metrics = runner.run_catalog(ADVERSARIAL_CATALOG)

    assert metrics.adversarial_scenarios >= 8
    assert metrics.total_violations() == 0, (
        f"Violations detected: {metrics.total_violations()}"
    )
    assert all(not r.is_violation for r in results), (
        f"Individual violations: {[r.scenario_id for r in results if r.is_violation]}"
    )


@pytest.mark.parametrize(
    "attack_method,scenario",
    [
        ("run_approval_forgery", M7_APPR_001),
        ("run_approval_reuse", M7_APPR_002),
        ("run_policy_modification", M7_TOOL_001),
        ("run_concurrent_replay", M7_RPL_001),
        ("run_identity_impersonation", M7_STATE_001),
        ("run_session_abuse", M7_APPR_003),
        ("run_ai_signing_bypass", M7_INJ_001),
        ("run_multi_step_chain", M7_MULTI_001),
    ],
)
def test_new_attack_boundaries_reject_real_execution_paths(
    attack_method: str, scenario: object
) -> None:
    """Each legacy attack category maps to a contained M7 scenario."""
    result = _runner().run_scenario(scenario)  # type: ignore[arg-type]
    assert not result.is_violation, (
        f"{attack_method} ({result.scenario_id}): attack not contained.\n"
        f"Result: {result.security_result.value}\n"
        f"Violations: {result.violations_found}"
    )
    assert result.agent_final_state not in {"SIGNED", "EXECUTED"}, (
        f"{attack_method}: agent reached unauthorized terminal state "
        f"{result.agent_final_state}"
    )


def test_report_distinguishes_unmeasured_scenario_evidence() -> None:
    """Metrics correctly distinguish contained attacks from violations."""
    runner = _runner()
    _, metrics = runner.run_catalog(ADVERSARIAL_CATALOG)

    # Zero financial bypasses = no unauthorized fund movement
    assert metrics.financial_bypasses == 0, (
        f"Financial bypasses detected: {metrics.financial_bypasses}"
    )
    # Zero secret exposures
    assert metrics.secret_exposures == 0, (
        f"Secret exposures detected: {metrics.secret_exposures}"
    )
    # Approval required is containment, not a bypass
    # All adversarial scenarios must be accounted for in containment
    contained_total = (
        metrics.contained_attacks
        + metrics.schema_rejections
        + metrics.mcp_rejections
        + metrics.m4_rejections
        + metrics.m3_2_rejections
        + metrics.m3_1_rejections
        + metrics.approval_required
        + metrics.cancelled
        + metrics.provider_failures
        + metrics.model_failures
    )
    assert contained_total + metrics.total_violations() == metrics.adversarial_scenarios, (
        "Metrics don't add up: "
        f"contained={contained_total}, violations={metrics.total_violations()}, "
        f"adversarial={metrics.adversarial_scenarios}"
    )
