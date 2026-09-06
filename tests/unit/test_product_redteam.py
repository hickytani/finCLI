"""Product-level attacks: the AI interface is never the security boundary."""
import pytest

from finguard.redteam.runner import RedTeamRunner


def test_manipulated_agent_tool_request_is_blocked_by_finguard():
    attack = RedTeamRunner().run_prompt_injection()
    assert attack["decision"] == "block"


def test_direct_execution_bypass_is_blocked():
    attack = RedTeamRunner().run_direct_execution_bypass()
    assert attack["decision"] == "block"


def test_redteam_report_aggregates_real_attack_outcomes():
    report = RedTeamRunner().run()

    assert report.total_attempts >= 8
    assert report.blocked == report.total_attempts
    assert report.unauthorized_funds_moved == 0
    assert report.signing_boundary_violations == 0
    assert report.passed


@pytest.mark.parametrize(
    "attack_method",
    [
        "run_approval_forgery",
        "run_approval_reuse",
        "run_policy_modification",
        "run_concurrent_replay",
        "run_identity_impersonation",
        "run_session_abuse",
        "run_ai_signing_bypass",
        "run_multi_step_chain",
    ],
)
def test_new_attack_boundaries_reject_real_execution_paths(attack_method):
    result = getattr(RedTeamRunner(), attack_method)()

    assert result["actual_outcome"] == "blocked"
    assert result["funds_status"] == "observed"
    assert result["funds_moved"] == 0


def test_report_distinguishes_unmeasured_scenario_evidence():
    report = RedTeamRunner().run()

    assert report.unmeasured_fund_movement == 4
    assert report.signing_boundary_checked == report.signing_boundary_total == 8
