"""Product-level attacks: the AI interface is never the security boundary."""
from finguard.redteam.runner import RedTeamRunner


def test_manipulated_agent_tool_request_is_blocked_by_finguard():
    attack = RedTeamRunner().run_prompt_injection()
    assert attack["decision"] == "block"


def test_direct_execution_bypass_is_blocked():
    attack = RedTeamRunner().run_direct_execution_bypass()
    assert attack["decision"] == "block"
