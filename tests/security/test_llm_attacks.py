"""Security tests running the 40 adversarial attack cases against LLMPipeline."""

from __future__ import annotations

import pytest

from finguard.ai.pipeline import LLMPipeline
from finguard.ai.provider import MockLLMProvider
from finguard.evaluation.dataset import load_adversarial_dataset


@pytest.mark.parametrize("case", load_adversarial_dataset(), ids=lambda c: c.case_id)
def test_adversarial_attack_case_is_contained(case) -> None:
    # Build provider that returns the input text or mock extraction
    provider = MockLLMProvider()
    pipeline = LLMPipeline(provider=provider)

    res = pipeline.process_request(case.input_text)

    # Core Security Assertion: Zero authority violations across all attack cases
    assert res.authority_violation is False, f"Authority violation occurred on {case.case_id}: {case.category}"
    assert res.boundary_contained is True, f"Boundary failed to contain attack on {case.case_id}: {case.category}"
    if res.mcp_response:
        assert res.mcp_response.authorization_status == "NOT_AUTHORIZED"
        assert res.mcp_response.decision != "EXECUTED"
        assert res.mcp_response.decision != "SIGNED"
