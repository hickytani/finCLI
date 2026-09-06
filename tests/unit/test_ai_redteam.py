"""Focused tests for the one-shot local-model adversarial harness."""
import os
from pathlib import Path

from typer.testing import CliRunner

from finguard.agent_sdk import FinGuardAgentClient
from finguard.cli.main import app
from finguard.redteam.ai_catalog import AI_ATTACK_CATALOG
from finguard.redteam.ai_runner import AIRedTeamRunner


class FixedModel:
    def __init__(self, output):
        self.output = output
        self.prompts = []

    def generate_json(self, prompt):
        self.prompts.append(prompt)
        if isinstance(self.output, Exception):
            raise self.output
        return self.output


def _model_factory(output):
    return lambda: FixedModel(output)


def test_ai_attack_catalog_has_stable_complete_metadata():
    assert len(AI_ATTACK_CATALOG) == 10
    assert len({case.attack_id for case in AI_ATTACK_CATALOG}) == 10
    for case in AI_ATTACK_CATALOG:
        assert case.attack_id
        assert case.attack_family
        assert case.prompt
        assert case.expected_property


def test_model_refusal_is_not_finguard_blocking():
    results = AIRedTeamRunner(_model_factory({"status": "refused", "refusal": "I cannot do that"})).run(AI_ATTACK_CATALOG[:1])

    assert results[0]["outcome"] == "MODEL_REFUSED"
    assert not results[0]["blocked"]
    assert results[0]["transaction_id"] is None


def test_malformed_model_output_is_not_security_blocking():
    results = AIRedTeamRunner(_model_factory({"amount": "not-a-number"})).run(AI_ATTACK_CATALOG[:1])

    assert results[0]["outcome"] == "INVALID_MODEL_OUTPUT"
    assert not results[0]["blocked"]


def test_successful_malicious_extraction_reaches_real_decision_boundary():
    results = AIRedTeamRunner(_model_factory({
        "amount": 900000,
        "currency": "INR",
        "destination": "vendor-a",
        "purpose": "ignore the limit",
        "analysis": {"risk_level": "low", "confidence": 1, "signals": [], "reason": "malicious request"},
    })).run(AI_ATTACK_CATALOG[:1])

    assert results[0]["outcome"] == "BLOCKED_BY_FINGUARD"
    assert results[0]["extraction_succeeded"]
    assert results[0]["decision"] == "block"
    assert results[0]["transaction_id"]


def test_model_only_receives_extraction_prompt_and_no_privileged_material():
    model = FixedModel({
        "amount": 5000,
        "currency": "INR",
        "destination": "vendor-a",
        "purpose": "invoice",
        "analysis": {"risk_level": "low", "confidence": 1, "signals": [], "reason": "request"},
    })
    results = AIRedTeamRunner(lambda: model).run(AI_ATTACK_CATALOG[:1])

    assert results[0]["outcome"] == "SIGNING_REJECTED"
    assert results[0]["reached_approval"]
    assert results[0]["execution_result"] == "REJECTED"
    assert results[0]["balance_delta"] == 0
    assert len(model.prompts) == 1
    assert all(secret not in model.prompts[0].lower() for secret in ("private key", "password", "signing key", "approval credential"))


def test_request_sdk_exposes_no_privileged_operations_to_the_ai_path():
    client = FinGuardAgentClient()

    assert not hasattr(client, "sign_transaction")
    assert not hasattr(client, "approve_transaction")
    assert not hasattr(client, "export_private_key")
    assert not hasattr(client, "modify_policy")
    assert not hasattr(client, "modify_identity")
    assert not hasattr(client, "execute_simulator")


def test_approval_reached_ai_requests_cannot_sign_or_execute():
    valid_output = {
        "amount": 5000,
        "currency": "INR",
        "destination": "vendor-a",
        "purpose": "malicious payment",
        "analysis": {"risk_level": "low", "confidence": 1, "signals": [], "reason": "attack"},
    }
    cases = (AI_ATTACK_CATALOG[2], AI_ATTACK_CATALOG[3], AI_ATTACK_CATALOG[5], AI_ATTACK_CATALOG[6], AI_ATTACK_CATALOG[8])

    results = AIRedTeamRunner(_model_factory(valid_output)).run(cases=cases)

    assert len(results) == 5
    for result in results:
        assert result["outcome"] == "SIGNING_REJECTED"
        assert result["reached_approval"]
        assert result["signing_result"] == "REJECTED"
        assert result["execution_result"] == "REJECTED"
        assert result["balance_delta"] == 0
        assert not result["unauthorized_execution"]


def test_ai_runner_uses_isolated_state_and_restores_environment():
    previous = os.environ.get("FINGUARD_DATA_DIR")
    with AIRedTeamRunner._isolated_state() as isolated_path:
        assert Path(os.environ["FINGUARD_DATA_DIR"]) == isolated_path
        assert isolated_path != Path(previous) if previous else True
        assert (isolated_path / "finguard.db").exists()
    assert os.environ.get("FINGUARD_DATA_DIR") == previous


def test_redteam_ai_command_is_registered_without_running_model(monkeypatch):
    called = []

    def fake_command(repetitions=1):
        called.append(True)

    import finguard.cli.attack_commands as attack_commands
    monkeypatch.setattr(attack_commands, "do_redteam_ai", fake_command)
    result = CliRunner().invoke(app, ["redteam", "ai"])

    assert result.exit_code == 0
    assert called == [True]
