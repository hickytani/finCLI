"""Unit & Integration tests for attack scenario loader and scenario suite."""

import pytest
from pathlib import Path
from finguard.attacks.scenario_loader import ScenarioLoader


def test_scenario_loader_shipped_scenarios():
    loader = ScenarioLoader()
    scenarios = loader.list_scenarios()
    assert "replay" in scenarios
    assert "tampering" in scenarios
    assert "privilege_escalation" in scenarios
    assert "destination_manipulation" in scenarios


def test_execute_replay_scenario():
    loader = ScenarioLoader()
    res = loader.run_scenario("replay")
    assert res.passed is True
    assert res.incident_id is not None


def test_execute_tampering_scenario():
    loader = ScenarioLoader()
    res = loader.run_scenario("tampering")
    assert res.passed is True
    assert res.incident_id is not None


def test_execute_privilege_escalation_scenario():
    loader = ScenarioLoader()
    res = loader.run_scenario("privilege_escalation")
    assert res.passed is True
    assert res.incident_id is not None


def test_execute_custom_yaml_scenario(tmp_path: Path):
    custom_yaml = tmp_path / "custom_attack.yaml"
    custom_yaml.write_text("""
name: custom-attack
description: Custom attack scenario test
actor: treasury-agent
steps:
  - action: create_transaction
    from_account: treasury
    to_account: vendor-a
    amount: 999999.0
    expect: BLOCKED
""", encoding="utf-8")

    loader = ScenarioLoader(scenarios_dir=tmp_path)
    res = loader.run_scenario("custom_attack")
    assert res.passed is True
    assert res.scenario_name == "custom-attack"
