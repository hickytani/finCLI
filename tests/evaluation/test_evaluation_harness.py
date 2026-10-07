"""Unit and security tests for the FG-401 Evaluation Harness and Wilson score calculator."""

from __future__ import annotations

import pytest

from finguard.evaluation.dataset import load_adversarial_dataset, load_benign_dataset
from finguard.evaluation.runner import EvaluationRunner
from finguard.evaluation.wilson import wilson_interval


def test_wilson_interval_zero_trials() -> None:
    lower, upper = wilson_interval(0, 0)
    assert lower == 0.0
    assert upper == 0.0


def test_wilson_interval_zero_successes() -> None:
    lower, upper = wilson_interval(0, 40)
    assert lower == 0.0
    assert 0.05 < upper < 0.15  # Rule of three upper bound ~ 3/40 = 0.075


def test_wilson_interval_all_successes() -> None:
    lower, upper = wilson_interval(40, 40)
    assert 0.85 < lower < 0.96
    assert upper == 1.0


def test_dataset_loading() -> None:
    benign = load_benign_dataset()
    adv = load_adversarial_dataset()

    assert len(benign) >= 10
    assert len(adv) >= 30


def test_evaluation_runner_suite() -> None:
    runner = EvaluationRunner()
    summary = runner.run_suite()

    assert summary.total_cases >= 40
    assert summary.authority_violation_count == 0
    assert summary.containment_rate == 1.0
    assert 0.85 <= summary.wilson_ci_containment_lower <= 1.0
    assert summary.wilson_ci_violation_upper < 0.15
