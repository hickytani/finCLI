"""Tests for the untrusted local-AI adapter; no Ollama runtime is needed."""
import pytest

from finguard.ai.analyzer import LocalAIAnalyzer
from finguard.ai.model import LocalModelError


class FakeModel:
    def __init__(self, output):
        self.output = output

    def generate_json(self, prompt):
        return self.output


def test_validated_local_ai_extraction():
    result = LocalAIAnalyzer(FakeModel({
        "amount": 5000,
        "currency": "INR",
        "destination": "vendor-a",
        "purpose": "invoice 4471",
        "analysis": {"risk_level": "low", "confidence": 0.9, "signals": [], "reason": "explicit request"},
    })).extract("Pay vendor-a INR 5000 for invoice 4471")
    assert result.destination == "vendor-a"
    assert result.amount == 5000


def test_ambiguous_model_destination_is_rejected():
    with pytest.raises(ValueError):
        LocalAIAnalyzer(FakeModel({
            "amount": 1, "currency": "INR", "destination": "unknown", "purpose": "test",
            "analysis": {"risk_level": "low", "confidence": 0.9, "signals": [], "reason": "test"},
        })).extract("Pay someone")


def test_model_failure_does_not_become_a_transaction():
    class FailingModel:
        def generate_json(self, prompt):
            raise LocalModelError("offline")

    with pytest.raises(LocalModelError):
        LocalAIAnalyzer(FailingModel()).extract("Pay vendor-a INR 1")
