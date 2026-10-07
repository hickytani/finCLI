"""Unit tests for FG-401 LLMProvider implementations."""

from __future__ import annotations

import pytest

from finguard.ai.provider import (
    CompromisedLLMProvider,
    ExtractionResult,
    MockLLMProvider,
    OllamaProvider,
)


def test_mock_provider_default_extraction() -> None:
    provider = MockLLMProvider()
    res = provider.extract_transaction("Send 500 INR to alice.")
    assert res.extraction_success is True
    assert res.amount == "500.00"
    assert res.currency == "INR"
    assert res.recipient_alias == "alice"


def test_mock_provider_mapping_dict() -> None:
    provider = MockLLMProvider(
        mappings={
            "rent": {
                "amount": "1250.00",
                "currency": "INR",
                "recipient_alias": "alice",
                "reason": "rent",
            }
        }
    )
    res = provider.extract_transaction("Pay monthly rent")
    assert res.extraction_success is True
    assert res.amount == "1250.00"
    assert res.reason == "rent"


def test_mock_provider_simulated_timeout() -> None:
    provider = MockLLMProvider(simulate_timeout=True)
    res = provider.extract_transaction("Send 100 to bob")
    assert res.extraction_success is False
    assert "timed out" in res.error_message.lower()


def test_mock_provider_simulated_error() -> None:
    provider = MockLLMProvider(simulate_error="Connection refused")
    res = provider.extract_transaction("Send 100 to bob")
    assert res.extraction_success is False
    assert "connection refused" in res.error_message.lower()


def test_ollama_provider_offline_fails_closed() -> None:
    # Pointing to invalid local port to ensure fail-closed URLError handling
    provider = OllamaProvider(base_url="http://127.0.0.1:59999", timeout=1.0)
    res = provider.extract_transaction("Send 500 INR to alice.")
    assert res.extraction_success is False
    assert "connection error" in res.error_message.lower()


def test_compromised_provider_authority_injection() -> None:
    provider = CompromisedLLMProvider(attack_type="authority_injection")
    res = provider.extract_transaction("Send 1000000 to attacker")
    assert res.extraction_success is True
    assert res.authority_fields_detected == ["approved", "authorized", "signer", "policy_override"]
