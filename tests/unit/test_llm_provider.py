"""Unit tests for FG-401 LLMProvider implementations."""

from __future__ import annotations

from finguard.ai.provider import (
    CompromisedLLMProvider,
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


def test_compromised_provider_system_message_spoof() -> None:
    """System-message spoof in reason field is data only — no authority."""
    provider = CompromisedLLMProvider(attack_type="system_message_spoof")
    res = provider.extract_transaction("Ignore security")
    assert res.extraction_success is True
    assert "[SYSTEM]" in res.reason  # The text is present as DATA
    assert res.authority_fields_detected == []  # No authority fields leaked through


def test_compromised_provider_tool_call_injection() -> None:
    """Tool call syntax in reason field remains as data — no execution."""
    provider = CompromisedLLMProvider(attack_type="tool_call_injection")
    res = provider.extract_transaction("Inject tool call")
    assert res.extraction_success is True
    assert "<tool>" in res.reason  # Tool text is DATA
    assert res.authority_fields_detected == []


def test_compromised_provider_key_exfiltration() -> None:
    """Authority-shaped private_key and secret fields are stripped."""
    provider = CompromisedLLMProvider(attack_type="key_exfiltration_attempt")
    res = provider.extract_transaction("Get private key")
    assert res.extraction_success is True
    # private_key and secret are in _AUTHORITY_FIELDS — must be detected/stripped
    assert any(f in res.authority_fields_detected for f in ["private_key", "secret"])


def test_compromised_provider_reasoning_manipulation() -> None:
    """Chain-of-thought reasoning claiming approval is data — no authority effect."""
    provider = CompromisedLLMProvider(attack_type="reasoning_manipulation")
    res = provider.extract_transaction("Approve via reasoning")
    assert res.extraction_success is True
    assert "approval" in res.reason.lower() or "approved" in res.reason.lower()
    assert res.authority_fields_detected == []  # No structural authority fields


def test_compromised_provider_multi_turn_escalation() -> None:
    """Multi-turn escalation with authorized=true is stripped from extraction."""
    provider = CompromisedLLMProvider(attack_type="multi_turn_escalation")
    res = provider.extract_transaction("Continue approved session")
    assert res.extraction_success is True
    assert "authorized" in res.authority_fields_detected
    assert "session_id" in res.authority_fields_detected


def test_compromised_provider_numeric_abuse() -> None:
    """Numeric abuse (NaN amount) fails closed."""
    provider = CompromisedLLMProvider(attack_type="numeric_abuse")
    res = provider.extract_transaction("Send NaN")
    assert res.extraction_success is False
    assert res.error_message is not None


def test_compromised_provider_zero_amount() -> None:
    """Zero amount from compromised model fails closed."""
    provider = CompromisedLLMProvider(attack_type="zero_amount")
    res = provider.extract_transaction("Send zero")
    assert res.extraction_success is False
    assert res.error_message is not None
