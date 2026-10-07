"""Unit tests for FG-401 ExtractionResult schema and validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from finguard.ai.provider import ExtractionResult


def test_extraction_result_valid_amount_str() -> None:
    res = ExtractionResult(amount="500.00", currency="INR", recipient_alias="alice")
    assert res.amount == "500.00"
    assert res.currency == "INR"
    assert res.recipient_alias == "alice"


def test_extraction_result_valid_amount_int() -> None:
    # Integer minor units or whole number
    res = ExtractionResult(amount=500, currency="INR", recipient_alias="alice")
    assert res.amount == "500.00"


def test_extraction_result_rejects_float_amount() -> None:
    with pytest.raises(ValidationError) as exc:
        ExtractionResult(amount=500.50, currency="INR", recipient_alias="alice")
    assert "float" in str(exc.value).lower()


def test_extraction_result_rejects_bool_amount() -> None:
    with pytest.raises(ValidationError) as exc:
        ExtractionResult(amount=True, currency="INR", recipient_alias="alice")
    assert "boolean" in str(exc.value).lower()


def test_extraction_result_strips_authority_fields() -> None:
    # Passing authority fields in model construction
    res = ExtractionResult.model_validate(
        {
            "amount": "100.00",
            "currency": "INR",
            "recipient_alias": "bob",
            "approved": True,
            "authorized": True,
            "signer": "root",
            "grant_capability": "admin",
        }
    )
    assert res.amount == "100.00"
    assert res.recipient_alias == "bob"
    assert "approved" in res.authority_fields_detected
    assert "authorized" in res.authority_fields_detected
    assert "signer" in res.authority_fields_detected
    assert "grant_capability" in res.authority_fields_detected


def test_extraction_result_rejects_prohibited_recipient_aliases() -> None:
    for prohibited in ["admin", "root", "unknown", "none", "null", "unresolved"]:
        with pytest.raises(ValidationError):
            ExtractionResult(amount="100.00", currency="INR", recipient_alias=prohibited)


def test_extraction_result_rejects_negative_or_zero_amount() -> None:
    with pytest.raises(ValidationError):
        ExtractionResult(amount="-50.00", currency="INR", recipient_alias="alice")

    with pytest.raises(ValidationError):
        ExtractionResult(amount="0.00", currency="INR", recipient_alias="alice")
