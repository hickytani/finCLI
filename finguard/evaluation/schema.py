"""FG-401 Evaluation Case and Scorecard Schemas."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class EvaluationCase(BaseModel):
    """Schema for a typed evaluation test case."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(description="Unique case identifier, e.g. ADV-01")
    category: str = Field(description="Evaluation category, e.g. prompt_injection, benign")
    input_text: str = Field(description="Input natural language prompt or request")
    expected_extraction: dict[str, Any] | None = Field(
        default=None, description="Expected extracted dictionary for benign cases"
    )
    expected_decision: str = Field(
        default="BLOCK", description="Expected authoritative decision: ALLOW, BLOCK, REQUIRE_APPROVAL"
    )
    expected_security_outcome: str = Field(
        default="CONTAINED", description="Expected security status: CONTAINED, VALID, REJECTED_AT_EXTRACTION"
    )
    attack_metadata: dict[str, Any] = Field(default_factory=dict)
    secret_sentinels: tuple[str, ...] = Field(
        default=(),
        description="Exact synthetic secret values used for disclosure checks.",
    )
    severity: Literal["low", "medium", "high", "critical"] = "high"


class EvaluationResult(BaseModel):
    """Individual result for one evaluated case."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    category: str
    input_text: str
    actual_extraction: dict[str, Any] | None = None
    pipeline_success: bool = False
    evaluation_status: Literal["evaluated", "inconclusive"] = "inconclusive"
    raw_llm_output: str | None = None
    model_complied: bool = False
    model_attack_attempted: bool = False
    boundary_contained: bool = False
    authority_violation: bool = False
    financial_effect: bool = False
    extraction_valid: bool = False
    authority_fields_detected: list[str] = Field(default_factory=list)
    mcp_contained: bool = False
    m4_contained: bool = False
    m3_2_contained: bool = False
    final_decision: str = "DENIED"
    error_message: str | None = None


class EvaluationSummary(BaseModel):
    """Aggregated scorecard with Wilson 95% confidence intervals."""

    model_config = ConfigDict(extra="forbid")

    timestamp: str
    provider_name: str
    model_name: str
    provider_is_mock: bool
    total_cases: int
    benign_cases_count: int
    adversarial_cases_count: int
    evaluated_adversarial_cases_count: int
    inconclusive_cases_count: int

    # Extraction metrics
    valid_json_count: int
    valid_json_rate: float
    amount_accuracy: float
    amount_accuracy_correct: int
    amount_accuracy_total: int
    recipient_accuracy: float
    recipient_accuracy_correct: int
    recipient_accuracy_total: int
    currency_accuracy: float
    currency_accuracy_correct: int
    currency_accuracy_total: int

    # Security metrics
    authority_violation_count: int
    authority_escalation_rate: float
    approval_bypass_count: int
    signing_bypass_count: int
    execution_bypass_count: int
    capability_escalation_count: int
    policy_override_count: int
    secret_exfiltration_count: int
    secret_exfiltration_cases_count: int

    # Containment metrics
    contained_attacks_count: int
    containment_rate: float
    wilson_ci_containment_lower: float
    wilson_ci_containment_upper: float
    wilson_ci_violation_lower: float
    wilson_ci_violation_upper: float

    results: list[EvaluationResult] = Field(default_factory=list)
