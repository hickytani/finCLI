"""M7 Attack Scenario Model.

Defines the typed data contracts for every red-team scenario.
Scenarios describe *behavior*, not merely a prompt string.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ── Attack Category ────────────────────────────────────────────────────────────


class AttackCategory(str, Enum):
    """Distinct security hypotheses — not cosmetic prompt variations."""

    # LLM / Model attacks
    PROMPT_INJECTION = "prompt_injection"
    SYSTEM_MESSAGE_SPOOFING = "system_message_spoofing"
    DEVELOPER_MESSAGE_SPOOFING = "developer_message_spoofing"
    STRUCTURED_OUTPUT_INJECTION = "structured_output_injection"
    UNKNOWN_FIELD_INJECTION = "unknown_field_injection"

    # Identity / authority attacks
    AUTHORITY_IMPERSONATION = "authority_impersonation"
    IDENTITY_SUBSTITUTION = "identity_substitution"
    APPROVAL_SPOOFING = "approval_spoofing"
    SIGNER_SPOOFING = "signer_spoofing"
    FAKE_HUMAN_APPROVAL = "fake_human_approval"
    FAKE_EMERGENCY_OVERRIDE = "fake_emergency_override"
    FAKE_POLICY = "fake_policy"
    FAKE_PREVIOUS_STATE = "fake_previous_state"

    # Capability attacks
    CAPABILITY_ESCALATION = "capability_escalation"
    POLICY_OVERRIDE = "policy_override"
    FINANCIAL_LIMIT_ESCALATION = "financial_limit_escalation"
    MAX_STEP_ESCALATION = "max_step_escalation"
    MAX_TOOL_CALL_ESCALATION = "max_tool_call_escalation"
    DEADLINE_EXTENSION = "deadline_extension"

    # Orchestration attacks
    INFINITE_REPLANNING = "infinite_replanning"
    RECURSIVE_REPLANNING = "recursive_replanning"
    M4_BYPASS = "m4_bypass"
    M3_1_BYPASS = "m3_1_bypass"
    M3_2_BYPASS = "m3_2_bypass"
    MCP_BOUNDARY_BYPASS = "mcp_boundary_bypass"
    DIRECT_PRIVILEGED_API_ACCESS = "direct_privileged_api_access"

    # Tool / observation attacks
    TOOL_OUTPUT_POISONING = "tool_output_poisoning"
    OBSERVATION_POISONING = "observation_poisoning"
    CONTEXT_POISONING = "context_poisoning"
    CONFLICTING_TOOL_RESULTS = "conflicting_tool_results"
    TOOL_IMPERSONATION = "tool_impersonation"
    MULTI_TOOL_ESCALATION = "multi_tool_escalation"

    # Financial manipulation
    MALICIOUS_RECIPIENT_SUBSTITUTION = "malicious_recipient_substitution"
    AMOUNT_MANIPULATION = "amount_manipulation"
    CURRENCY_MANIPULATION = "currency_manipulation"
    UNIT_CONFUSION = "unit_confusion"
    NUMERIC_OVERFLOW = "numeric_overflow"

    # Replay / duplicate attacks
    DUPLICATE_TRANSACTION = "duplicate_transaction"
    REPLAY = "replay"
    RETRY_ABUSE = "retry_abuse"
    CANCELLATION_BYPASS = "cancellation_bypass"
    TIMEOUT_BYPASS = "timeout_bypass"
    PROVIDER_FAILURE_EXPLOITATION = "provider_failure_exploitation"

    # Secret exfiltration
    SECRET_EXFILTRATION = "secret_exfiltration"
    PRIVATE_KEY_EXFILTRATION = "private_key_exfiltration"
    CREDENTIAL_EXFILTRATION = "credential_exfiltration"

    # Multi-turn / stateful
    MULTI_TURN_ESCALATION = "multi_turn_escalation"
    STATE_ROLLBACK_MANIPULATION = "state_rollback_manipulation"
    CROSS_RUN_STATE_CONFUSION = "cross_run_state_confusion"
    CORRELATION_ID_CONFUSION = "correlation_id_confusion"

    # Benign (regression)
    BENIGN = "benign"


# ── Attacker Mode ──────────────────────────────────────────────────────────────


class AttackMode(str, Enum):
    """Which components are treated as actively malicious."""

    MODEL_COMPROMISED = "model_compromised"
    TOOL_COMPROMISED = "tool_compromised"
    MCP_COMPROMISED = "mcp_compromised"
    MULTI_COMPONENT_COMPROMISED = "multi_component_compromised"
    BENIGN = "benign"


# ── Security Properties ────────────────────────────────────────────────────────


class SecurityProperty(str, Enum):
    """Properties that every adversarial scenario must verify from trusted state."""

    NO_AUTHORITY_ESCALATION = "NO_AUTHORITY_ESCALATION"
    NO_CAPABILITY_ESCALATION = "NO_CAPABILITY_ESCALATION"
    NO_POLICY_MUTATION = "NO_POLICY_MUTATION"
    NO_IDENTITY_MUTATION = "NO_IDENTITY_MUTATION"
    NO_SIGNER_MUTATION = "NO_SIGNER_MUTATION"
    NO_ORCHESTRATION_BOUND_ESCAPE = "NO_ORCHESTRATION_BOUND_ESCAPE"
    NO_APPROVAL_BYPASS = "NO_APPROVAL_BYPASS"
    NO_SIGNING_BYPASS = "NO_SIGNING_BYPASS"
    NO_EXECUTION_BYPASS = "NO_EXECUTION_BYPASS"
    NO_SECRET_EXPOSURE = "NO_SECRET_EXPOSURE"
    NO_PRIVATE_KEY_EXPOSURE = "NO_PRIVATE_KEY_EXPOSURE"
    NO_FINANCIAL_BYPASS = "NO_FINANCIAL_BYPASS"
    NO_DUPLICATE_FINANCIAL_EFFECT = "NO_DUPLICATE_FINANCIAL_EFFECT"
    NO_REPLAY_EFFECT = "NO_REPLAY_EFFECT"
    NO_CANCELLATION_BYPASS = "NO_CANCELLATION_BYPASS"
    NO_MCP_BYPASS = "NO_MCP_BYPASS"
    NO_M4_BYPASS = "NO_M4_BYPASS"
    NO_M3_1_BYPASS = "NO_M3_1_BYPASS"
    NO_M3_2_BYPASS = "NO_M3_2_BYPASS"


# ── Security Result ────────────────────────────────────────────────────────────


class SecurityResult(str, Enum):
    """Structured classification — not a simple PASS/FAIL."""

    # Containment results (expected, good)
    CONTAINED = "CONTAINED"
    MODEL_FAILURE = "MODEL_FAILURE"
    SCHEMA_REJECTED = "SCHEMA_REJECTED"
    MCP_REJECTED = "MCP_REJECTED"
    M4_REJECTED = "M4_REJECTED"
    M3_1_REJECTED = "M3_1_REJECTED"
    M3_2_REJECTED = "M3_2_REJECTED"
    DECISION_DENIED = "DECISION_DENIED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    CANCELLED = "CANCELLED"
    TIMEOUT = "TIMEOUT"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"

    # Violation results (unexpected, bad)
    SECURITY_VIOLATION = "SECURITY_VIOLATION"
    FINANCIAL_EFFECT_VIOLATION = "FINANCIAL_EFFECT_VIOLATION"
    SECRET_EXPOSURE = "SECRET_EXPOSURE"
    DUPLICATE_EFFECT = "DUPLICATE_EFFECT"

    # Benign
    BENIGN_SUCCESS = "BENIGN_SUCCESS"
    BENIGN_EXPECTED_REJECTION = "BENIGN_EXPECTED_REJECTION"
    BENIGN_APPROVAL_REQUIRED = "BENIGN_APPROVAL_REQUIRED"
    BENIGN_FAILURE = "BENIGN_FAILURE"

    @property
    def is_violation(self) -> bool:
        return self in {
            SecurityResult.SECURITY_VIOLATION,
            SecurityResult.FINANCIAL_EFFECT_VIOLATION,
            SecurityResult.SECRET_EXPOSURE,
            SecurityResult.DUPLICATE_EFFECT,
        }

    @property
    def is_contained(self) -> bool:
        return self in {
            SecurityResult.CONTAINED,
            SecurityResult.MODEL_FAILURE,
            SecurityResult.SCHEMA_REJECTED,
            SecurityResult.MCP_REJECTED,
            SecurityResult.M4_REJECTED,
            SecurityResult.M3_1_REJECTED,
            SecurityResult.M3_2_REJECTED,
            SecurityResult.DECISION_DENIED,
            SecurityResult.APPROVAL_REQUIRED,
            SecurityResult.CANCELLED,
            SecurityResult.TIMEOUT,
            SecurityResult.PROVIDER_FAILURE,
        }


# ── Attack Turn ────────────────────────────────────────────────────────────────


class AttackTurn(BaseModel):
    """A single turn in a multi-turn attack scenario."""

    model_config = ConfigDict(frozen=True)

    turn_number: int
    description: str
    # What the model/tool/MCP caller sends
    malicious_model_output: dict[str, Any] | str | None = None
    malicious_tool_output: dict[str, Any] | str | None = None
    malicious_mcp_args: dict[str, Any] | None = None
    # What input reaches this turn
    user_text: str | None = None
    # Expected containment at this turn (None = not the terminal turn)
    expected_containment: SecurityResult | None = None


# ── Core Scenario ──────────────────────────────────────────────────────────────


class AttackScenario(BaseModel):
    """Complete specification of a red-team attack scenario.

    Describes *behavior*, not merely a prompt string.
    """

    model_config = ConfigDict(frozen=True)

    # Identity
    scenario_id: str = Field(description="Unique ID, e.g. M7-CAP-001")
    name: str = Field(description="Human-readable scenario name")
    category: AttackCategory
    severity: str = Field(description="CRITICAL / HIGH / MEDIUM / LOW")
    description: str

    # Execution parameters
    initial_request: str = Field(description="Natural language request from the user")
    attack_mode: AttackMode = AttackMode.MODEL_COMPROMISED
    turn_count: int = Field(default=1, ge=1)
    max_steps: int = Field(default=5, ge=1)
    max_tool_calls: int = Field(default=3, ge=0)
    financial_limit_minor: int = Field(default=1_000_000, ge=0)

    # Attack specification
    attacker_behavior: str = Field(description="Prose description of attacker strategy")
    malicious_model_outputs: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Sequence of malicious JSON responses the model might produce",
    )
    malicious_tool_outputs: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Sequence of malicious tool observations",
    )
    attack_sequence: list[AttackTurn] = Field(default_factory=list)

    # Expected outcomes (checked against oracle, not agent self-report)
    expected_terminal_state: str = Field(
        description="CONTAINED / DENIED / APPROVAL_REQUIRED / CANCELLED / etc."
    )
    expected_security_properties: list[SecurityProperty] = Field(default_factory=list)
    expected_result: SecurityResult

    # Optional extras
    capabilities_required: list[str] = Field(default_factory=list)
    notes: str = ""
