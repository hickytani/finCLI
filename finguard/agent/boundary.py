"""One-shot, fail-closed boundary between untrusted agent output and FinGuard core."""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Annotated, ClassVar, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from finguard.ai.analyzer import LocalAIAnalyzer
from finguard.ai.schemas import TransactionExtraction
from finguard.audit.ledger import AuditLedger
from finguard.core.canonical import canonical_serialize
from finguard.core.enums import ActorType, Currency, DecisionType
from finguard.core.errors import SecurityError
from finguard.core.transaction import Transaction
from finguard.crypto.hashing import sha256_hash
from finguard.decision.engine import DecisionEngine, DecisionReceipt
from finguard.identity.registry import ActorConfig, IdentityRegistry
from finguard.money import MAX_AMOUNT_MINOR, Money
from finguard.storage.database import get_session
from finguard.storage.repositories import AuditRepository, ReceiptRepository, TransactionRepository

PROPOSE_TOOL_ID = "finguard.propose_transaction"
PROPOSE_CAPABILITY = "transaction.propose"
_INTENT_DOMAIN = b"finguard.agent.intent.v1\x00"


class AgentRunState(str, Enum):
    REQUESTED = "requested"
    PLANNING = "planning"
    GUARDRAIL_CHECK = "guardrail_check"
    TOOL_CALL = "tool_call"
    OBSERVATION = "observation"
    APPROVAL_REQUIRED = "approval_required"
    COMPLETED = "completed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    EXECUTION = "execution"


class AgentBoundaryError(SecurityError):
    """A fail-closed agent-boundary rejection with a client-safe code."""

    def __init__(self, code: str, message: str, *, outcome_unknown: bool = False):
        super().__init__(message)
        self.code = code
        self.outcome_unknown = outcome_unknown


class AgentRunStateMachine:
    """Single-pass agent state machine; execution is intentionally unreachable."""

    _TRANSITIONS: ClassVar[dict[AgentRunState, set[AgentRunState]]] = {
        AgentRunState.REQUESTED: {
            AgentRunState.PLANNING,
            AgentRunState.CANCELLED,
            AgentRunState.REJECTED,
        },
        AgentRunState.PLANNING: {
            AgentRunState.GUARDRAIL_CHECK,
            AgentRunState.CANCELLED,
            AgentRunState.TIMED_OUT,
            AgentRunState.REJECTED,
        },
        AgentRunState.GUARDRAIL_CHECK: {
            AgentRunState.TOOL_CALL,
            AgentRunState.CANCELLED,
            AgentRunState.REJECTED,
        },
        AgentRunState.TOOL_CALL: {
            AgentRunState.OBSERVATION,
            AgentRunState.TIMED_OUT,
            AgentRunState.REJECTED,
            AgentRunState.RECONCILIATION_REQUIRED,
            AgentRunState.CANCELLED,
        },
        AgentRunState.OBSERVATION: {
            AgentRunState.APPROVAL_REQUIRED,
            AgentRunState.COMPLETED,
            AgentRunState.REJECTED,
        },
    }

    def __init__(self) -> None:
        self.state = AgentRunState.REQUESTED
        self.history = [self.state]

    def transition(self, target: AgentRunState) -> None:
        if target not in self._TRANSITIONS.get(self.state, set()):
            raise AgentBoundaryError(
                "INVALID_AGENT_TRANSITION",
                f"Agent state transition {self.state.value} -> {target.value} is not permitted",
            )
        self.state = target
        self.history.append(target)


@dataclass(frozen=True)
class AgentExecutionLimits:
    """Hard limits for one agent turn; this implementation permits one proposal."""

    max_iterations: int = 1
    max_tool_calls: int = 1
    max_elapsed_seconds: float = 15.0
    tool_timeout_seconds: float = 5.0
    max_request_chars: int = 4000
    max_intent_bytes: int = 8192
    max_tool_response_bytes: int = 8192
    max_financial_value_minor: int | None = None

    def __post_init__(self) -> None:
        if self.max_iterations != 1 or self.max_tool_calls != 1:
            raise ValueError("This agent boundary supports exactly one iteration and one tool call")
        if self.max_elapsed_seconds <= 0 or self.tool_timeout_seconds <= 0:
            raise ValueError("Agent time budgets must be positive")
        if self.max_request_chars <= 0 or self.max_intent_bytes <= 0:
            raise ValueError("Agent input budgets must be positive")
        if self.max_tool_response_bytes <= 0:
            raise ValueError("Tool response budget must be positive")
        if (
            self.max_financial_value_minor is not None
            and (
                isinstance(self.max_financial_value_minor, bool)
                or not isinstance(self.max_financial_value_minor, int)
                or not 0 < self.max_financial_value_minor <= MAX_AMOUNT_MINOR
            )
        ):
            raise ValueError("Agent financial-value budget is invalid")


class AgentRequest(BaseModel):
    """Untrusted text and request identifiers; authority and time are server-bound."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    correlation_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    request_text: str = Field(min_length=1, max_length=65_536)

    @field_validator("request_text")
    @classmethod
    def request_text_is_valid_utf8(cls, value: str) -> str:
        value.encode("utf-8", errors="strict")
        return value


class StructuredIntent(BaseModel):
    """Validated proposal intent; caller/model-controlled fields contain no authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = Field(default=1, ge=1, le=1)
    intent_id: uuid.UUID
    correlation_id: uuid.UUID
    requested_at: datetime.datetime
    actor_id: str = Field(min_length=1, max_length=128)
    session_id: str = Field(min_length=1, max_length=128)
    action: str = Field(default=PROPOSE_TOOL_ID, pattern=f"^{PROPOSE_TOOL_ID}$")
    capability: str = Field(default=PROPOSE_CAPABILITY, pattern=f"^{PROPOSE_CAPABILITY}$")
    transaction_id: str = Field(min_length=1, max_length=64)
    nonce: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=1, max_length=128)
    from_account: str = Field(min_length=1, max_length=128)
    to_account: str = Field(min_length=1, max_length=128)
    currency: Currency
    amount: str = Field(min_length=1, max_length=64)
    purpose: str = Field(min_length=1, max_length=256)
    request_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("requested_at")
    @classmethod
    def intent_timestamp_is_aware_utc(cls, value: datetime.datetime) -> datetime.datetime:
        if value.tzinfo is None:
            raise ValueError("Intent timestamps must be timezone-aware")
        return value.astimezone(datetime.UTC)

    @field_validator("actor_id", "session_id", "transaction_id", "nonce", "idempotency_key")
    @classmethod
    def identifiers_are_canonical(cls, value: str) -> str:
        return Transaction.validate_signed_identifier(value)

    @field_validator("amount")
    @classmethod
    def amount_is_exact(cls, value: str, info) -> str:
        currency = info.data.get("currency")
        if currency is not None:
            return Money.from_decimal(value, currency).to_decimal_string()
        return value

    @field_validator("from_account", "to_account")
    @classmethod
    def accounts_are_signed_identifiers(cls, value: str) -> str:
        normalized = Transaction.validate_signed_identifier(value.strip())
        if normalized == "*":
            raise ValueError("Wildcard is not an account identifier")
        return normalized

    @field_validator("purpose")
    @classmethod
    def purpose_is_bounded_data(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Intent purpose must not be empty")
        return normalized


class AgentToolCall(BaseModel):
    """Strict call envelope consumed by the only registered agent tool."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str = Field(pattern=f"^{PROPOSE_TOOL_ID}$")
    capability: str = Field(pattern=f"^{PROPOSE_CAPABILITY}$")
    actor_id: str = Field(min_length=1, max_length=128)
    correlation_id: uuid.UUID
    intent: StructuredIntent


class _CoreToolResult(BaseModel):
    """Allowlisted result data; no instruction or executable field is accepted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    transaction_id: str = Field(min_length=1, max_length=64)
    receipt_id: str = Field(min_length=1, max_length=64)
    transaction_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: str = Field(pattern=r"^(allow|block|require_approval)$")
    reasons: list[Annotated[str, Field(max_length=512)]] = Field(max_length=20)


class AgentToolObservation(BaseModel):
    """Sanitized, provenance-bearing tool data; never interpreted as instructions."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str
    capability: str
    correlation_id: uuid.UUID
    intent_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    transaction_id: str
    receipt_id: str
    transaction_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    decision: str = Field(pattern=r"^(allow|block|require_approval)$")
    reasons: list[Annotated[str, Field(max_length=512)]] = Field(max_length=20)
    source: str
    trust_level: str = Field(default="data_only", pattern="^data_only$")
    observed_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC)
    )


class AgentRunResult(BaseModel):
    """Bounded execution result with no signer, approval, or executor capability."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    state: AgentRunState
    request_id: uuid.UUID
    correlation_id: uuid.UUID
    iteration_count: int = 0
    tool_call_count: int = 0
    intent: StructuredIntent | None = None
    observation: AgentToolObservation | None = None
    transaction_id: str | None = None
    receipt_id: str | None = None
    decision: str | None = None
    error_code: str | None = None
    transitions: list[AgentRunState]


class AgentToolTransport(Protocol):
    """Narrow future-MCP adapter contract: proposal only, returning untrusted data."""

    async def propose_transaction(self, call: AgentToolCall) -> object:
        """Send one validated proposal to the configured tool endpoint."""


class LocalDecisionToolTransport:
    """In-process adapter to the existing DecisionEngine; no other tool is exposed."""

    def __init__(self, principal: ActorConfig, source_account: str):
        self._principal = principal
        self._source_account = source_account

    async def propose_transaction(self, call: AgentToolCall) -> object:
        return await asyncio.to_thread(self._decide, call)

    def _decide(self, call: AgentToolCall) -> dict:
        intent = call.intent
        transaction = _transaction_from_intent(
            intent,
            self._principal,
            self._source_account,
            call.tool_id,
            call.capability,
        )
        result = DecisionEngine().decide(
            transaction,
            ai_assessment={"status": "ADVISORY", "source": "validated-agent-extraction"},
        )
        return {
            "transaction_id": result.transaction.transaction_id,
            "receipt_id": result.receipt.receipt_id,
            "transaction_hash": result.receipt.transaction_hash,
            "decision": result.decision.value,
            "reasons": result.receipt.reasons,
        }


class AgentToolGateway:
    """Authorize one declared capability, bound its execution, and verify core evidence."""

    def __init__(
        self,
        principal: ActorConfig,
        source_account: str,
        correlation_id: uuid.UUID,
        limits: AgentExecutionLimits,
        transport: AgentToolTransport,
        started_at: float,
    ):
        self._principal = principal
        self._source_account = source_account
        self._correlation_id = correlation_id
        self._limits = limits
        self._transport = transport
        self._started_at = started_at
        self.tool_call_count = 0

    async def invoke(self, raw_call: object) -> AgentToolObservation:
        try:
            call = AgentToolCall.model_validate(raw_call)
        except ValidationError as exc:
            self._audit("AGENT_TOOL_DENIED", "INVALID_TOOL_CALL")
            raise AgentBoundaryError("INVALID_TOOL_CALL", "Tool call schema is invalid") from exc

        if (
            call.tool_id != PROPOSE_TOOL_ID
            or call.capability != PROPOSE_CAPABILITY
            or call.actor_id != self._principal.actor_id
            or call.intent.actor_id != self._principal.actor_id
            or call.intent.from_account != self._source_account
            or call.correlation_id != self._correlation_id
            or call.intent.correlation_id != self._correlation_id
        ):
            self._audit("AGENT_TOOL_DENIED", "CAPABILITY_OR_IDENTITY_MISMATCH")
            raise AgentBoundaryError(
                "UNAUTHORIZED_TOOL",
                "Agent is not authorized for the requested tool or identity",
            )
        if self.tool_call_count >= self._limits.max_tool_calls:
            self._audit("AGENT_TOOL_DENIED", "TOOL_BUDGET_EXCEEDED")
            raise AgentBoundaryError("TOOL_BUDGET_EXCEEDED", "Agent tool-call budget is exhausted")

        self.tool_call_count += 1
        remaining = self._limits.max_elapsed_seconds - (
            asyncio.get_running_loop().time() - self._started_at
        )
        timeout = min(self._limits.tool_timeout_seconds, remaining)
        if timeout <= 0:
            self._audit("AGENT_TOOL_TIMEOUT", "RUN_BUDGET_EXCEEDED")
            raise AgentBoundaryError(
                "TOOL_TIMEOUT",
                "Tool call exceeded the agent time budget; reconcile by transaction ID",
                outcome_unknown=True,
            )

        try:
            # A timeout can leave a proposal completing in the worker. Stable request IDs make
            # exact retries idempotent; this proposal-only tool cannot sign or settle money.
            raw_result = await asyncio.wait_for(
                self._transport.propose_transaction(call),
                timeout=timeout,
            )
        except TimeoutError as exc:
            self._audit("AGENT_TOOL_TIMEOUT", "TOOL_TIMEOUT")
            raise AgentBoundaryError(
                "TOOL_TIMEOUT",
                "Tool call timed out; reconcile by transaction ID before retrying",
                outcome_unknown=True,
            ) from exc
        except ValueError as exc:
            if "idempotency key" in str(exc).lower():
                self._audit("AGENT_TOOL_REJECTED", "IDEMPOTENCY_CONFLICT")
                raise AgentBoundaryError(
                    "IDEMPOTENCY_CONFLICT",
                    "Request ID was reused with different transaction content",
                ) from exc
            self._audit("AGENT_TOOL_FAILURE", "CORE_PROPOSAL_REJECTED")
            raise AgentBoundaryError(
                "TOOL_CALL_FAILED",
                "Proposal call failed closed",
                outcome_unknown=True,
            ) from exc
        except (OSError, RuntimeError) as exc:
            self._audit("AGENT_TOOL_FAILURE", "TRANSPORT_FAILURE")
            raise AgentBoundaryError(
                "TOOL_TRANSPORT_FAILURE",
                "Tool transport failed; reconcile by transaction ID",
                outcome_unknown=True,
            ) from exc

        try:
            if type(raw_result) is not dict:
                raise TypeError("Tool response must be a JSON object")
            result = _CoreToolResult.model_validate(raw_result, strict=True)
            encoded_result = json.dumps(
                result.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (RecursionError, TypeError, UnicodeError, ValueError, ValidationError) as exc:
            self._audit("AGENT_TOOL_REJECTED", "INVALID_TOOL_RESULT")
            raise AgentBoundaryError(
                "UNTRUSTED_TOOL_RESULT",
                "Tool response is not valid bounded JSON data",
                outcome_unknown=True,
            ) from exc
        if len(encoded_result) > self._limits.max_tool_response_bytes:
            self._audit("AGENT_TOOL_REJECTED", "TOOL_RESULT_TOO_LARGE")
            raise AgentBoundaryError(
                "UNTRUSTED_TOOL_RESULT",
                "Tool response exceeds the configured size limit",
                outcome_unknown=True,
            )

        try:
            receipt = self._load_verified_local_decision(call, result)
        except AgentBoundaryError:
            self._audit("AGENT_TOOL_REJECTED", "CORE_EVIDENCE_MISMATCH")
            raise

        return AgentToolObservation(
            tool_id=call.tool_id,
            capability=call.capability,
            correlation_id=call.correlation_id,
            intent_digest=sha256_hash(
                _INTENT_DOMAIN
                + canonical_serialize(call.intent.model_dump(mode="json"))
            ),
            transaction_id=receipt.transaction_id,
            receipt_id=receipt.receipt_id,
            transaction_hash=receipt.transaction_hash,
            decision=receipt.final_decision,
            reasons=receipt.reasons,
            source="finguard.local-core",
        )

    def _load_verified_local_decision(
        self,
        call: AgentToolCall,
        result: _CoreToolResult,
    ) -> DecisionReceipt:
        intent = call.intent
        expected_transaction = _transaction_from_intent(
            intent,
            self._principal,
            self._source_account,
            call.tool_id,
            call.capability,
        )
        session = get_session()
        try:
            record = TransactionRepository(session).get(intent.transaction_id)
            receipt_record = ReceiptRepository(session).get_by_transaction(
                intent.transaction_id
            )
            if record is None or receipt_record is None:
                raise AgentBoundaryError(
                    "CORE_EVIDENCE_MISSING",
                    "No local decision evidence exists for the tool result",
                    outcome_unknown=True,
                )
            receipt = DecisionReceipt.model_validate_json(receipt_record.reason)
            if record.amount_minor is None or record.canonical_version != 2:
                raise AgentBoundaryError(
                    "CORE_EVIDENCE_MISMATCH",
                    "Stored transaction is not a complete canonical v2 record",
                    outcome_unknown=True,
                )
            stored_transaction = Transaction(
                transaction_id=record.transaction_id,
                actor_id=record.actor_id,
                session_id=record.session_id,
                from_account=record.from_account,
                to_account=record.to_account,
                amount=Money(record.amount_minor, record.currency),
                currency=Currency(record.currency),
                canonical_version=record.canonical_version,
                nonce=record.nonce,
                timestamp=record.timestamp,
                metadata=json.loads(record.metadata_json or "{}"),
                idempotency_key=record.idempotency_key,
                policy_version=record.policy_version,
                initiating_actor_type=ActorType.AGENT.value,
            )
            if (
                record.actor_id != self._principal.actor_id
                or stored_transaction.transaction_hash()
                != expected_transaction.transaction_hash()
                or record.canonical_hash != expected_transaction.transaction_hash()
                or receipt.transaction_id != intent.transaction_id
                or receipt.actor_type != ActorType.AGENT.value
                or receipt.transaction_hash != record.canonical_hash
                or receipt_record.transaction_hash != record.canonical_hash
                or receipt_record.receipt_hash != receipt.receipt_hash()
                or receipt_record.transaction_version != receipt.transaction_version
                or result.transaction_id != intent.transaction_id
                or result.receipt_id != receipt.receipt_id
                or result.transaction_hash != receipt.transaction_hash
                or result.decision != receipt.final_decision
                or result.reasons != receipt.reasons
            ):
                raise AgentBoundaryError(
                    "CORE_EVIDENCE_MISMATCH",
                    "Tool response does not match the local decision evidence",
                    outcome_unknown=True,
                )
            valid, _, reason = AuditLedger(session=session).verify_integrity()
            if not valid:
                raise AgentBoundaryError(
                    "AUDIT_INTEGRITY_FAILURE",
                    f"Local audit evidence failed integrity verification: {reason}",
                    outcome_unknown=True,
                )
            decision_entries = [
                entry
                for entry in AuditRepository(session).get_by_transaction(
                    intent.transaction_id
                )
                if entry.action == "DECISION"
            ]
            if len(decision_entries) != 1:
                raise AgentBoundaryError(
                    "CORE_EVIDENCE_MISMATCH",
                    "Expected exactly one decision audit entry",
                    outcome_unknown=True,
                )
            decision_evidence = json.loads(decision_entries[0].metadata_json or "{}")
            if (
                decision_evidence.get("receipt_id") != receipt.receipt_id
                or decision_evidence.get("receipt_hash") != receipt.receipt_hash()
                or decision_evidence.get("transaction_hash") != receipt.transaction_hash
            ):
                raise AgentBoundaryError(
                    "CORE_EVIDENCE_MISMATCH",
                    "Decision receipt is not bound to its audit entry",
                    outcome_unknown=True,
                )
            return receipt
        except (TypeError, ValueError, ValidationError) as exc:
            raise AgentBoundaryError(
                "CORE_EVIDENCE_INVALID",
                "Local decision evidence could not be validated",
                outcome_unknown=True,
            ) from exc
        finally:
            session.close()

    def _audit(self, action: str, reason_code: str) -> None:
        AuditLedger().append(
            action=action,
            actor_id=self._principal.actor_id,
            result="BLOCKED",
            metadata={
                "correlation_id": str(self._correlation_id),
                "reason_code": reason_code,
                "tool_id": PROPOSE_TOOL_ID,
            },
        )

    def record_cancellation(self) -> None:
        self._audit("AGENT_TOOL_CANCELLED", "CANCELLED_DURING_TOOL_CALL")


class AgentSecurityBoundary:
    """Bind model extraction to one configured AGENT identity and a single core proposal."""

    def __init__(
        self,
        *,
        actor_id: str,
        source_account: str,
        session_id: str | None = None,
        analyzer: object | None = None,
        limits: AgentExecutionLimits | None = None,
        tool_transport: AgentToolTransport | None = None,
        registry: IdentityRegistry | None = None,
        clock: Callable[[], datetime.datetime] | None = None,
    ):
        self._registry = registry or IdentityRegistry()
        principal = self._registry.get_actor(actor_id)
        if principal is None or principal.actor_type != ActorType.AGENT:
            raise SecurityError("Agent boundary requires an active registered AGENT identity")
        if (
            not isinstance(source_account, str)
            or not source_account
            or source_account == "*"
            or source_account not in principal.allowed_source_accounts
            or "*" in principal.allowed_source_accounts
        ):
            raise SecurityError("Agent source account must be an explicit registered grant")
        try:
            if (
                source_account.strip() != source_account
                or Transaction.validate_signed_identifier(source_account) != source_account
            ):
                raise SecurityError("Agent source account is not a canonical signed identifier")
        except ValueError as exc:
            raise SecurityError("Agent source account is not a canonical signed identifier") from exc
        self._principal = principal
        self._source_account = source_account
        self._session_id = session_id or f"{principal.actor_id}-agent-runtime"
        self._analyzer = analyzer or LocalAIAnalyzer()
        self._limits = limits or AgentExecutionLimits()
        self._tool_transport = tool_transport
        self._clock = clock or (lambda: datetime.datetime.now(datetime.UTC))
        configured_cap = self._limits.max_financial_value_minor
        self._financial_limit_minor = (
            configured_cap if configured_cap is not None else MAX_AMOUNT_MINOR
        )

    async def run(
        self,
        request: AgentRequest,
        *,
        cancellation: asyncio.Event | None = None,
    ) -> AgentRunResult:
        machine = AgentRunStateMachine()
        loop = asyncio.get_running_loop()
        started_at = loop.time()
        deadline = started_at + self._limits.max_elapsed_seconds
        observation: AgentToolObservation | None = None
        intent: StructuredIntent | None = None
        transaction_id: str | None = None
        receipt_id: str | None = None
        decision: str | None = None
        error_code: str | None = None
        iteration_count = 0
        tool_call_count = 0

        def result() -> AgentRunResult:
            return AgentRunResult(
                state=machine.state,
                request_id=request.request_id,
                correlation_id=request.correlation_id,
                iteration_count=iteration_count,
                tool_call_count=tool_call_count,
                intent=intent,
                observation=observation,
                transaction_id=transaction_id,
                receipt_id=receipt_id,
                decision=decision,
                error_code=error_code,
                transitions=machine.history,
            )

        if cancellation and cancellation.is_set():
            machine.transition(AgentRunState.CANCELLED)
            return result()
        if len(request.request_text) > self._limits.max_request_chars:
            self._record_guardrail_rejection(request, "REQUEST_TOO_LARGE")
            machine.transition(AgentRunState.REJECTED)
            error_code = "REQUEST_TOO_LARGE"
            return result()

        machine.transition(AgentRunState.PLANNING)
        iteration_count = 1
        remaining = deadline - loop.time()
        if remaining <= 0:
            machine.transition(AgentRunState.TIMED_OUT)
            error_code = "RUN_TIMEOUT"
            return result()
        try:
            raw_extraction = await asyncio.wait_for(
                asyncio.to_thread(self._analyzer.extract, request.request_text),
                timeout=remaining,
            )
            extraction = TransactionExtraction.model_validate(raw_extraction)
        except TimeoutError:
            machine.transition(AgentRunState.TIMED_OUT)
            error_code = "EXTRACTION_TIMEOUT"
            self._record_guardrail_rejection(request, error_code)
            return result()
        except (ValidationError, TypeError, ValueError):
            machine.transition(AgentRunState.REJECTED)
            error_code = "INVALID_INTENT"
            self._record_guardrail_rejection(request, error_code)
            return result()
        except RuntimeError:
            machine.transition(AgentRunState.REJECTED)
            error_code = "EXTRACTION_UNAVAILABLE"
            self._record_guardrail_rejection(request, error_code)
            return result()

        if cancellation and cancellation.is_set():
            machine.transition(AgentRunState.CANCELLED)
            return result()
        machine.transition(AgentRunState.GUARDRAIL_CHECK)
        try:
            intent = self._create_intent(request, extraction)
            intent_size = len(
                canonical_serialize(intent.model_dump(mode="json"))
            )
            if intent_size > self._limits.max_intent_bytes:
                raise AgentBoundaryError(
                    "INTENT_TOO_LARGE",
                    "Structured intent exceeds the configured size limit",
                )
            amount = Money.from_decimal(extraction.amount, extraction.currency)
            if (
                extraction.currency == self._principal.authority_currency
                and amount.minor_units > self._financial_limit_minor
            ):
                raise AgentBoundaryError(
                    "AGENT_VALUE_LIMIT",
                    "Request exceeds the configured agent financial-value budget",
                )
        except (AgentBoundaryError, TypeError, ValueError, ValidationError) as exc:
            machine.transition(AgentRunState.REJECTED)
            error_code = (
                exc.code if isinstance(exc, AgentBoundaryError) else "INVALID_INTENT"
            )
            self._record_guardrail_rejection(request, error_code)
            return result()

        if cancellation and cancellation.is_set():
            machine.transition(AgentRunState.CANCELLED)
            return result()
        machine.transition(AgentRunState.TOOL_CALL)
        call = AgentToolCall(
            tool_id=PROPOSE_TOOL_ID,
            capability=PROPOSE_CAPABILITY,
            actor_id=self._principal.actor_id,
            correlation_id=request.correlation_id,
            intent=intent,
        )
        gateway = AgentToolGateway(
            principal=self._principal,
            source_account=self._source_account,
            correlation_id=request.correlation_id,
            limits=self._limits,
            transport=self._tool_transport
            or LocalDecisionToolTransport(self._principal, self._source_account),
            started_at=started_at,
        )
        cancel_wait: asyncio.Task[bool] | None = None
        try:
            invocation = asyncio.create_task(
                gateway.invoke(call.model_dump(mode="python"))
            )
            if cancellation is None:
                observation = await invocation
            else:
                cancel_wait = asyncio.create_task(cancellation.wait())
                done, _ = await asyncio.wait(
                    (invocation, cancel_wait),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if cancel_wait in done and cancellation.is_set() and not invocation.done():
                    invocation.cancel()
                    await asyncio.gather(invocation, return_exceptions=True)
                    gateway.record_cancellation()
                    tool_call_count = gateway.tool_call_count
                    if tool_call_count:
                        transaction_id = intent.transaction_id
                        machine.transition(AgentRunState.RECONCILIATION_REQUIRED)
                        error_code = "TOOL_CANCELLED"
                    else:
                        machine.transition(AgentRunState.CANCELLED)
                    return result()
                observation = await invocation
                cancel_wait.cancel()
                await asyncio.gather(cancel_wait, return_exceptions=True)
            tool_call_count = gateway.tool_call_count
        except AgentBoundaryError as exc:
            tool_call_count = gateway.tool_call_count
            error_code = exc.code
            transaction_id = intent.transaction_id if exc.outcome_unknown else None
            target_state = (
                AgentRunState.RECONCILIATION_REQUIRED
                if exc.outcome_unknown
                else AgentRunState.REJECTED
            )
            machine.transition(target_state)
            return result()
        except (ValidationError, TypeError, ValueError):
            tool_call_count = gateway.tool_call_count
            error_code = "TOOL_CALL_REJECTED"
            transaction_id = intent.transaction_id
            machine.transition(AgentRunState.RECONCILIATION_REQUIRED)
            return result()
        finally:
            if cancel_wait is not None and not cancel_wait.done():
                cancel_wait.cancel()
                await asyncio.gather(cancel_wait, return_exceptions=True)

        transaction_id = observation.transaction_id
        receipt_id = observation.receipt_id
        decision = observation.decision
        machine.transition(AgentRunState.OBSERVATION)
        if decision == DecisionType.BLOCK.value:
            machine.transition(AgentRunState.REJECTED)
        elif decision == DecisionType.REQUIRE_APPROVAL.value:
            machine.transition(AgentRunState.APPROVAL_REQUIRED)
        else:
            self._record_guardrail_rejection(request, "AGENT_APPROVAL_FLOOR_MISSING")
            error_code = "AGENT_APPROVAL_FLOOR_MISSING"
            machine.transition(AgentRunState.REJECTED)
        return result()

    def _create_intent(
        self,
        request: AgentRequest,
        extraction: TransactionExtraction,
    ) -> StructuredIntent:
        request_digest = hashlib.sha256(request.request_text.encode("utf-8")).hexdigest()
        seed = hashlib.sha256(
            b"finguard.agent.request.v1\x00"
            + self._principal.actor_id.encode("utf-8")
            + b"\x00"
            + str(request.request_id).encode("ascii")
        ).hexdigest()
        return StructuredIntent(
            intent_id=request.request_id,
            correlation_id=request.correlation_id,
            requested_at=self._request_timestamp(
                request.request_id,
                request_digest,
                f"AG-{seed[:24].upper()}",
            ),
            actor_id=self._principal.actor_id,
            session_id=self._session_id,
            transaction_id=f"AG-{seed[:24].upper()}",
            nonce=seed[:32],
            idempotency_key=f"agent-{seed[:48]}",
            from_account=self._source_account,
            to_account=extraction.destination,
            amount=extraction.amount,
            currency=Currency(extraction.currency),
            purpose=extraction.purpose,
            request_digest=request_digest,
        )

    def _request_timestamp(
        self,
        request_id: uuid.UUID,
        request_digest: str,
        transaction_id: str,
    ) -> datetime.datetime:
        session = get_session()
        try:
            record = TransactionRepository(session).get(transaction_id)
            if record is not None and record.actor_id == self._principal.actor_id:
                metadata = json.loads(record.metadata_json or "{}")
                if not isinstance(metadata, dict):
                    raise ValueError("Stored agent transaction metadata is not an object")
                provenance = metadata.get("agent_provenance", {})
                if not isinstance(provenance, dict):
                    raise ValueError("Stored agent provenance is not an object")
                if (
                    provenance.get("request_id") == str(request_id)
                    and provenance.get("request_digest") == request_digest
                ):
                    timestamp = record.timestamp
                    if timestamp.tzinfo is None:
                        timestamp = timestamp.replace(tzinfo=datetime.UTC)
                    return timestamp.astimezone(datetime.UTC)
        finally:
            session.close()

        timestamp = self._clock()
        if timestamp.tzinfo is None:
            raise ValueError("Agent clock must return a timezone-aware timestamp")
        return timestamp.astimezone(datetime.UTC)

    def _record_guardrail_rejection(self, request: AgentRequest, reason_code: str) -> None:
        AuditLedger().append(
            action="AGENT_GUARDRAIL_REJECT",
            actor_id=self._principal.actor_id,
            result="BLOCKED",
            metadata={
                "request_id": str(request.request_id),
                "correlation_id": str(request.correlation_id),
                "reason_code": reason_code,
                "request_digest": hashlib.sha256(
                    request.request_text.encode("utf-8")
                ).hexdigest(),
            },
        )


def _transaction_from_intent(
    intent: StructuredIntent,
    principal: ActorConfig,
    source_account: str,
    tool_id: str,
    capability: str,
) -> Transaction:
    return Transaction(
        transaction_id=intent.transaction_id,
        actor_id=principal.actor_id,
        session_id=intent.session_id,
        from_account=source_account,
        to_account=intent.to_account,
        amount=intent.amount,
        currency=intent.currency,
        nonce=intent.nonce,
        timestamp=intent.requested_at,
        metadata={
            "purpose": intent.purpose,
            "agent_provenance": {
                "request_id": str(intent.intent_id),
                "correlation_id": str(intent.correlation_id),
                "tool_id": tool_id,
                "capability": capability,
                "request_digest": intent.request_digest,
            },
        },
        idempotency_key=intent.idempotency_key,
        initiating_actor_type=ActorType.AGENT.value,
    )
