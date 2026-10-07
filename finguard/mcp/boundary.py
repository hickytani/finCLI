"""MCP Security Boundary — the enforcement layer between MCP callers and the core.

Trust model
-----------
Input  (MCP request):  UNTRUSTED — validated, sanitized, rate-limited before touching core
Output (MCP response): data only — provenance metadata, NOT authority
Core (DecisionEngine): AUTHORITATIVE — the boundary routes to it but cannot bypass it

What this boundary CANNOT do
------------------------------
- Sign a transaction          (imports signing is PROHIBITED)
- Approve a transaction       (imports approvals is PROHIBITED)
- Bypass M3.2 guardrails      (enforced by StructuredIntentBoundary)
- Bypass M4 orchestration     (BoundedOrchestrator limits are set by config, not caller)
- Grant capabilities          (capabilities come from the signed IdentityRegistry)
- Expose private keys         (crypto.keystore is PROHIBITED import)
- Execute financial transfers (simulator/service is PROHIBITED import)

Permitted imports from trusted core
-------------------------------------
- finguard.agent.intent.StructuredIntentBoundary   (proposals enter here)
- finguard.agent.orchestrator.BoundedOrchestrator  (M4 bounds, immutable from MCP)
- finguard.audit.ledger.AuditLedger                (read-only proof queries)
- finguard.storage.*                               (read-only queries via repositories)
- finguard.decision.DecisionType                   (read-only enum)
- finguard.core.enums                              (read-only enums)
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from finguard.agent.intent import IntentValidationError, StructuredIntentBoundary
from finguard.agent.orchestrator import (
    BoundedOrchestrator,
    OrchestrationBudgetExceeded,
    OrchestrationRun,
)
from finguard.audit.ledger import AuditLedger
from finguard.core.enums import DecisionType
from finguard.core.errors import SecurityError
from finguard.mcp.errors import (
    MCPBoundaryError,
    MCPForbiddenToolError,
    MCPInputError,
    MCPNotFoundError,
    MCPRateLimitError,
)
from finguard.mcp.models import (
    AuditProofResponse,
    DecisionResponse,
    GetAuditProofRequest,
    GetDecisionRequest,
    ListTransactionsRequest,
    ListTransactionsResponse,
    ProposeTransactionRequest,
    ProposeTransactionResponse,
    TransactionSummary,
)
from finguard.storage.database import get_session
from finguard.storage.models import AuditEntryRecord, DecisionReceiptRecord, TransactionRecord

logger = logging.getLogger(__name__)

# ─── Rate-limiting constants ───────────────────────────────────────────────
_SESSION_REQUEST_LIMIT = 100  # requests per session lifetime
_MAX_REQUEST_BYTES = 32_768   # 32 KiB

# ─── Prohibited MCP tool names (structural enforcement) ───────────────────
_PROHIBITED_TOOLS: frozenset[str] = frozenset(
    {
        "approve_transaction",
        "sign_transaction",
        "execute_transaction",
        "grant_capability",
        "set_policy",
        "set_signer",
        "modify_authorization",
        "create_key",
        "delete_key",
        "export_key",
        "get_private_key",
    }
)

# ─── Authority-shaped fields that must never appear in any MCP input ───────
_AUTHORITY_FIELDS: frozenset[str] = frozenset(
    {
        "approved",
        "authorized",
        "authorization",
        "signer",
        "signature",
        "execute",
        "execution",
        "execution_state",
        "policy_override",
        "grant_capability",
        "admin",
        "root",
        "signing_key",
        "approve",
        "sign",
        "private_key",
        "secret",
        "credential",
    }
)


def _reject_authority_shaped_input(data: dict[str, Any]) -> None:
    """Fail loudly if any authority-shaped key appears in raw MCP input."""
    for key in data:
        normalized = key.strip().lower().replace("-", "_").replace(" ", "_")
        if normalized in _AUTHORITY_FIELDS:
            raise MCPInputError(
                f"Authority-shaped field '{key}' is not permitted in MCP requests.",
                code="MCP_AUTHORITY_FIELD_REJECTED",
            )


class MCPSession:
    """Minimal per-session state: rate-limiting only.

    Session identity is bound by server configuration — never by tool arguments.
    The MCP caller cannot define its own session limits or capabilities.
    """

    def __init__(self, session_id: str) -> None:
        if not session_id or not session_id.strip():
            raise ValueError("MCP session_id must not be blank")
        self.session_id = session_id.strip()
        self._request_count = 0

    def check_rate_limit(self, correlation_id: str | None = None) -> None:
        self._request_count += 1
        if self._request_count > _SESSION_REQUEST_LIMIT:
            logger.warning(
                "MCP rate limit exceeded session_id=%s count=%d",
                self.session_id,
                self._request_count,
            )
            raise MCPRateLimitError(correlation_id=correlation_id)

    @property
    def request_count(self) -> int:
        return self._request_count


class MCPSecurityBoundary:
    """The M5 MCP security enforcement boundary.

    Binds an MCP actor to a trusted actor identity and delegates proposals
    through the existing M4 → M3.1 → M3.2 → DecisionEngine chain.

    Security invariants enforced here:
        MCP_INPUT_IS_UNTRUSTED        — every input validated before touching core
        MCP_CANNOT_BYPASS_M3_2        — proposals flow through StructuredIntentBoundary
        MCP_CANNOT_BYPASS_M4          — BoundedOrchestrator bounds set by config
        MCP_CANNOT_SELF_GRANT_CAPABILITY — capabilities come from IdentityRegistry
        MCP_CANNOT_AUTHORIZE          — decision is read, never granted here
        MCP_CANNOT_SIGN               — signing imports are absent from this package
        MCP_CANNOT_EXECUTE            — simulator imports are absent from this package
        MCP_CANNOT_CHANGE_POLICY      — policy imports are absent from this package
        MCP_CANNOT_EXPOSE_SECRETS     — errors are safe; keystore is never imported
        MCP_CANNOT_EXTEND_ORCHESTRATION_BOUNDS — caller cannot set max_steps/etc.
        MCP_OUTPUT_IS_UNTRUSTED       — tool outputs return to deterministic checks
    """

    def __init__(
        self,
        *,
        actor_id: str,
        session: MCPSession,
        orchestrator_config: dict[str, Any] | None = None,
    ) -> None:
        if not actor_id or not actor_id.strip():
            raise SecurityError("MCP actor_id must not be blank")
        self._actor_id = actor_id.strip()
        self._session = session
        # Orchestrator limits are set by server configuration — MCP caller cannot override
        cfg = orchestrator_config or {}
        self._orchestrator = BoundedOrchestrator(
            max_steps=int(cfg.get("max_steps", 5)),
            max_tool_calls=int(cfg.get("max_tool_calls", 3)),
            deadline_seconds=int(cfg.get("deadline_seconds", 300)),
            allowed_capabilities=cfg.get("allowed_capabilities", ("transaction.propose",)),
            allowed_tools=cfg.get("allowed_tools", ("read_context", "submit_intent")),
            financial_limit=cfg.get("financial_limit"),
        )

    # ─── Public MCP tool handlers ─────────────────────────────────────────

    def propose_transaction(
        self,
        raw_input: dict[str, Any],
    ) -> ProposeTransactionResponse:
        """MCP propose_transaction — a PROPOSAL, not an authority operation.

        Flow: MCP input validation → authority-field rejection → ProposeTransactionRequest
              → M4 orchestration check → StructuredIntentBoundary → M3.2 guardrails
              → DecisionEngine → read decision result → ProposeTransactionResponse

        The MCP caller is never the authority.  APPROVAL_REQUIRED stops here.
        """
        correlation_id = str(uuid.uuid4())
        self._session.check_rate_limit(correlation_id)
        self._reject_prohibited_tool_attempt("propose_transaction", raw_input)
        _reject_authority_shaped_input(raw_input)

        try:
            req = ProposeTransactionRequest(**raw_input)
        except Exception as exc:  # broad catch: any Pydantic/validation error terminates the request safely
            raise MCPInputError(
                f"Request validation failed: {exc}",
                code="MCP_REQUEST_INVALID",
                correlation_id=correlation_id,
            ) from exc

        self._audit_mcp_event(
            "MCP_PROPOSE_RECEIVED",
            correlation_id,
            {
                "from_account": req.from_account,
                "recipient": req.recipient,
                "currency": req.currency,
                "request_id": str(req.request_id),
            },
        )

        # M4: assert that the run stays within orchestrator-configured bounds
        # (MCP caller cannot set max_steps, deadline, capabilities, etc.)
        try:
            run: OrchestrationRun = self._orchestrator.start(
                f"mcp:propose_transaction:{req.request_id}",
                capabilities=None,  # use server-configured capabilities only
            )
        except OrchestrationBudgetExceeded as exc:
            raise MCPBoundaryError(
                "MCP_ORCHESTRATION_BUDGET_EXCEEDED",
                "Orchestration budget exceeded; request cannot proceed.",
                retryable=False,
                correlation_id=correlation_id,
            ) from exc

        # Build a StructuredIntent dict for the M3.1 boundary.
        # The actor_id is bound by this boundary class, NOT taken from MCP input.
        intent_dict = {
            "schema_version": 1,
            "intent_id": str(uuid.uuid4()),
            "correlation_id": correlation_id,
            "action": "propose_transaction",
            "capability": "transaction.propose",
            "from_account": req.from_account,
            "recipient": req.recipient,
            "amount": req.amount,
            "currency": req.currency,
            "reason": req.reason,
            "context": {},
        }

        try:
            # M3.1 + M3.2: StructuredIntentBoundary enforces guardrails internally
            boundary = StructuredIntentBoundary(
                actor_id=self._actor_id,
                session_id=self._session.session_id,
            )
            decision_result = boundary.submit(intent_dict)
        except IntentValidationError as exc:
            self._orchestrator.reject(run, f"intent_validation: {exc.code}")
            self._audit_mcp_event(
                "MCP_PROPOSE_REJECTED",
                correlation_id,
                {"reason_code": exc.code, "reasons": list(exc.reasons)},
                result="REJECT",
            )
            return ProposeTransactionResponse(
                request_id=req.request_id,
                correlation_id=correlation_id,
                success=False,
                decision="block",
                reasons=list(exc.reasons),
                approval_required=False,
            )
        except SecurityError as exc:
            self._orchestrator.fail(run, str(exc))
            self._audit_mcp_event(
                "MCP_PROPOSE_SECURITY_ERROR",
                correlation_id,
                {"error": "security_error"},
                result="FAIL",
            )
            raise MCPBoundaryError(
                "MCP_SECURITY_ERROR",
                "A security check failed. The request has been denied.",
                retryable=False,
                correlation_id=correlation_id,
            ) from exc

        decision = decision_result.decision
        receipt = decision_result.receipt

        # APPROVAL_REQUIRED: orchestration STOPS here. MCP must not auto-approve.
        approval_required = decision == DecisionType.REQUIRE_APPROVAL
        if approval_required:
            self._orchestrator.require_approval(run, "core_requires_human_approval")
        else:
            # Complete the orchestration run — bounds were respected
            self._orchestrator.guardrail_check(run)

        self._audit_mcp_event(
            "MCP_PROPOSE_DECIDED",
            correlation_id,
            {
                "decision": decision.value,
                "receipt_id": receipt.receipt_id,
                "transaction_id": receipt.transaction_id,
                "transaction_hash": receipt.transaction_hash,
                "approval_required": approval_required,
                "authorization": "none",
            },
        )

        return ProposeTransactionResponse(
            request_id=req.request_id,
            correlation_id=correlation_id,
            success=True,
            decision=decision.value,
            receipt_id=receipt.receipt_id,
            transaction_id=receipt.transaction_id,
            transaction_hash=receipt.transaction_hash,
            reasons=receipt.reasons,
            approval_required=approval_required,
        )

    def get_decision(self, raw_input: dict[str, Any]) -> DecisionResponse:
        """MCP get_decision — read-only receipt query. No mutations."""
        correlation_id = str(uuid.uuid4())
        self._session.check_rate_limit(correlation_id)
        _reject_authority_shaped_input(raw_input)

        try:
            req = GetDecisionRequest(**raw_input)
        except Exception as exc:  # broad catch: any Pydantic/validation error terminates the request safely
            raise MCPInputError(
                f"Request validation failed: {exc}",
                correlation_id=correlation_id,
            ) from exc

        session = get_session()
        try:
            record = session.get(DecisionReceiptRecord, req.receipt_id)
            if record is None:
                raise MCPNotFoundError(correlation_id=correlation_id)
            # Return only safe, non-secret fields
            return DecisionResponse(
                request_id=req.request_id,
                receipt_id=record.receipt_id,
                transaction_id=record.transaction_id,
                transaction_hash=record.transaction_hash,
                decision=record.decision,
                actor_id=record.actor_id,
                approval_required=(record.approval_state == "pending"),
                reasons=[],  # reason detail not exposed through MCP
            )
        finally:
            session.close()

    def list_transactions(self, raw_input: dict[str, Any]) -> ListTransactionsResponse:
        """MCP list_transactions — read-only, scoped to caller's actor_id."""
        correlation_id = str(uuid.uuid4())
        self._session.check_rate_limit(correlation_id)
        _reject_authority_shaped_input(raw_input)

        try:
            req = ListTransactionsRequest(**raw_input)
        except Exception as exc:  # broad catch: any Pydantic/validation error terminates the request safely
            raise MCPInputError(
                f"Request validation failed: {exc}",
                correlation_id=correlation_id,
            ) from exc

        db_session = get_session()
        try:
            records = (
                db_session.query(TransactionRecord)
                .filter(TransactionRecord.actor_id == self._actor_id)
                .order_by(TransactionRecord.timestamp.desc())
                .limit(req.limit)
                .all()
            )
            items = [
                TransactionSummary(
                    transaction_id=r.transaction_id,
                    state=r.state,
                    amount=str(r.amount_minor) if r.amount_minor is not None else None,
                    currency=r.currency,
                    decision=None,
                    created_at=r.timestamp.isoformat() if r.timestamp else None,
                )
                for r in records
            ]
            return ListTransactionsResponse(
                request_id=req.request_id,
                items=items,
                count=len(items),
            )
        finally:
            db_session.close()

    def get_audit_proof(self, raw_input: dict[str, Any]) -> AuditProofResponse:
        """MCP get_audit_proof — read-only ledger entry. No mutation."""
        correlation_id = str(uuid.uuid4())
        self._session.check_rate_limit(correlation_id)
        _reject_authority_shaped_input(raw_input)

        try:
            req = GetAuditProofRequest(**raw_input)
        except Exception as exc:  # broad catch: any Pydantic/validation error terminates the request safely
            raise MCPInputError(
                f"Request validation failed: {exc}",
                correlation_id=correlation_id,
            ) from exc

        db_session = get_session()
        try:
            record = (
                db_session.query(AuditEntryRecord)
                .filter(AuditEntryRecord.seq == req.seq)
                .first()
            )
            if record is None:
                raise MCPNotFoundError(correlation_id=correlation_id)
            # No private keys, credentials, or metadata with secrets returned
            return AuditProofResponse(
                request_id=req.request_id,
                seq=record.seq,
                entry_hash=record.entry_hash,
                previous_hash=record.previous_hash,
                action=record.action,
                actor_id=record.actor_id,
                result=record.result,
            )
        finally:
            db_session.close()

    # ─── Structural prohibition ───────────────────────────────────────────

    @staticmethod
    def _reject_prohibited_tool_attempt(
        tool_name: str, raw_input: dict[str, Any]
    ) -> None:
        """Structurally reject attempts to invoke prohibited tools by name."""
        # Check if the input itself is trying to invoke a prohibited operation
        for field_name in ("tool", "tool_name", "operation", "action"):
            attempted = str(raw_input.get(field_name, "")).strip().lower()
            if attempted and attempted in _PROHIBITED_TOOLS:
                raise MCPForbiddenToolError(attempted)

    # ─── Audit ────────────────────────────────────────────────────────────

    def _audit_mcp_event(
        self,
        action: str,
        correlation_id: str,
        metadata: dict[str, Any],
        *,
        result: str = "PASS",
    ) -> None:
        """Append supplemental MCP events to the existing audit ledger.

        These appends are supplemental (not atomic with the core financial
        transaction). Atomicity is guaranteed by the core decision path only.
        """
        try:
            AuditLedger().append(
                action=action,
                actor_id=self._actor_id,
                result=result,
                metadata={
                    **metadata,
                    "mcp_session_id": self._session.session_id,
                    "correlation_id": correlation_id,
                    "boundary": "M5_MCP",
                },
            )
        except Exception:  # noqa: BLE001
            # Audit failure must not block the response, but MUST be logged loudly
            logger.error(
                "MCP AUDIT FAILURE: supplemental MCP event could not be appended. "
                "action=%s actor=%s correlation=%s  — manual review required.",
                action,
                self._actor_id,
                correlation_id,
            )
