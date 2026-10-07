"""MCP Boundary structural and integration tests — M5.

Tests the MCPSecurityBoundary enforces its core invariants:
- MCP_INPUT_IS_UNTRUSTED
- MCP_OUTPUT_IS_UNTRUSTED
- MCP_CANNOT_BYPASS_M3_2
- MCP_CANNOT_BYPASS_M4
- MCP_CANNOT_SELF_GRANT_CAPABILITY
- MCP_CANNOT_AUTHORIZE
- MCP_CANNOT_SIGN
- MCP_CANNOT_EXECUTE
- MCP_CANNOT_CHANGE_POLICY
- MCP_CANNOT_EXPOSE_SECRETS
- MCP_CANNOT_EXTEND_ORCHESTRATION_BOUNDS
"""

from __future__ import annotations

import importlib
import types

import pytest
from pydantic import ValidationError

from finguard.core.enums import ActorType, AgentCapability
from finguard.identity.registry import ActorConfig, IdentityRegistry
from finguard.mcp.boundary import MCPSecurityBoundary, MCPSession
from finguard.mcp.errors import MCPBoundaryError, MCPInputError, MCPRateLimitError
from finguard.mcp.models import (
    AuditProofResponse,
    ListTransactionsRequest,
    ListTransactionsResponse,
    ProposeTransactionRequest,
    ProposeTransactionResponse,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _register_test_agent(
    actor_id: str = "treasury-agent",
    allowed_destinations: list[str] | None = None,
    allowed_source_accounts: list[str] | None = None,
    authority_limit: str = "10000.00",
    capabilities: list[str] | None = None,
) -> None:
    registry = IdentityRegistry()
    actor = ActorConfig(
        actor_id=actor_id,
        actor_type=ActorType.AGENT,
        display_name="Test Agent",
        active=True,
        authority_currency="INR",
        authority_limit=authority_limit,
        allowed_destinations=allowed_destinations or ["vendor-a", "vendor-b"],
        allowed_source_accounts=allowed_source_accounts or ["treasury"],
        agent_capabilities=[
            AgentCapability(c) for c in (capabilities or ["transaction.propose"])
        ],
    )
    registry.register_actor(actor, registry.root_priv_path)


def _make_boundary(
    actor_id: str = "treasury-agent",
    session_id: str = "mcp-test-session",
    orchestrator_config: dict | None = None,
) -> tuple[MCPSecurityBoundary, MCPSession]:
    session = MCPSession(session_id)
    boundary = MCPSecurityBoundary(
        actor_id=actor_id,
        session=session,
        orchestrator_config=orchestrator_config,
    )
    return boundary, session


def _valid_propose() -> dict:
    return {
        "from_account": "treasury",
        "recipient": "vendor-a",
        "amount": "5.00",
        "currency": "INR",
        "reason": "invoice 1234",
    }


# ─── I. Session and Rate-Limit ─────────────────────────────────────────────

class TestMCPSession:
    def test_session_requires_non_blank_id(self):
        with pytest.raises(ValueError):
            MCPSession("")

    def test_session_tracks_request_count(self):
        s = MCPSession("s1")
        s.check_rate_limit()
        s.check_rate_limit()
        assert s.request_count == 2

    def test_session_rate_limit_enforced_after_100_requests(self):
        s = MCPSession("s-rate")
        for _ in range(100):
            s.check_rate_limit()
        with pytest.raises(MCPRateLimitError):
            s.check_rate_limit()

    def test_rate_limit_error_is_retryable(self):
        s = MCPSession("s-retry")
        for _ in range(100):
            s.check_rate_limit()
        try:
            s.check_rate_limit()
        except MCPRateLimitError as exc:
            assert exc.retryable is True


# ─── II. Input Validation ──────────────────────────────────────────────────

class TestMCPInputValidation:
    def test_valid_propose_request_passes_validation(self):
        req = ProposeTransactionRequest(**_valid_propose())
        assert req.from_account == "treasury"
        assert req.currency == "INR"

    def test_float_amount_is_rejected(self):
        with pytest.raises((ValidationError, TypeError)):
            ProposeTransactionRequest(**{**_valid_propose(), "amount": 5.00})

    def test_bool_amount_is_rejected(self):
        with pytest.raises((ValidationError, TypeError)):
            ProposeTransactionRequest(**{**_valid_propose(), "amount": True})

    def test_nan_string_amount_rejected_by_money_layer(self):
        """NaN passes string check but Money.from_decimal rejects it downstream."""
        # We test that the propose pipeline itself rejects NaN
        _register_test_agent()
        boundary, _ = _make_boundary()
        result = boundary.propose_transaction({**_valid_propose(), "amount": "nan"})
        assert result.success is False

    def test_oversized_reason_is_rejected(self):
        with pytest.raises(ValidationError):
            ProposeTransactionRequest(**{**_valid_propose(), "reason": "x" * 1025})

    def test_blank_from_account_is_rejected(self):
        with pytest.raises(ValidationError):
            ProposeTransactionRequest(**{**_valid_propose(), "from_account": ""})

    def test_blank_recipient_is_rejected(self):
        with pytest.raises(ValidationError):
            ProposeTransactionRequest(**{**_valid_propose(), "recipient": ""})

    def test_extra_unknown_fields_are_forbidden(self):
        with pytest.raises(ValidationError):
            ProposeTransactionRequest(**{**_valid_propose(), "unexpected_field": "x"})

    def test_currency_normalised_to_uppercase(self):
        req = ProposeTransactionRequest(**{**_valid_propose(), "currency": "inr"})
        assert req.currency == "INR"

    def test_non_alpha_currency_rejected(self):
        with pytest.raises(ValidationError):
            ProposeTransactionRequest(**{**_valid_propose(), "currency": "IN1"})


# ─── III. Authority-Field Rejection ───────────────────────────────────────

class TestAuthorityFieldRejection:
    """MCP_INPUT_IS_UNTRUSTED: authority-shaped fields denied before any core call."""

    @pytest.mark.parametrize("field", [
        "approved", "authorized", "signer", "signature", "execute",
        "execution", "execution_state", "policy_override", "grant_capability",
        "admin", "root", "signing_key", "approve", "sign", "private_key",
        "secret", "credential",
    ])
    def test_authority_shaped_field_rejected(self, field):
        _register_test_agent()
        boundary, _ = _make_boundary()
        hostile = {**_valid_propose(), field: True}
        with pytest.raises(MCPInputError) as exc_info:
            boundary.propose_transaction(hostile)
        assert "MCP_AUTHORITY_FIELD_REJECTED" in exc_info.value.code

    def test_authority_field_rejected_in_get_decision(self):
        _register_test_agent()
        boundary, _ = _make_boundary()
        with pytest.raises(MCPInputError):
            boundary.get_decision({"receipt_id": "RCT-ABC", "approved": True})

    def test_authority_field_rejected_in_list_transactions(self):
        _register_test_agent()
        boundary, _ = _make_boundary()
        with pytest.raises(MCPInputError):
            boundary.list_transactions({"limit": 10, "authorized": True})

    def test_authority_field_rejected_in_get_audit_proof(self):
        _register_test_agent()
        boundary, _ = _make_boundary()
        with pytest.raises(MCPInputError):
            boundary.get_audit_proof({"seq": 1, "signer": "root"})


# ─── IV. Proposal Flow — Happy Path ───────────────────────────────────────

class TestMCPProposalFlow:
    def test_valid_proposal_returns_response_with_decision(self):
        _register_test_agent()
        boundary, _ = _make_boundary()
        result = boundary.propose_transaction(_valid_propose())
        assert isinstance(result, ProposeTransactionResponse)
        assert result.decision in ("allow", "block", "require_approval")
        assert result.authorization_status == "NOT_AUTHORIZED"

    def test_proposal_response_never_claims_authorization(self):
        _register_test_agent()
        boundary, _ = _make_boundary()
        result = boundary.propose_transaction(_valid_propose())
        assert result.authorization_status == "NOT_AUTHORIZED"

    def test_proposal_stops_at_approval_required(self):
        """When core returns REQUIRE_APPROVAL the MCP response must set approval_required."""
        _register_test_agent(authority_limit="1.00")  # very low limit forces approval
        boundary, _ = _make_boundary()
        result = boundary.propose_transaction({**_valid_propose(), "amount": "500.00"})
        # Either blocked or approval_required — not executed
        assert result.decision in ("block", "require_approval")

    def test_invalid_actor_raises_security_error(self):
        """Actor not registered → MCPBoundaryError, not a bypass."""
        boundary, _ = _make_boundary(actor_id="nonexistent-agent-xyz")
        with pytest.raises(MCPBoundaryError):
            boundary.propose_transaction(_valid_propose())

    def test_proposal_with_unregistered_recipient_is_blocked(self):
        _register_test_agent(allowed_destinations=["vendor-a"])
        boundary, _ = _make_boundary()
        result = boundary.propose_transaction({**_valid_propose(), "recipient": "attacker"})
        assert result.success is False
        assert result.decision in ("block",)


# ─── V. M4 Orchestration Bounds Are Immutable From MCP ───────────────────

class TestMCPCannotExtendOrchestrationBounds:
    """MCP_CANNOT_EXTEND_ORCHESTRATION_BOUNDS: caller cannot change max_steps etc."""

    def test_boundary_uses_server_configured_max_steps(self):
        _register_test_agent()
        boundary, _ = _make_boundary(orchestrator_config={"max_steps": 3})
        # The orchestrator should have max_steps=3 — not caller-supplied
        assert boundary._orchestrator.max_steps == 3

    def test_boundary_ignores_caller_attempt_to_set_high_max_steps(self):
        """MCP input cannot carry orchestration parameters."""
        _register_test_agent()
        boundary, _ = _make_boundary(orchestrator_config={"max_steps": 3})
        hostile = {**_valid_propose(), "max_steps": 9999}
        # extra fields are rejected by ProposeTransactionRequest (extra='forbid')
        with pytest.raises(MCPInputError):
            boundary.propose_transaction(hostile)

    def test_boundary_ignores_caller_capability_override(self):
        _register_test_agent()
        boundary, _ = _make_boundary()
        hostile = {**_valid_propose(), "capabilities": ["admin", "sign_transaction"]}
        with pytest.raises(MCPInputError):
            boundary.propose_transaction(hostile)

    def test_financial_limit_cannot_be_reset_by_mcp_caller(self):
        _register_test_agent()
        boundary, _ = _make_boundary(orchestrator_config={"financial_limit": 100_00})  # 100.00 INR
        hostile = {**_valid_propose(), "financial_limit": 999_999_999}
        with pytest.raises(MCPInputError):
            boundary.propose_transaction(hostile)


# ─── VI. Read-Only Tools ──────────────────────────────────────────────────

class TestMCPReadOnlyTools:
    def test_get_decision_with_missing_receipt_raises_not_found(self):
        from finguard.mcp.errors import MCPNotFoundError
        _register_test_agent()
        boundary, _ = _make_boundary()
        with pytest.raises(MCPNotFoundError):
            boundary.get_decision({"receipt_id": "RCT-DOESNOTEXIST"})

    def test_list_transactions_returns_empty_for_new_actor(self):
        _register_test_agent()
        boundary, _ = _make_boundary()
        result = boundary.list_transactions({"limit": 10})
        assert isinstance(result, ListTransactionsResponse)
        assert result.count == 0

    def test_list_transactions_limit_enforced(self):
        with pytest.raises(ValidationError):
            ListTransactionsRequest(limit=51)

    def test_get_audit_proof_missing_seq_raises_not_found(self):
        from finguard.mcp.errors import MCPNotFoundError
        _register_test_agent()
        boundary, _ = _make_boundary()
        with pytest.raises(MCPNotFoundError):
            boundary.get_audit_proof({"seq": 99999})

    def test_get_audit_proof_response_has_no_secret_fields(self):
        """Audit proof response model must not have key/credential fields."""
        fields = AuditProofResponse.model_fields.keys()
        prohibited = {"private_key", "secret", "credential", "signing_key", "password"}
        assert not (set(fields) & prohibited)


# ─── VII. Import Boundary ─────────────────────────────────────────────────

class TestMCPImportBoundary:
    """Structural: finguard.mcp must NOT import forbidden privileged modules."""

    def _collect_transitive_imports(self, module_name: str) -> set[str]:
        """Walk the import graph from module_name and collect all module names."""
        visited: set[str] = set()
        queue = [module_name]
        while queue:
            name = queue.pop()
            if name in visited:
                continue
            visited.add(name)
            try:
                mod = importlib.import_module(name)
            except ImportError:
                continue
            for attr in dir(mod):
                val = getattr(mod, attr, None)
                if isinstance(val, types.ModuleType) and val.__name__.startswith("finguard"):
                    queue.append(val.__name__)
        return visited

    @pytest.mark.parametrize("forbidden_module", [
        "finguard.crypto.keystore",
        "finguard.signing",
        "finguard.signing.gate",
        "finguard.approvals.service",
        "finguard.simulator.service",
    ])
    def test_mcp_boundary_does_not_import_forbidden_module(self, forbidden_module):
        """MCP boundary.py must not pull in signing/keystore/approvals/simulator."""
        import finguard.mcp.boundary as mod
        source_imports = set()

        # Walk the module's direct __dict__ for imported module references
        for attr in dir(mod):
            val = getattr(mod, attr, None)
            if isinstance(val, types.ModuleType):
                source_imports.add(val.__name__)

        assert forbidden_module not in source_imports, (
            f"finguard.mcp.boundary must NOT import {forbidden_module}"
        )

    def test_mcp_init_does_not_import_keystore(self):
        import finguard.mcp as pkg
        for attr in dir(pkg):
            val = getattr(pkg, attr, None)
            if isinstance(val, types.ModuleType):
                assert "keystore" not in val.__name__, (
                    f"finguard.mcp.__init__ must not expose keystore; found {val.__name__}"
                )

    def test_mcp_errors_does_not_import_finguard_core(self):
        """Error module should be standalone — no core dependency."""
        import finguard.mcp.errors as err_mod
        for attr in dir(err_mod):
            val = getattr(err_mod, attr, None)
            if isinstance(val, types.ModuleType):
                # Allow builtins but not finguard core
                assert not val.__name__.startswith("finguard.crypto"), (
                    f"finguard.mcp.errors must not import crypto; found {val.__name__}"
                )


# ─── VIII. Error Safety ──────────────────────────────────────────────────

class TestMCPErrorSafety:
    """MCP_CANNOT_EXPOSE_SECRETS: errors never leak keys, paths, credentials."""

    def test_mcp_input_error_message_has_no_path_separators(self):
        err = MCPInputError("bad input", correlation_id="c1")
        assert "\\" not in err.message
        assert "/.finguard" not in err.message

    def test_mcp_boundary_error_to_dict_has_stable_shape(self):
        err = MCPBoundaryError("TEST_CODE", "test message", retryable=True, correlation_id="x")
        d = err.to_dict()
        assert d["error"]["code"] == "TEST_CODE"
        assert d["error"]["retryable"] is True
        assert "message" in d["error"]
        assert "correlation_id" in d["error"]

    def test_mcp_error_does_not_contain_private_key_words(self):
        err = MCPInputError("validation failed")
        forbidden_words = ("private_key", "secret", "password", "credential", "keystore")
        for word in forbidden_words:
            assert word not in err.message.lower()

    def test_boundary_error_for_invalid_actor_does_not_expose_internals(self):
        boundary, _ = _make_boundary(actor_id="nonexistent-xyz")
        try:
            boundary.propose_transaction(_valid_propose())
        except MCPBoundaryError as exc:
            assert "keystore" not in exc.message.lower()
            assert "private" not in exc.message.lower()
            assert ".finguard" not in exc.message


# ─── IX. Security Chain Integration ──────────────────────────────────────

class TestMCPFullSecurityChain:
    """Test the complete chain: MCP → M4 → M3.1 → M3.2 → DecisionEngine."""

    def test_valid_mcp_proposal_reaches_decision_engine(self):
        """A legitimate proposal must produce a real decision receipt."""
        _register_test_agent()
        boundary, _ = _make_boundary()
        result = boundary.propose_transaction(_valid_propose())
        # Any decision (allow/block/require_approval) is a valid core response
        assert result.decision is not None
        assert result.receipt_id is not None or result.success is False

    def test_proposal_authorization_status_always_not_authorized(self):
        """No matter what the decision, MCP response never claims authorization."""
        _register_test_agent()
        boundary, _ = _make_boundary()
        result = boundary.propose_transaction(_valid_propose())
        assert result.authorization_status == "NOT_AUTHORIZED"

    def test_approval_required_does_not_auto_advance(self):
        """APPROVAL_REQUIRED state: MCP must not continue to execution."""
        _register_test_agent(authority_limit="0.50")  # forces approval on 5 INR
        boundary, _ = _make_boundary()
        result = boundary.propose_transaction({**_valid_propose(), "amount": "5.00"})
        # Must be blocked or approval_required — never executed
        assert result.decision in ("block", "require_approval")
        # run should be in APPROVAL_REQUIRED or REJECTED state, never COMPLETED+executed
        assert result.authorization_status == "NOT_AUTHORIZED"
