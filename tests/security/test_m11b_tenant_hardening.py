"""M11-B regression tests for Tenant and Account Boundary Hardening.

These tests prove that DecisionEngine.decide() enforces tenant and account
ownership on the authoritative decision path.

Vulnerabilities reproduced:
1. Source account belongs to another tenant (vulnerable baseline allows it).
2. Destination account belongs to another tenant (vulnerable baseline allows it).
3. A valid alias resolves to an account owned by another tenant.
4. Caller attempts to spoof tenant identity in transaction payload or metadata.
5. Unknown or ambiguous account ownership fails closed.
6. Missing actor tenant identity fails closed.
7. Legitimate same-tenant transfer succeeds.
8. Rejection leaves no authorized decision, approval request, signature, or balance mutation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from finguard.core.enums import (
    ActorType,
    AgentCapability,
    Currency,
    DecisionType,
    TransactionState,
)
from finguard.core.errors import SecurityError
from finguard.core.transaction import Transaction
from finguard.decision.engine import DecisionEngine
from finguard.identity.account_registry import (
    AccountConfig,
    AccountRegistry,
)
from finguard.identity.registry import ActorConfig, IdentityRegistry
from finguard.money import Money
from finguard.policy.engine import PolicyEngine
from finguard.policy.schema import PolicyConfig
from finguard.signing.gate import SigningGate
from finguard.storage.database import get_session
from finguard.storage.models import ApprovalRequestRecord
from finguard.storage.repositories import TransactionRepository

# ---------------------------------------------------------------------------
# Fixtures and Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def multi_tenant_setup(tmp_path: Path):
    """Set up two tenants (alpha and beta) with distinct accounts and actors."""
    id_registry = IdentityRegistry(data_dir=tmp_path)
    root_key_path = tmp_path / "root_operator.key"

    # Register tenant_alpha agent
    agent_alpha = ActorConfig(
        actor_id="agent-alpha",
        actor_type=ActorType.AGENT,
        display_name="Tenant Alpha Treasury Agent",
        authority_currency=Currency.INR,
        authority_limit="50000.00",
        allowed_source_accounts=["acct_alpha_treasury", "acct_beta_treasury"],  # intentionally broad
        allowed_destinations=["acct_alpha_vendor", "acct_beta_vendor", "shared_alias", "beta_alias"],
        agent_capabilities=[AgentCapability.TRANSACTION_PROPOSE],
        tenant_id="tenant_alpha",
    )
    id_registry.register_actor(agent_alpha, root_key_path)

    # Register tenant_alpha operator for human-authorized flows
    operator_alpha = ActorConfig(
        actor_id="operator-alpha",
        actor_type=ActorType.HUMAN_OPERATOR,
        display_name="Tenant Alpha Human Operator",
        authority_currency=Currency.INR,
        authority_limit="50000.00",
        allowed_source_accounts=["acct_alpha_treasury"],
        allowed_destinations=["acct_alpha_vendor"],
        tenant_id="tenant_alpha",
    )
    id_registry.register_actor(operator_alpha, root_key_path)

    # Register tenant_beta agent
    agent_beta = ActorConfig(
        actor_id="agent-beta",
        actor_type=ActorType.AGENT,
        display_name="Tenant Beta Treasury Agent",
        authority_currency=Currency.INR,
        authority_limit="50000.00",
        allowed_source_accounts=["acct_beta_treasury"],
        allowed_destinations=["acct_beta_vendor"],
        tenant_id="tenant_beta",
    )
    id_registry.register_actor(agent_beta, root_key_path)

    # Register actor with missing tenant_id
    agent_no_tenant = ActorConfig(
        actor_id="agent-no-tenant",
        actor_type=ActorType.AGENT,
        display_name="Agent Without Tenant",
        authority_currency=Currency.INR,
        authority_limit="50000.00",
        allowed_source_accounts=["acct_alpha_treasury"],
        allowed_destinations=["acct_alpha_vendor"],
        tenant_id="",  # empty tenant
    )
    id_registry.register_actor(agent_no_tenant, root_key_path)

    # Set up AccountRegistry with tenant-isolated accounts
    acc_registry = AccountRegistry()

    # Alpha accounts
    acc_registry.register_account(
        AccountConfig(
            account_id="acct_alpha_treasury",
            tenant_id="tenant_alpha",
            display_name="Alpha Treasury",
            currency=Currency.INR,
            aliases=["alpha_treasury"],
        )
    )
    acc_registry.register_account(
        AccountConfig(
            account_id="acct_alpha_vendor",
            tenant_id="tenant_alpha",
            display_name="Alpha Vendor",
            currency=Currency.INR,
            aliases=["alpha_vendor"],
        )
    )

    # Beta accounts
    acc_registry.register_account(
        AccountConfig(
            account_id="acct_beta_treasury",
            tenant_id="tenant_beta",
            display_name="Beta Treasury",
            currency=Currency.INR,
            aliases=["beta_treasury"],
        )
    )
    acc_registry.register_account(
        AccountConfig(
            account_id="acct_beta_vendor",
            tenant_id="tenant_beta",
            display_name="Beta Vendor",
            currency=Currency.INR,
            aliases=["beta_alias", "beta_vendor"],
        )
    )

    # Ambiguous alias shared between alpha and beta
    acc_registry.register_account(
        AccountConfig(
            account_id="acct_shared_alpha",
            tenant_id="tenant_alpha",
            display_name="Shared Alpha",
            currency=Currency.INR,
            aliases=["shared_alias"],
        )
    )
    acc_registry.register_account(
        AccountConfig(
            account_id="acct_shared_beta",
            tenant_id="tenant_beta",
            display_name="Shared Beta",
            currency=Currency.INR,
            aliases=["shared_alias"],
        )
    )

    policy = PolicyConfig(
        policy_id="tenant-policy",
        version=1,
        max_amount={"amount": "100000.00"},
        allowed_destinations=["acct_alpha_vendor", "acct_beta_vendor", "vendor-a", "vendor-b"],
        approval={"required_above": "25000.00", "required_approvals": 1},
        agent={
            "max_amount": "50000.00",
            "allowed_destinations": ["acct_alpha_vendor", "acct_beta_vendor", "vendor-a", "vendor-b"],
        },
    )
    policy_engine = PolicyEngine(policy=policy)
    engine = DecisionEngine(
        registry=id_registry,
        policy_engine=policy_engine,
        account_registry=acc_registry,
    )
    return engine, id_registry, acc_registry


# ===========================================================================
# Phase 2 — Regression Tests for DecisionEngine Tenant Hardening
# ===========================================================================

class TestTenantBoundaryDecisionPath:
    """Demonstrate that DecisionEngine.decide() strictly enforces tenant isolation."""

    def test_case_1_source_account_belongs_to_another_tenant_is_blocked(self, multi_tenant_setup):
        """Case 1: agent-alpha attempts to spend from acct_beta_treasury.

        Even though agent-alpha has acct_beta_treasury in allowed_source_accounts,
        acct_beta_treasury belongs to tenant_beta, not tenant_alpha.
        Decision must be BLOCK.
        """
        engine, _, _ = multi_tenant_setup
        tx = Transaction(
            actor_id="agent-alpha",
            from_account="acct_beta_treasury",  # owned by tenant_beta
            to_account="acct_alpha_vendor",     # owned by tenant_alpha
            amount=Money.from_decimal("100.00", Currency.INR),
        )
        result = engine.decide(tx)
        assert result.decision == DecisionType.BLOCK
        assert any("Tenant boundary violation" in r for r in result.receipt.reasons)

    def test_case_2_destination_account_belongs_to_another_tenant_is_blocked(self, multi_tenant_setup):
        """Case 2: agent-alpha attempts to transfer to acct_beta_vendor.

        acct_beta_vendor belongs to tenant_beta.
        Decision must be BLOCK.
        """
        engine, _, _ = multi_tenant_setup
        tx = Transaction(
            actor_id="agent-alpha",
            from_account="acct_alpha_treasury",
            to_account="acct_beta_vendor",  # owned by tenant_beta
            amount=Money.from_decimal("100.00", Currency.INR),
        )
        result = engine.decide(tx)
        assert result.decision == DecisionType.BLOCK
        assert any("Tenant boundary violation" in r for r in result.receipt.reasons)

    def test_case_3_valid_alias_resolving_to_another_tenant_is_blocked(self, multi_tenant_setup):
        """Case 3: agent-alpha uses valid alias 'beta_alias' which resolves to acct_beta_vendor.

        Even though 'beta_alias' is a valid registered alias, its target belongs to tenant_beta.
        Decision must be BLOCK.
        """
        engine, _, _ = multi_tenant_setup
        tx = Transaction(
            actor_id="agent-alpha",
            from_account="acct_alpha_treasury",
            to_account="beta_alias",  # alias for acct_beta_vendor (tenant_beta)
            amount=Money.from_decimal("100.00", Currency.INR),
        )
        result = engine.decide(tx)
        assert result.decision == DecisionType.BLOCK
        assert any("Tenant boundary violation" in r for r in result.receipt.reasons)

    def test_case_4_spoofed_tenant_in_metadata_is_ignored_and_blocked(self, multi_tenant_setup):
        """Case 4: Caller passes metadata={'tenant_id': 'tenant_beta'} attempting to authorize

        spending from acct_beta_treasury.
        The decision engine must use trusted actor.tenant_id ('tenant_alpha') only.
        Decision must be BLOCK.
        """
        engine, _, _ = multi_tenant_setup
        tx = Transaction(
            actor_id="agent-alpha",
            from_account="acct_beta_treasury",
            to_account="acct_beta_vendor",
            amount=Money.from_decimal("100.00", Currency.INR),
            metadata={"tenant_id": "tenant_beta", "claim": "admin_override"},
        )
        result = engine.decide(tx)
        assert result.decision == DecisionType.BLOCK
        assert any("Tenant boundary violation" in r for r in result.receipt.reasons)

    def test_case_5a_unknown_account_fails_closed(self, multi_tenant_setup):
        """Case 5a: Unregistered destination account fails closed."""
        engine, _, _ = multi_tenant_setup
        tx = Transaction(
            actor_id="agent-alpha",
            from_account="acct_alpha_treasury",
            to_account="acct_completely_unknown",
            amount=Money.from_decimal("100.00", Currency.INR),
        )
        result = engine.decide(tx)
        assert result.decision == DecisionType.BLOCK
        assert any(
            "resolution failed" in r.lower() or "tenant boundary violation" in r.lower()
            for r in result.receipt.reasons
        )

    def test_case_5b_ambiguous_alias_fails_closed(self, multi_tenant_setup):
        """Case 5b: Destination alias 'shared_alias' matches accounts in both tenants.

        Ambiguous alias resolution must fail closed with BLOCK.
        """
        engine, _, _ = multi_tenant_setup
        tx = Transaction(
            actor_id="agent-alpha",
            from_account="acct_alpha_treasury",
            to_account="shared_alias",
            amount=Money.from_decimal("100.00", Currency.INR),
        )
        result = engine.decide(tx)
        assert result.decision == DecisionType.BLOCK
        assert any("resolution failed" in r.lower() for r in result.receipt.reasons)

    def test_case_6_missing_actor_tenant_identity_fails_closed(self, multi_tenant_setup):
        """Case 6: Actor configured with empty/missing tenant_id fails closed."""
        engine, _, _ = multi_tenant_setup
        tx = Transaction(
            actor_id="agent-no-tenant",
            from_account="acct_alpha_treasury",
            to_account="acct_alpha_vendor",
            amount=Money.from_decimal("100.00", Currency.INR),
        )
        result = engine.decide(tx)
        assert result.decision == DecisionType.BLOCK
        assert any("missing or empty actor tenant" in r.lower() for r in result.receipt.reasons)

    def test_case_7_legitimate_same_tenant_transfer_succeeds(self, multi_tenant_setup):
        """Case 7: operator-alpha transferring from acct_alpha_treasury to acct_alpha_vendor.

        Both accounts belong to tenant_alpha. Decision must be ALLOW.
        """
        engine, _, _ = multi_tenant_setup
        tx = Transaction(
            actor_id="operator-alpha",
            from_account="acct_alpha_treasury",
            to_account="acct_alpha_vendor",
            amount=Money.from_decimal("100.00", Currency.INR),
        )
        result = engine.decide(tx)
        assert result.decision == DecisionType.ALLOW
        assert result.receipt.authority_allowed is True

    def test_case_7_agent_same_tenant_transfer_authorized_requires_approval(
        self, multi_tenant_setup
    ):
        """Case 7b: agent-alpha transferring from acct_alpha_treasury to acct_alpha_vendor.

        Authority and tenant checks succeed; agent approval floor requires human approval.
        """
        engine, _, _ = multi_tenant_setup
        tx = Transaction(
            actor_id="agent-alpha",
            from_account="acct_alpha_treasury",
            to_account="acct_alpha_vendor",
            amount=Money.from_decimal("100.00", Currency.INR),
        )
        result = engine.decide(tx)
        assert result.decision == DecisionType.REQUIRE_APPROVAL
        assert result.receipt.authority_allowed is True
        assert not any("tenant boundary violation" in r.lower() for r in result.receipt.reasons)

    def test_case_8_cross_tenant_rejection_leaves_no_authorized_state_or_approval(
        self, multi_tenant_setup
    ):
        """Case 8: Cross-tenant rejection must not create approval request or signable record.

        Even with high amount that would otherwise trigger maker-checker approval.
        """
        engine, _, _ = multi_tenant_setup
        # Amount > 25000 would trigger approval if authority passed
        tx = Transaction(
            actor_id="agent-alpha",
            from_account="acct_beta_treasury",  # cross-tenant violation
            to_account="acct_alpha_vendor",
            amount=Money.from_decimal("30000.00", Currency.INR),
        )
        result = engine.decide(tx)

        # 1. Decision must be BLOCK (not REQUIRE_APPROVAL)
        assert result.decision == DecisionType.BLOCK
        assert result.transaction.state == TransactionState.BLOCKED

        session = get_session()
        try:
            # 2. No ApprovalRequestRecord created
            req = (
                session.query(ApprovalRequestRecord)
                .filter(ApprovalRequestRecord.transaction_id == tx.transaction_id)
                .first()
            )
            assert req is None, "Approval request was created for a blocked cross-tenant transfer!"

            # 3. TransactionRecord in DB is marked blocked or not committed (fail-closed before persistence)
            tx_rec = TransactionRepository(session).get(tx.transaction_id)
            assert tx_rec is None or tx_rec.state == "blocked"

            # 4. SigningGate must refuse to sign the transaction
            gate = SigningGate()
            with pytest.raises(SecurityError):
                gate.sign(tx.transaction_id, key_id="operator_key", password="test")
        finally:
            session.close()


# ===========================================================================
# Phase 4 — Adversarial Integration Coverage (MCP, SDK, Simulator, Retries)
# ===========================================================================

class TestTenantAdversarialIntegration:
    """Test the authoritative decision path through MCP and SDK surfaces."""

    def test_mcp_propose_cross_tenant_destination_is_blocked(self, multi_tenant_setup):
        """MCP proposal cannot transfer funds to an account belonging to another tenant."""
        from finguard.mcp.boundary import MCPSecurityBoundary, MCPSession

        _, id_registry, acc_registry = multi_tenant_setup
        session = MCPSession("mcp-tenant-test")
        boundary = MCPSecurityBoundary(
            actor_id="agent-alpha",  # tenant_alpha agent
            session=session,
            account_registry=acc_registry,
            registry=id_registry,
        )

        # agent-alpha belongs to tenant_alpha; acct_beta_vendor belongs to tenant_beta
        payload = {
            "from_account": "acct_alpha_treasury",
            "recipient": "acct_beta_vendor",
            "amount": "100.00",
            "currency": "INR",
            "reason": "adversarial cross-tenant attempt",
        }
        res = boundary.propose_transaction(payload)
        assert res.decision == "block"
        assert any("tenant boundary violation" in r.lower() for r in res.reasons)

    def test_mcp_propose_rejects_tenant_id_in_payload(self):
        """MCP boundary rejects authority-shaped 'tenant_id' field in requests."""
        from finguard.mcp.boundary import MCPSecurityBoundary, MCPSession
        from finguard.mcp.errors import MCPInputError

        session = MCPSession("mcp-spoof-test")
        boundary = MCPSecurityBoundary(actor_id="treasury-agent", session=session)

        payload = {
            "from_account": "acct_treasury",
            "recipient": "vendor-a",
            "amount": "100.00",
            "currency": "INR",
            "reason": "attempt to override tenant",
            "tenant_id": "tenant_admin",
        }
        with pytest.raises(MCPInputError, match="Authority-shaped field 'tenant_id' is not permitted"):
            boundary.propose_transaction(payload)

    def test_sdk_submit_intent_cross_tenant_is_blocked(self, multi_tenant_setup):
        """SDK client proposals routing to cross-tenant account are blocked."""
        from finguard.agent_sdk import FinGuardAgentClient

        _, id_registry, acc_registry = multi_tenant_setup
        client = FinGuardAgentClient(
            actor_id="agent-alpha",
            session_id="sdk-test",
            account_registry=acc_registry,
            registry=id_registry,
        )
        result = client.create_transaction(
            amount="100.00",
            currency="INR",
            destination="acct_beta_vendor",
            purpose="cross-tenant payment via SDK",
            from_account="acct_alpha_treasury",
        )
        assert result.decision == DecisionType.BLOCK
        assert any("tenant boundary violation" in r.lower() for r in result.receipt.reasons)

    def test_sdk_rejects_tenant_id_in_context(self):
        """SDK client rejects intent with 'tenant_id' in context dictionary."""
        from finguard.agent_sdk import FinGuardAgentClient

        client = FinGuardAgentClient(actor_id="treasury-agent", session_id="sdk-spoof")
        result = client.create_transaction(
            amount="100.00",
            currency="INR",
            destination="vendor-a",
            purpose="test context spoofing",
            metadata={"tenant_id": "tenant_admin"},
        )
        # Should fail closed with BLOCK due to authority context key rejection
        assert result.decision == DecisionType.BLOCK
        assert any("authority-like" in r.lower() or "tenant" in r.lower() for r in result.receipt.reasons)

    def test_simulator_balances_remain_unmutated_on_cross_tenant_rejection(
        self, multi_tenant_setup
    ):
        """Cross-tenant transaction rejection produces 0 balance changes in simulator."""
        from finguard.simulator.service import FinancialSimulator, SimulatorError

        sim = FinancialSimulator()
        sim.bootstrap()
        initial_balances = {b["account_id"]: b["balance_minor"] for b in sim.balances()}

        engine, _, _ = multi_tenant_setup
        tx = Transaction(
            actor_id="agent-alpha",
            from_account="acct_beta_treasury",
            to_account="acct_alpha_vendor",
            amount=Money.from_decimal("500.00", Currency.INR),
        )
        res = engine.decide(tx)
        assert res.decision == DecisionType.BLOCK

        # Simulator balances must be completely unchanged
        current_balances = {b["account_id"]: b["balance_minor"] for b in sim.balances()}
        assert current_balances == initial_balances

        # Direct execution attempt of rejected transaction must fail closed
        with pytest.raises(SimulatorError):
            sim.execute(tx.transaction_id)

    def test_cross_tenant_retry_preserves_rejection(self, multi_tenant_setup):
        """Duplicate and retry requests preserve the same strict tenant boundary enforcement."""
        engine, _, _ = multi_tenant_setup
        tx = Transaction(
            actor_id="agent-alpha",
            from_account="acct_beta_treasury",
            to_account="acct_alpha_vendor",
            amount=Money.from_decimal("100.00", Currency.INR),
            idempotency_key="idemp_cross_tenant_retry_1",
        )
        res1 = engine.decide(tx)
        assert res1.decision == DecisionType.BLOCK
        assert any("tenant boundary violation" in r.lower() for r in res1.receipt.reasons)

        # Retry with identical payload
        res2 = engine.decide(tx)
        assert res2.decision == DecisionType.BLOCK
        assert any("tenant boundary violation" in r.lower() for r in res2.receipt.reasons)
