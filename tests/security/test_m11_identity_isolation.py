"""Security test suite for M11: Identity, Tenant Isolation & Account Disambiguation."""

import pytest

from finguard.core.enums import ActorType, Currency, DecisionType
from finguard.core.errors import SecurityError
from finguard.core.transaction import Transaction
from finguard.decision.engine import DecisionEngine
from finguard.identity.account_registry import (
    AccountConfig,
    AccountRegistry,
    ResolutionStatus,
    normalize_alias,
)
from finguard.identity.registry import ActorConfig, IdentityRegistry
from finguard.money import Money


def test_m11_alias_nfkc_and_casefold_normalization():
    # NFKC normalizes full-width characters and casefolds to lowercase
    alias = "ＶＥＮＤＯＲ-Ａ"
    norm = normalize_alias(alias)
    assert norm == "vendor-a"


def test_m11_zero_width_and_control_character_rejection():
    # Reject zero-width space \u200b in account alias
    bad_alias = "vendor\u200ba"
    with pytest.raises(SecurityError, match="forbidden control or zero-width character"):
        normalize_alias(bad_alias)


def test_m11_mixed_script_homoglyph_rejection():
    # Cyrillic 'а' mixed with Latin 'vendor-a'
    homoglyph_alias = "vendor-а"  # 'а' is U+0430
    with pytest.raises(SecurityError, match="mixed-script characters"):
        normalize_alias(homoglyph_alias)


def test_m11_account_registry_alias_resolution():
    registry = AccountRegistry()
    res = registry.resolve_account("vendor-a")
    assert res.status == ResolutionStatus.RESOLVED
    assert res.account_id == "acct_vendor_a"
    assert res.currency == Currency.INR


def test_m11_ambiguous_alias_rejection():
    registry = AccountRegistry()
    # Register two accounts sharing an ambiguous alias
    registry.register_account(
        AccountConfig(
            account_id="acct_ambig_1",
            tenant_id="tenant_1",
            display_name="Ambiguous 1",
            aliases=["shared_vendor"],
        )
    )
    registry.register_account(
        AccountConfig(
            account_id="acct_ambig_2",
            tenant_id="tenant_2",
            display_name="Ambiguous 2",
            aliases=["shared_vendor"],
        )
    )

    res = registry.resolve_account("shared_vendor")
    assert res.status == ResolutionStatus.AMBIGUOUS_ALIAS
    assert res.account is None


def test_m11_tenant_boundary_validation():
    registry = AccountRegistry()
    registry.register_account(
        AccountConfig(
            account_id="acct_tenant_a",
            tenant_id="tenant_alpha",
            display_name="Tenant Alpha Treasury",
        )
    )

    valid, _reason = registry.validate_tenant_boundary(
        actor_tenant_id="tenant_alpha",
        from_account_id="acct_tenant_a",
        to_account_id="acct_vendor_a",
    )
    assert valid is True

    # Cross-tenant violation: tenant_beta attempting to spend from tenant_alpha account
    valid_cross, reason_cross = registry.validate_tenant_boundary(
        actor_tenant_id="tenant_beta",
        from_account_id="acct_tenant_a",
        to_account_id="acct_vendor_a",
    )
    assert valid_cross is False
    assert "Tenant boundary violation" in reason_cross


def test_m11_transaction_blocks_zero_width_destination():
    # Attempting to construct a Transaction with zero-width space raises ValidationError at domain model boundary
    with pytest.raises(Exception, match="Control and format characters are forbidden"):
        Transaction(
            actor_id="treasury-agent",
            from_account="acct_treasury",
            to_account="vendor\u200b-a",
            amount=Money.from_decimal("500.00", Currency.INR),
        )


def test_m11_agent_wildcard_source_and_destination_forbidden(tmp_path):
    id_registry = IdentityRegistry(data_dir=tmp_path)
    root_key_path = tmp_path / "root_operator.key"

    # Register an agent with wildcard destination authority
    wildcard_agent = ActorConfig(
        actor_id="wildcard-agent",
        actor_type=ActorType.AGENT,
        display_name="Wildcard Agent",
        authority_limit="10000.00",
        allowed_destinations=["*"],
        allowed_source_accounts=["acct_treasury"],
    )
    id_registry.register_actor(wildcard_agent, root_key_path)

    engine = DecisionEngine(registry=id_registry)
    tx = Transaction(
        actor_id="wildcard-agent",
        from_account="acct_treasury",
        to_account="acct_vendor_a",
        amount=Money.from_decimal("100.00", Currency.INR),
    )

    result = engine.decide(tx)
    assert result.decision == DecisionType.BLOCK
    assert "Destination is not explicitly authorized" in result.receipt.reasons
