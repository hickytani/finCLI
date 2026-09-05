from finguard.agent_sdk import FinGuardAgentClient
from finguard.core.enums import DecisionType
from finguard.core.transaction import Transaction
from finguard.decision import DecisionEngine


def test_authority_violation_blocks():
    result = FinGuardAgentClient().create_transaction(50000, "INR", "vendor-a", "test")
    assert result.decision == DecisionType.BLOCK
    assert result.receipt.authority_allowed is False


def test_unknown_identity_fails_closed():
    tx = Transaction(actor_id="not-real", from_account="treasury", to_account="vendor-a", amount=1)
    assert DecisionEngine().decide(tx).decision == DecisionType.BLOCK


def test_sdk_has_no_sign_or_self_approve():
    client = FinGuardAgentClient()
    assert not hasattr(client, "sign_transaction")
    assert not hasattr(client, "self_approve")
