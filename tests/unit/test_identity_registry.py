"""Unit tests for signed identity registry."""

import pytest
from pathlib import Path
from finguard.core.enums import ActorType
from finguard.core.errors import SecurityError
from finguard.identity.registry import IdentityRegistry, ActorConfig


def test_identity_registry_bootstrap_and_load(tmp_path: Path):
    registry = IdentityRegistry(data_dir=tmp_path)
    op = registry.get_actor("operator-1")
    assert op is not None
    assert op.actor_type == ActorType.HUMAN_OPERATOR
    assert op.authority_limit == 1000000.0

    agent = registry.get_actor("treasury-agent")
    assert agent is not None
    assert agent.actor_type == ActorType.AGENT
    assert agent.authority_limit == 10000.0


def test_identity_registry_tamper_detection(tmp_path: Path):
    registry = IdentityRegistry(data_dir=tmp_path)
    yaml_path = tmp_path / "identities.yaml"

    # Tamper with authority limit in identities.yaml
    content = yaml_path.read_text(encoding="utf-8")
    tampered_content = content.replace("10000.0", "9999999.0")
    yaml_path.write_text(tampered_content, encoding="utf-8")

    # Reloading should fail closed due to signature mismatch
    with pytest.raises(SecurityError, match="IDENTITY REGISTRY TAMPERING DETECTED"):
        registry.load_registry()


def test_identity_registry_register_actor(tmp_path: Path):
    registry = IdentityRegistry(data_dir=tmp_path)
    root_key_path = tmp_path / "root_operator.key"

    new_actor = ActorConfig(
        actor_id="new-agent",
        actor_type=ActorType.AGENT,
        display_name="New Agent",
        authority_limit=5000.0,
        allowed_destinations=["vendor-a"]
    )

    registry.register_actor(new_actor, root_key_path)

    # Verify registered
    fetched = registry.get_actor("new-agent")
    assert fetched is not None
    assert fetched.authority_limit == 5000.0

    # Verify signature passes
    registry.load_registry()
