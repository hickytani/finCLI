"""Pytest configuration and shared fixtures for FIN//GUARD."""

import pytest

from finguard.core.config import reset_config
from finguard.crypto.keystore import Keystore
from finguard.identity.registry import IdentityRegistry
from finguard.storage.database import init_db, reset_db


@pytest.fixture(autouse=True)
def setup_test_environment(tmp_path, monkeypatch):
    """Automatically configure isolated temporary data directory and DB for each test."""
    monkeypatch.setenv("FINGUARD_DATA_DIR", str(tmp_path / ".finguard"))
    reset_config()
    reset_db()
    init_db()
    yield
    reset_config()
    reset_db()


@pytest.fixture
def bind_actor_key():
    def bind(actor_id: str, key_id: str):
        registry = IdentityRegistry()
        actor = registry.get_actor(actor_id)
        assert actor is not None
        actor.public_key = Keystore().get_public_key(key_id)
        registry.register_actor(actor, registry.root_priv_path)
        return IdentityRegistry().get_actor(actor_id)

    return bind
