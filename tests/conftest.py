"""Pytest configuration and shared fixtures for FIN//GUARD."""

import pytest
from finguard.core.config import get_config, reset_config
from finguard.storage.database import init_db, reset_db, get_engine


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
