"""FIN//GUARD configuration.

Centralized configuration using Pydantic settings. All paths default to
a local data directory to keep the system self-contained and runnable
without external infrastructure.
"""

import os
from pathlib import Path

from pydantic_settings import BaseSettings
from pydantic import Field


def _default_data_dir() -> Path:
    """Resolve the FIN//GUARD data directory.

    Priority:
    1. FINGUARD_DATA_DIR environment variable
    2. .finguard/ in the current working directory
    """
    env = os.environ.get("FINGUARD_DATA_DIR")
    if env:
        return Path(env)
    return Path.cwd() / ".finguard"


class FinguardConfig(BaseSettings):
    """Application configuration.

    All sensitive defaults are restrictive (fail-closed).
    """

    model_config = {"env_prefix": "FINGUARD_"}

    # Paths
    data_dir: Path = Field(default_factory=_default_data_dir)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "finguard.db"

    @property
    def keystore_dir(self) -> Path:
        return self.data_dir / "keys"

    @property
    def audit_dir(self) -> Path:
        return self.data_dir / "audit"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def incidents_dir(self) -> Path:
        return self.data_dir / "incidents"

    # Security defaults
    log_level: str = "INFO"
    default_policy_path: str = "policies/default.yaml"
    operating_hours_start: int = 9   # 09:00
    operating_hours_end: int = 18    # 18:00
    velocity_window_seconds: int = 600  # 10 minutes
    velocity_max_count: int = 5
    velocity_max_amount: int = 100000  # INR

    def ensure_dirs(self) -> None:
        """Create all required data directories."""
        for d in [self.data_dir, self.keystore_dir, self.audit_dir,
                  self.evidence_dir, self.incidents_dir]:
            d.mkdir(parents=True, exist_ok=True)


# Singleton config instance
_config: FinguardConfig | None = None


def get_config() -> FinguardConfig:
    """Get or create the global configuration."""
    global _config
    if _config is None:
        _config = FinguardConfig()
    return _config


def reset_config() -> None:
    """Reset config (for testing)."""
    global _config
    _config = None
