"""YAML Policy parser and validator for FIN//GUARD.

SECURITY PROPERTY:
- Invalid policy configuration MUST fail safe (raise exception and block execution).
- Never allow a malformed or unvalidated policy to default to permissive execution.
"""

from pathlib import Path
import yaml

from finguard.core.errors import ConfigurationError
from finguard.policy.schema import PolicyConfig


def load_policy_from_yaml(policy_path: str | Path) -> PolicyConfig:
    """Load and validate a YAML policy file.

    Args:
        policy_path: File system path to the YAML policy file.

    Returns:
        Validated PolicyConfig model instance.

    Raises:
        ConfigurationError: If the policy file does not exist, is invalid YAML, or fails schema validation.
    """
    path = Path(policy_path)
    if not path.exists():
        raise ConfigurationError(f"Policy file '{path}' does not exist")

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f)

        if not isinstance(raw_data, dict):
            raise ConfigurationError(f"Policy file '{path}' must contain a YAML object/dictionary")

        return PolicyConfig.model_validate(raw_data)
    except yaml.YAMLError as e:
        raise ConfigurationError(f"YAML syntax error in '{path}': {e}") from e
    except Exception as e:
        if isinstance(e, ConfigurationError):
            raise
        raise ConfigurationError(f"Policy validation failed for '{path}': {e}") from e
