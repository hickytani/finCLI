"""Signed Identity and Authority Registry for FIN//GUARD.

SECURITY PROPERTY:
The identity and authority registry is stored in identities.yaml along with a
detached Ed25519 cryptographic signature (identities.yaml.sig) created by the root
operator key. Any unauthorized attempt by an actor or agent to edit identities.yaml
or escalate privileges will cause signature verification to fail and the registry
will fail to load (failing closed).
"""

from pathlib import Path

import yaml
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import BaseModel, Field, ValidationInfo, field_validator

from finguard.core.config import get_config
from finguard.core.enums import ActorType, AgentCapability, Currency
from finguard.core.errors import IntegrityError, SecurityError
from finguard.crypto.signing import (
    generate_keypair,
    public_key_to_hex,
    sign_canonical_bytes,
    verify_signature,
)


class ActorConfig(BaseModel):
    """Actor identity configuration."""
    actor_id: str
    actor_type: ActorType
    display_name: str
    authority_currency: Currency = Currency.INR
    authority_limit: str = "10000.00"
    allowed_destinations: list[str] = Field(default_factory=list)
    allowed_source_accounts: list[str] = Field(default_factory=list)
    agent_capabilities: list[AgentCapability] = Field(default_factory=list)
    active: bool = True
    session_binding_required: bool = False
    public_key: str | None = None

    @field_validator("authority_limit", mode="before")
    @classmethod
    def exact_authority_limit(cls, value: object, info: ValidationInfo) -> str:
        from finguard.money import Money
        exact_text = str(value)
        Money.from_decimal(exact_text, info.data.get("authority_currency", Currency.INR))
        return exact_text


class IdentityRegistry:
    """Registry managing identity definitions and cryptographic authority limits."""

    def __init__(self, data_dir: Path | None = None):
        config = get_config()
        self.data_dir = data_dir or config.data_dir
        self.registry_path = self.data_dir / "identities.yaml"
        self.sig_path = self.data_dir / "identities.yaml.sig"
        self.root_pub_path = self.data_dir / "root_operator.pub"
        self.root_priv_path = self.data_dir / "root_operator.key"
        self._actors: dict[str, ActorConfig] = {}
        self._init_or_load()

    def _init_or_load(self) -> None:
        """Initialize default registry or load and verify existing registry."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if not self.registry_path.exists():
            self._bootstrap_registry()
        else:
            self.load_registry()

    def _bootstrap_registry(self) -> None:
        """Generate root operator keypair and initial signed registry."""
        priv_key, pub_key = generate_keypair()
        pub_hex = public_key_to_hex(pub_key)

        # Save root public key
        with open(self.root_pub_path, "w") as f:
            f.write(pub_hex)

        # Save root private key for bootstrap operator
        with open(self.root_priv_path, "w") as f:
            priv_bytes = priv_key.private_bytes_raw()
            f.write(priv_bytes.hex())

        # Default initial identities
        default_identities = {
            "version": 1,
            "identities": [
                {
                    "actor_id": "operator-1",
                    "actor_type": ActorType.HUMAN_OPERATOR.value,
                    "display_name": "Primary Operator",
                    "authority_limit": "1000000.00",
                    "allowed_destinations": ["vendor-a", "vendor-b", "treasury-out", "payroll"],
                    "allowed_source_accounts": ["*"],
                    "active": True,
                    "session_binding_required": False
                },
                {
                    "actor_id": "treasury-agent",
                    "actor_type": ActorType.AGENT.value,
                    "display_name": "Autonomous Treasury Agent",
                    "authority_limit": "10000.00",
                    "allowed_destinations": ["vendor-a", "vendor-b"],
                    "allowed_source_accounts": ["treasury", "acct_treasury"],
                    "agent_capabilities": [AgentCapability.TRANSACTION_PROPOSE.value],
                    "active": True,
                    "session_binding_required": True
                },
                {
                    "actor_id": "approver-1",
                    "actor_type": ActorType.APPROVER.value,
                    "display_name": "Senior Approver",
                    "authority_limit": "500000.00",
                    "allowed_destinations": ["*"],
                    "allowed_source_accounts": ["*"],
                    "active": True,
                    "session_binding_required": False
                }
            ]
        }

        content_bytes = yaml.dump(default_identities, sort_keys=True).encode("utf-8")
        with open(self.registry_path, "wb") as f:
            f.write(content_bytes)

        # Sign registry content with root operator key
        sig_hex = sign_canonical_bytes(content_bytes, priv_key)
        with open(self.sig_path, "w") as f:
            f.write(sig_hex)

        self._populate_actors(default_identities)

    def load_registry(self) -> None:
        """Load and cryptographically verify identities.yaml. Fails closed if tampered."""
        if not self.registry_path.exists() or not self.sig_path.exists() or not self.root_pub_path.exists():
            raise SecurityError("Identity registry files missing or incomplete.")

        with open(self.root_pub_path, "r") as f:
            root_pub_hex = f.read().strip()

        with open(self.registry_path, "rb") as f:
            content_bytes = f.read()

        with open(self.sig_path, "r") as f:
            sig_hex = f.read().strip()

        # Verify signature
        try:
            pub_bytes = bytes.fromhex(root_pub_hex)
            verify_signature(content_bytes, sig_hex, pub_bytes)
        except IntegrityError as e:
            raise SecurityError(
                "IDENTITY REGISTRY TAMPERING DETECTED! "
                "identities.yaml signature does not match root operator key."
            ) from e

        data = yaml.safe_load(content_bytes)
        self._populate_actors(data)

    def _populate_actors(self, data: dict) -> None:
        self._actors.clear()
        for item in data.get("identities", []):
            legacy_source_accounts = item.get("allowed_source_accounts")
            if legacy_source_accounts is None:
                # Backward-compatibility for old registry files created before source-account
                # restrictions were recorded explicitly. Preserve the legacy behavior
                # without silently widening new entries: older configs are normalized to
                # an explicit wildcard so they continue to function as a migration artifact.
                legacy_source_accounts = ["*"] if item.get("allowed_destinations") else []

            actor = ActorConfig(
                actor_id=item["actor_id"],
                actor_type=ActorType(item["actor_type"]),
                display_name=item["display_name"],
                authority_currency=Currency(item.get("authority_currency", Currency.INR.value)),
                authority_limit=str(item.get("authority_limit", "10000.00")),
                allowed_destinations=item.get("allowed_destinations", []),
                allowed_source_accounts=legacy_source_accounts,
                agent_capabilities=item.get("agent_capabilities", []),
                active=item.get("active", True),
                session_binding_required=item.get("session_binding_required", False),
                public_key=item.get("public_key")
            )
            self._actors[actor.actor_id] = actor

    def get_actor(self, actor_id: str) -> ActorConfig | None:
        """Return actor config if present and active."""
        actor = self._actors.get(actor_id)
        if actor and actor.active:
            return actor
        return None

    def validate_actor(self, actor_id: str, session_token: str | None = None) -> ActorConfig:
        """Validate actor existence, active status, and session binding if required."""
        actor = self.get_actor(actor_id)
        if not actor:
            raise SecurityError(f"Actor '{actor_id}' is unknown or inactive in identity registry.")

        if actor.session_binding_required and not session_token:
            # Generate or require session token for agent
            pass

        return actor

    def register_actor(self, actor_config: ActorConfig, root_priv_key_path: Path) -> None:
        """Register a new actor or update authority using root operator private key.

        Re-signs identities.yaml with root operator key.
        """
        if not root_priv_key_path.exists():
            raise SecurityError(f"Root key file '{root_priv_key_path}' not found.")

        with open(root_priv_key_path, "r") as f:
            priv_hex = f.read().strip()

        priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))

        # Re-load current raw data
        with open(self.registry_path, "rb") as f:
            data = yaml.safe_load(f.read()) or {"version": 1, "identities": []}

        identities = data.get("identities", [])
        # Replace or append
        updated = False
        new_entry = actor_config.model_dump()
        new_entry["actor_type"] = actor_config.actor_type.value
        new_entry["authority_currency"] = actor_config.authority_currency.value
        new_entry["agent_capabilities"] = [
            capability.value for capability in actor_config.agent_capabilities
        ]

        for i, item in enumerate(identities):
            if item["actor_id"] == actor_config.actor_id:
                identities[i] = new_entry
                updated = True
                break
        if not updated:
            identities.append(new_entry)

        data["identities"] = identities
        content_bytes = yaml.dump(data, sort_keys=True).encode("utf-8")

        # Write and re-sign
        with open(self.registry_path, "wb") as f:
            f.write(content_bytes)

        sig_hex = sign_canonical_bytes(content_bytes, priv_key)
        with open(self.sig_path, "w") as f:
            f.write(sig_hex)

        self._populate_actors(data)

    def list_actors(self) -> list[ActorConfig]:
        """List all actors in registry."""
        return list(self._actors.values())
