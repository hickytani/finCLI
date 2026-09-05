"""Encrypted software keystore for FIN//GUARD.

FLOW:
  password → Argon2id → derived key → AES-256-GCM → encrypted private key file.

SECURITY PROPERTIES:
- Only encrypted private key material is stored on disk.
- Plaintext private keys never touch persistent disk.
- Password material and unlocked key material are held in volatile process memory only.
- Limitation: Standard Python interpreter memory management does not support guaranteed memory zeroization.
"""

import json
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from finguard.core.config import get_config
from finguard.core.errors import KeystoreError
from finguard.crypto.encryption import derive_key_argon2id, encrypt_aes_gcm, decrypt_aes_gcm
from finguard.crypto.signing import generate_keypair, public_key_to_hex
from finguard.storage.database import get_session
from finguard.storage.models import KeyRecord
from finguard.storage.repositories import KeyRepository


class Keystore:
    """Manages encrypted keypair storage and retrieval."""

    def __init__(self, storage_dir: Path | None = None):
        self.storage_dir = storage_dir or get_config().keystore_dir
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _key_file_path(self, key_id: str) -> Path:
        return self.storage_dir / f"{key_id}.json"

    def create_keypair(self, key_id: str, password: str) -> str:
        """Generate a new Ed25519 keypair, encrypt the private key with password, and store on disk."""
        return self._create_keypair_impl(key_id, password)

    def generate_keypair(self, key_id: str, password: str) -> str:
        """Alias for create_keypair."""
        return self._create_keypair_impl(key_id, password)

    def _create_keypair_impl(self, key_id: str, password: str) -> str:
        key_file = self._key_file_path(key_id)
        if key_file.exists():
            raise KeystoreError(f"Key ID '{key_id}' already exists")

        private_key, public_key = generate_keypair()

        # Serialize raw private key bytes
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        salt = os.urandom(16)
        derived_key = derive_key_argon2id(password, salt)
        nonce, ciphertext = encrypt_aes_gcm(priv_bytes, derived_key, associated_data=key_id.encode("utf-8"))

        pub_hex = public_key_to_hex(public_key)
        fingerprint = pub_hex[:16]

        payload = {
            "key_id": key_id,
            "algorithm": "Ed25519",
            "public_key_hex": pub_hex,
            "fingerprint": fingerprint,
            "salt_hex": salt.hex(),
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": ciphertext.hex()
        }

        with open(key_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        # Store metadata in DB
        session = get_session()
        try:
            repo = KeyRepository(session)
            record = KeyRecord(
                key_id=key_id,
                public_key_hex=pub_hex,
                algorithm="Ed25519",
                fingerprint=fingerprint,
                active=True
            )
            repo.save(record)
        finally:
            session.close()

        return pub_hex

    def load_private_key(self, key_id: str, password: str) -> ed25519.Ed25519PrivateKey:
        """Decrypt and load an Ed25519 private key from disk.

        Args:
            key_id: Key identifier.
            password: User password.

        Returns:
            Decrypted Ed25519PrivateKey object.
        """
        key_file = self._key_file_path(key_id)
        if not key_file.exists():
            raise KeystoreError(f"Key ID '{key_id}' not found in keystore")

        try:
            with open(key_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            salt = bytes.fromhex(data["salt_hex"])
            nonce = bytes.fromhex(data["nonce_hex"])
            ciphertext = bytes.fromhex(data["ciphertext_hex"])

            derived_key = derive_key_argon2id(password, salt)
            priv_bytes = decrypt_aes_gcm(ciphertext, derived_key, nonce, associated_data=key_id.encode("utf-8"))

            return ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        except Exception as e:
            if isinstance(e, KeystoreError):
                raise
            raise KeystoreError(f"Failed to unlock key '{key_id}': invalid password or corrupt file") from e

    def get_public_key(self, key_id: str) -> str:
        """Retrieve the public key hex for a given key_id without asking for a password."""
        key_file = self._key_file_path(key_id)
        if not key_file.exists():
            # Try DB fallback
            session = get_session()
            try:
                record = KeyRepository(session).get(key_id)
                if record:
                    return record.public_key_hex
            finally:
                session.close()
            raise KeystoreError(f"Key ID '{key_id}' not found")

        with open(key_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data["public_key_hex"]

    def list_keys(self) -> list[dict]:
        """List all stored keys metadata."""
        keys = []
        for file_path in self.storage_dir.glob("*.json"):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                keys.append({
                    "key_id": data.get("key_id"),
                    "algorithm": data.get("algorithm", "Ed25519"),
                    "public_key_hex": data.get("public_key_hex"),
                    "fingerprint": data.get("fingerprint"),
                })
            except Exception:
                continue
        return keys
