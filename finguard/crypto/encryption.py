"""AES-256-GCM encryption and Argon2id key derivation utilities.

SECURITY PROPERTIES:
- Key derivation uses Argon2id (memory-hard password hashing function).
- Symmetric encryption uses AES-256-GCM (authenticated encryption).
- Secret key material is never written to disk in plaintext.
- Documented limitation: Python memory cannot guarantee absolute secret zeroization.
"""

import os
from argon2 import PasswordHasher, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from finguard.core.errors import KeystoreError


def derive_key_argon2id(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit symmetric encryption key from a password using Argon2id.

    Args:
        password: User secret password string.
        salt: Cryptographically random salt (at least 16 bytes).

    Returns:
        32-byte (256-bit) raw key.
    """
    ph = PasswordHasher(
        time_cost=3,
        memory_cost=65536,  # 64 MB
        parallelism=4,
        hash_len=32,
        salt_len=len(salt),
        type=Type.ID
    )
    # Extract raw key using Argon2id hashing
    hash_str = ph.hash(password, salt=salt)
    # Re-derive raw bytes from password + salt deterministically via low-level argon2
    import argon2.low_level as ll
    return ll.hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=ll.Type.ID
    )


def encrypt_aes_gcm(plaintext: bytes, key: bytes, associated_data: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM.

    Args:
        plaintext: Raw data to encrypt.
        key: 32-byte symmetric key.
        associated_data: Optional authenticated data.

    Returns:
        Tuple of (nonce [12 bytes], ciphertext_with_tag).
    """
    if len(key) != 32:
        raise KeystoreError("AES-256 key must be exactly 32 bytes")
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, associated_data: bytes | None = None) -> bytes:
    """Decrypt ciphertext using AES-256-GCM.

    Args:
        ciphertext: Ciphertext payload including GCM authentication tag.
        key: 32-byte symmetric key.
        nonce: 12-byte nonce used during encryption.
        associated_data: Optional authenticated data.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        KeystoreError: If authentication tag check fails or parameters are invalid.
    """
    if len(key) != 32:
        raise KeystoreError("AES-256 key must be exactly 32 bytes")
    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except Exception as e:
        raise KeystoreError(f"Decryption failed or invalid password/tag: {e}") from e
