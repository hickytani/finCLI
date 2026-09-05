"""Ed25519 cryptographic signing engine for FIN//GUARD.

SECURITY PROPERTIES:
- Uses Ed25519 signatures (RFC 8032) via the standard `cryptography` library.
- Signatures bind to canonical transaction bytes.
- Verification is deterministic and constant-time against forged signatures.
- Fails closed on invalid key bytes or malformed signatures.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from finguard.core.errors import IntegrityError, KeystoreError


def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a new Ed25519 keypair using secure randomness."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_canonical_bytes(data: bytes, private_key: ed25519.Ed25519PrivateKey) -> str:
    """Sign canonical data bytes using an Ed25519 private key.

    Returns the signature as a hex-encoded string.
    """
    signature_bytes = private_key.sign(data)
    return signature_bytes.hex()


def verify_signature(data: bytes, signature_hex: str, public_key_bytes: bytes) -> bool:
    """Verify an Ed25519 signature against canonical data bytes and public key bytes.

    Args:
        data: Canonical byte payload that was signed.
        signature_hex: Hex-encoded signature string.
        public_key_bytes: Raw 32-byte Ed25519 public key.

    Returns:
        True if signature is valid.

    Raises:
        IntegrityError: If signature verification fails or signature is malformed.
    """
    try:
        sig_bytes = bytes.fromhex(signature_hex)
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub_key.verify(sig_bytes, data)
        return True
    except (InvalidSignature, ValueError) as e:
        raise IntegrityError(f"Signature verification failed: {e}") from e


def public_key_to_hex(public_key: ed25519.Ed25519PublicKey) -> str:
    """Serialize an Ed25519 public key to hex format."""
    from cryptography.hazmat.primitives import serialization
    bytes_data = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return bytes_data.hex()


def public_key_from_hex(pub_hex: str) -> ed25519.Ed25519PublicKey:
    """Deserialize an Ed25519 public key from hex format."""
    try:
        raw_bytes = bytes.fromhex(pub_hex)
        return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)
    except ValueError as e:
        raise KeystoreError(f"Invalid public key hex format: {e}") from e
