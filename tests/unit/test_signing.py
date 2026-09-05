"""Unit tests for Ed25519 signing and verification."""

import pytest
from finguard.crypto.signing import generate_keypair, sign_canonical_bytes, verify_signature, public_key_to_hex
from finguard.core.errors import IntegrityError


def test_signing_and_verifying_valid():
    priv, pub = generate_keypair()
    pub_bytes = bytes.fromhex(public_key_to_hex(pub))
    data = b"canonical-transaction-bytes-12345"

    sig_hex = sign_canonical_bytes(data, priv)
    assert verify_signature(data, sig_hex, pub_bytes) is True


def test_signature_fails_if_data_modified():
    priv, pub = generate_keypair()
    pub_bytes = bytes.fromhex(public_key_to_hex(pub))
    data = b"original-bytes"
    modified_data = b"tampered-bytes"

    sig_hex = sign_canonical_bytes(data, priv)
    with pytest.raises(IntegrityError):
        verify_signature(modified_data, sig_hex, pub_bytes)


def test_signature_fails_if_wrong_public_key():
    priv1, pub1 = generate_keypair()
    priv2, pub2 = generate_keypair()
    pub2_bytes = bytes.fromhex(public_key_to_hex(pub2))
    data = b"original-bytes"

    sig_hex = sign_canonical_bytes(data, priv1)
    with pytest.raises(IntegrityError):
        verify_signature(data, sig_hex, pub2_bytes)
