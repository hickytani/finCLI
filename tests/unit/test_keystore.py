"""Unit tests for encrypted software keystore."""

import pytest
from finguard.crypto.keystore import Keystore
from finguard.core.errors import KeystoreError


def test_keystore_generate_and_unlock(tmp_path):
    ks = Keystore(storage_dir=tmp_path)
    pub_hex = ks.create_keypair("test-key", "secret-passphrase")
    assert len(pub_hex) == 64  # Ed25519 public key hex length

    priv_key = ks.load_private_key("test-key", "secret-passphrase")
    assert priv_key is not None


def test_keystore_wrong_password_fails(tmp_path):
    ks = Keystore(storage_dir=tmp_path)
    ks.create_keypair("test-key", "correct-passphrase")

    with pytest.raises(KeystoreError):
        ks.load_private_key("test-key", "wrong-passphrase")


def test_keystore_duplicate_key_id_fails(tmp_path):
    ks = Keystore(storage_dir=tmp_path)
    ks.create_keypair("dup-key", "pass")
    with pytest.raises(KeystoreError):
        ks.create_keypair("dup-key", "pass")
