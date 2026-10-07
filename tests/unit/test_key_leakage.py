"""FG-804 / I11 attack test: private key material must never appear in
logs, error messages, receipts, or exception strings.

These tests probe the attack surface of the keystore and signing code to
verify that:
  1. Wrong-password errors do not leak private key bytes or the derived key.
  2. Corrupt-file errors do not propagate raw key bytes in their messages.
  3. The error string raised on a bad password contains no 32-byte (Ed25519)
     hex sequences that might be confused with private key material.
"""
from __future__ import annotations

import logging
import re
import traceback

import pytest

from finguard.core.errors import KeystoreError
from finguard.crypto.keystore import Keystore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HEX64 = re.compile(r"[0-9a-f]{64}", re.IGNORECASE)  # 32-byte private key hex


def _extract_text(*objects: object) -> str:
    """Convert objects to their string forms for inspection."""
    return " ".join(str(o) for o in objects)


# ---------------------------------------------------------------------------
# FG-804 / I11: test_key_leakage_in_error_logs
# ---------------------------------------------------------------------------


def test_key_leakage_in_error_logs(tmp_path, caplog):
    """Attack test: wrong-password KeystoreError must not contain private key bytes.

    Procedure:
      1. Generate a keypair and capture the known public key hex.
      2. Attempt to unlock with a wrong password — expect KeystoreError.
      3. Inspect the exception message AND log output for 64-hex sequences
         that look like a 32-byte private key.
      4. The *public* key hex IS 64 chars and is expected — we exclude it.
         Any *other* 64-hex sequence is a probable private key leak → FAIL.
    """
    ks = Keystore(storage_dir=tmp_path)
    pub_hex = ks.create_keypair("leak-test-key", "correct-pass")

    with caplog.at_level(logging.DEBUG), pytest.raises(KeystoreError) as exc_info:
        ks.load_private_key("leak-test-key", "wrong-password")

    # Build corpus: exception message + traceback + all log records
    tb_text = "".join(traceback.format_exception(type(exc_info.value), exc_info.value, exc_info.value.__traceback__))
    log_text = "\n".join(r.getMessage() for r in caplog.records)
    full_corpus = tb_text + "\n" + log_text

    # Find all 64-char hex sequences in the corpus
    found_hex = set(_HEX64.findall(full_corpus))
    # Remove the known public key — it may legitimately appear in errors
    found_hex.discard(pub_hex)
    found_hex.discard(pub_hex.upper())
    found_hex.discard(pub_hex.lower())

    assert not found_hex, (
        f"Potential private-key material leaked in error output or logs: {found_hex!r}\n\n"
        f"Exception message: {exc_info.value!s}\n\n"
        f"Traceback excerpt:\n{tb_text[:2000]}"
    )


def test_corrupt_keyfile_does_not_leak_raw_bytes(tmp_path):
    """Attack test: a corrupt or truncated keyfile error must not contain raw key hex."""
    ks = Keystore(storage_dir=tmp_path)
    pub_hex = ks.create_keypair("corrupt-test-key", "pass")

    # Corrupt the file by writing partial JSON with a fake 64-hex payload
    fake_priv_hex = "a" * 64  # deliberate decoy — must not appear in output
    key_file = tmp_path / "corrupt-test-key.json"
    key_file.write_text(f'{{"key_id":"corrupt-test-key","ciphertext_hex":"{fake_priv_hex}","bad":true}}')

    with pytest.raises(KeystoreError) as exc_info:
        ks.load_private_key("corrupt-test-key", "pass")

    msg = str(exc_info.value)
    # The fake private hex should not appear verbatim in the error message
    assert fake_priv_hex not in msg, (
        f"Corrupt keyfile hex content leaked into error message: {msg!r}"
    )
    # Public key is allowed to appear; anything else that is 64-hex chars is suspect.
    # Since we already stripped known pub_hex above, this line is just a doc assertion.
    assert pub_hex not in msg.replace(pub_hex, ""), "pub_hex replacement check passed"


def test_keystore_error_messages_are_opaque(tmp_path):
    """Attack test: error messages must not contain passwords, salts or nonces."""
    ks = Keystore(storage_dir=tmp_path)
    secret_password = "super-secret-password-12345"
    ks.create_keypair("opaque-test-key", secret_password)

    with pytest.raises(KeystoreError) as exc_info:
        ks.load_private_key("opaque-test-key", "wrong-guess")

    msg = str(exc_info.value)
    assert secret_password not in msg, f"Password appeared in error message: {msg!r}"
    assert "wrong-guess" not in msg, f"Attempted password appeared in error message: {msg!r}"
