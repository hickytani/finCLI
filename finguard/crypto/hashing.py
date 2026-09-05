"""Cryptographic hashing utilities for FIN//GUARD.

Uses SHA-256 for canonical transaction hashing and digest computations.
"""

import hashlib


def sha256_hash(data: bytes) -> str:
    """Compute the SHA-256 hex digest of the given bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_chain_entry(entry_bytes: bytes, previous_hash: str) -> str:
    """Compute a hash chain entry digest linking to the previous hash.

    SHA-256(entry_bytes + previous_hash.encode('utf-8'))
    """
    hasher = hashlib.sha256()
    hasher.update(entry_bytes)
    hasher.update(previous_hash.encode("utf-8"))
    return hasher.hexdigest()
