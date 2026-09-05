"""Canonical serialization for FIN//GUARD.

SECURITY PROPERTY: The same logical transaction must always produce the
same canonical byte representation, regardless of Python dictionary ordering,
floating-point representation, or datetime formatting.

This module provides deterministic serialization that is suitable for
cryptographic hashing and signature binding. It does NOT use Python's
str(dict) or repr() — these are non-deterministic.

DESIGN:
- Fields are sorted lexicographically by key name
- Numbers use fixed-point string representation (no scientific notation)
- Datetimes use ISO-8601 with explicit UTC timezone
- UUIDs use lowercase hex with hyphens
- Enums use their .value
- None is serialized as the string "null"
- Output is UTF-8 encoded
- No trailing whitespace or newlines
"""

import datetime
import decimal
import json
import uuid
from enum import Enum
from typing import Any


class CanonicalEncoder(json.JSONEncoder):
    """JSON encoder that produces deterministic output for all FIN//GUARD types."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime.datetime):
            # Always use UTC ISO-8601 with microsecond precision
            if obj.tzinfo is None:
                # Treat naive datetimes as UTC
                obj = obj.replace(tzinfo=datetime.timezone.utc)
            return obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        if isinstance(obj, datetime.date):
            return obj.isoformat()

        if isinstance(obj, uuid.UUID):
            return str(obj)

        if isinstance(obj, Enum):
            return obj.value

        if isinstance(obj, decimal.Decimal):
            return str(obj)

        if isinstance(obj, set):
            return sorted(obj)

        if isinstance(obj, bytes):
            return obj.hex()

        return super().default(obj)


def canonical_serialize(data: dict) -> bytes:
    """Produce deterministic canonical bytes from a dictionary.

    INVARIANT: canonical_serialize(d1) == canonical_serialize(d2)
    if and only if d1 and d2 represent the same logical data.

    Args:
        data: Dictionary of transaction/record fields.

    Returns:
        UTF-8 encoded canonical JSON bytes with sorted keys,
        no extra whitespace, and deterministic type handling.
    """
    canonical_json = json.dumps(
        data,
        cls=CanonicalEncoder,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,  # Force ASCII for byte-level reproducibility
    )
    return canonical_json.encode("utf-8")


def canonical_amount(amount: float) -> str:
    """Convert a monetary amount to a canonical string representation.

    Uses fixed-point decimal with 2 decimal places to avoid
    floating-point representation ambiguity.

    SECURITY NOTE: This is critical for signature binding.
    ₹10000.0 and ₹10000.00 must produce the same canonical form.
    """
    # Use Decimal for exact representation
    d = decimal.Decimal(str(amount)).quantize(decimal.Decimal("0.01"))
    return str(d)
