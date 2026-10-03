"""Canonical serialization for FIN//GUARD (v1 legacy & v2 domain-separated).

SECURITY PROPERTY:
- The same logical transaction must always produce the same canonical byte representation.
- v2 canonical serialization uses integer minor units (amount_minor) and a domain separation prefix:
  b"finguard.tx.v2\x00" + UTF-8(sorted_keys_compact_json).
- v1 legacy verification is preserved for historical receipts, but new signatures require v2.
"""

import datetime
import decimal
import json
import uuid
from enum import Enum
from typing import Any

from finguard.core.errors import CanonicalizationError

DOMAIN_PREFIX_V2 = b"finguard.tx.v2\x00"


class CanonicalEncoder(json.JSONEncoder):
    """JSON encoder that produces deterministic output for all FIN//GUARD types."""

    normalize_aware_datetime_to_utc = False

    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime.datetime):
            if obj.tzinfo is None:
                obj = obj.replace(tzinfo=datetime.UTC)
            elif self.normalize_aware_datetime_to_utc:
                obj = obj.astimezone(datetime.UTC)
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


class CanonicalV2Encoder(CanonicalEncoder):
    """Encoder that normalizes aware timestamps without changing legacy v1 bytes."""

    normalize_aware_datetime_to_utc = True


def canonical_serialize_v1(data: dict) -> bytes:
    """Legacy v1 canonical serialization (raw compact sorted JSON)."""
    canonical_json = json.dumps(
        data,
        cls=CanonicalEncoder,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return canonical_json.encode("utf-8")


def canonical_serialize_v2(data: dict) -> bytes:
    """Canonical v2 serialization with domain separation prefix.

    Preimage: b"finguard.tx.v2\\x00" + UTF-8(sorted_keys_compact_json)
    """
    canonical_json = json.dumps(
        data,
        cls=CanonicalV2Encoder,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return DOMAIN_PREFIX_V2 + canonical_json.encode("utf-8")


def canonical_serialize(data: dict, version: int = 2) -> bytes:
    """Produce deterministic canonical bytes from a dictionary for a given canonical version."""
    if version == 1:
        return canonical_serialize_v1(data)
    elif version == 2:
        return canonical_serialize_v2(data)
    else:
        raise CanonicalizationError(f"Unsupported canonical version: {version}")


def canonical_amount(amount: str | int | decimal.Decimal) -> str:  # legacy v1 representation only
    """Legacy v1 amount formatter (quantizes float to 2dp string)."""
    d = decimal.Decimal(str(amount)).quantize(decimal.Decimal("0.01"))
    return str(d)
