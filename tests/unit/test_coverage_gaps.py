"""Tests for production modules with low branch coverage.

These tests target uncovered branches in security-relevant modules:
crypto/hashing, policy/parser, core/canonical, evaluation/wilson,
redteam/coverage, and core/errors. Each test exercises meaningful
production logic rather than trivially inflating coverage numbers.
"""

from __future__ import annotations

import datetime
import decimal
import json
import uuid
from enum import Enum
from pathlib import Path

import pytest
import yaml

from finguard.core.canonical import (
    DOMAIN_PREFIX_V2,
    CanonicalEncoder,
    CanonicalV2Encoder,
    canonical_amount,
    canonical_serialize,
    canonical_serialize_v1,
    canonical_serialize_v2,
)
from finguard.core.errors import (
    AuditIntegrityError,
    CanonicalizationError,
    ConfigurationError,
    PolicyViolationError,
)
from finguard.crypto.hashing import hash_chain_entry, sha256_hash
from finguard.evaluation.wilson import wilson_interval
from finguard.policy.parser import load_policy_from_yaml
from finguard.redteam.coverage import ATTACK_COVERAGE, coverage_by_id

# ---------------------------------------------------------------------------
# crypto/hashing - hash_chain_entry (50% -> 100%)
# ---------------------------------------------------------------------------


class TestHashChainEntry:
    """Test the hash chain entry computation used by the audit ledger."""

    def test_chain_entry_links_previous_hash(self):
        """hash_chain_entry must combine entry bytes with the previous hash."""
        entry = b"some audit entry"
        prev = "0" * 64
        result = hash_chain_entry(entry, prev)
        assert isinstance(result, str)
        assert len(result) == 64  # SHA-256 hex length

    def test_chain_entry_differs_with_different_prev_hash(self):
        """Changing the previous hash must change the output (no collisions)."""
        entry = b"payload"
        h1 = hash_chain_entry(entry, "a" * 64)
        h2 = hash_chain_entry(entry, "b" * 64)
        assert h1 != h2

    def test_chain_entry_differs_with_different_entry(self):
        """Changing the entry bytes must change the output."""
        prev = sha256_hash(b"genesis")
        h1 = hash_chain_entry(b"entry_1", prev)
        h2 = hash_chain_entry(b"entry_2", prev)
        assert h1 != h2

    def test_sha256_hash_deterministic(self):
        """sha256_hash must return the same digest for the same input."""
        data = b"finguard test"
        assert sha256_hash(data) == sha256_hash(data)


# ---------------------------------------------------------------------------
# policy/parser - all branches (54% -> ~100%)
# ---------------------------------------------------------------------------


class TestPolicyParser:
    """Test YAML policy loading with fail-safe error handling."""

    def test_missing_file_raises_configuration_error(self, tmp_path: Path):
        """Non-existent policy file must raise ConfigurationError."""
        missing = tmp_path / "nonexistent.yaml"
        with pytest.raises(ConfigurationError, match="does not exist"):
            load_policy_from_yaml(missing)

    def test_non_dict_yaml_raises_configuration_error(self, tmp_path: Path):
        """YAML that deserializes to a list (not dict) must be rejected."""
        policy_file = tmp_path / "bad.yaml"
        policy_file.write_text("- item1\n- item2\n", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="YAML object/dictionary"):
            load_policy_from_yaml(policy_file)

    def test_invalid_yaml_syntax_raises_configuration_error(self, tmp_path: Path):
        """Malformed YAML must raise ConfigurationError."""
        policy_file = tmp_path / "malformed.yaml"
        policy_file.write_text("{{invalid:\nyaml: [", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="YAML syntax error"):
            load_policy_from_yaml(policy_file)

    def test_schema_validation_failure_raises_configuration_error(self, tmp_path: Path):
        """Valid YAML that fails Pydantic schema validation must raise ConfigurationError."""
        policy_file = tmp_path / "bad_schema.yaml"
        policy_file.write_text(
            yaml.dump({"unknown_field": "value", "version": "not_an_int"}),
            encoding="utf-8",
        )
        with pytest.raises(ConfigurationError):
            load_policy_from_yaml(policy_file)


# ---------------------------------------------------------------------------
# core/canonical - uncovered encoder branches (57% -> ~85%+)
# ---------------------------------------------------------------------------


class TestCanonicalEncoder:
    """Test CanonicalEncoder type handling for deterministic serialization."""

    def test_encodes_datetime_with_utc(self):
        """Naive datetime gets UTC timezone and canonical format."""
        dt = datetime.datetime(2026, 1, 1, 0, 0, 0)  # noqa: DTZ001
        result = json.dumps({"ts": dt}, cls=CanonicalEncoder)
        assert "2026-01-01T00:00:00.000000Z" in result

    def test_encodes_aware_datetime(self):
        """Aware datetime is serialized correctly."""
        dt = datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.UTC)
        result = json.dumps({"ts": dt}, cls=CanonicalEncoder)
        assert "2026-01-01T12:00:00.000000Z" in result

    def test_encodes_date(self):
        """date objects use isoformat."""
        d = datetime.date(2026, 6, 15)
        result = json.dumps({"d": d}, cls=CanonicalEncoder)
        assert "2026-06-15" in result

    def test_encodes_uuid(self):
        """UUID objects are serialized as strings."""
        u = uuid.UUID("12345678-1234-5678-1234-567812345678")
        result = json.dumps({"id": u}, cls=CanonicalEncoder)
        assert "12345678-1234-5678-1234-567812345678" in result

    def test_encodes_enum(self):
        """Enum values are serialized using their .value."""

        class Color(Enum):
            RED = "red"

        result = json.dumps({"c": Color.RED}, cls=CanonicalEncoder)
        assert '"red"' in result

    def test_encodes_decimal(self):
        """Decimal values are serialized as strings."""
        d = decimal.Decimal("123.45")
        result = json.dumps({"amt": d}, cls=CanonicalEncoder)
        assert '"123.45"' in result

    def test_encodes_set(self):
        """Sets are serialized as sorted lists."""
        result = json.dumps({"s": {"c", "a", "b"}}, cls=CanonicalEncoder)
        parsed = json.loads(result)
        assert parsed["s"] == ["a", "b", "c"]

    def test_encodes_bytes(self):
        """Bytes are serialized as hex strings."""
        result = json.dumps({"b": b"\xde\xad"}, cls=CanonicalEncoder)
        assert '"dead"' in result

    def test_v2_encoder_normalizes_aware_datetime_to_utc(self):
        """CanonicalV2Encoder converts non-UTC aware datetimes to UTC."""
        import datetime as dt

        eastern = dt.timezone(dt.timedelta(hours=-5))
        aware_dt = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=eastern)
        result = json.dumps({"ts": aware_dt}, cls=CanonicalV2Encoder)
        # 12:00 EST = 17:00 UTC
        assert "2026-01-01T17:00:00.000000Z" in result


class TestCanonicalSerializeVersions:
    """Test canonical_serialize version dispatching."""

    def test_v1_returns_raw_json_bytes(self):
        """v1 canonical serialization produces raw compact JSON."""
        data = {"b": 2, "a": 1}
        result = canonical_serialize_v1(data)
        assert result == b'{"a":1,"b":2}'

    def test_v2_returns_prefixed_json_bytes(self):
        """v2 canonical serialization includes the domain prefix."""
        data = {"key": "val"}
        result = canonical_serialize_v2(data)
        assert result.startswith(DOMAIN_PREFIX_V2)
        payload = result[len(DOMAIN_PREFIX_V2):]
        assert json.loads(payload) == {"key": "val"}

    def test_version_dispatch_v1(self):
        """canonical_serialize(version=1) routes to v1."""
        data = {"x": 1}
        assert canonical_serialize(data, version=1) == canonical_serialize_v1(data)

    def test_version_dispatch_v2(self):
        """canonical_serialize(version=2) routes to v2."""
        data = {"x": 1}
        assert canonical_serialize(data, version=2) == canonical_serialize_v2(data)

    def test_unsupported_version_raises(self):
        """Unknown canonical version must raise CanonicalizationError."""
        with pytest.raises(CanonicalizationError, match="Unsupported canonical version"):
            canonical_serialize({"x": 1}, version=99)

    def test_canonical_amount_legacy(self):
        """Legacy canonical_amount quantizes to 2 decimal places."""
        assert canonical_amount("500.005") == "500.00"  # Banker's rounding (ROUND_HALF_EVEN)
        assert canonical_amount(100) == "100.00"
        assert canonical_amount(decimal.Decimal("42.5")) == "42.50"


# ---------------------------------------------------------------------------
# evaluation/wilson - all branches (15% -> 100%)
# ---------------------------------------------------------------------------


class TestWilsonInterval:
    """Test Wilson score confidence interval computations."""

    def test_zero_trials_returns_zero(self):
        """Zero trials must produce (0.0, 0.0)."""
        assert wilson_interval(0, 0) == (0.0, 0.0)

    def test_negative_trials_returns_zero(self):
        """Negative trials must produce (0.0, 0.0)."""
        assert wilson_interval(5, -1) == (0.0, 0.0)

    def test_all_successes(self):
        """All successes must have upper bound of 1.0."""
        lower, upper = wilson_interval(100, 100)
        assert upper == 1.0
        assert lower > 0.9

    def test_no_successes(self):
        """Zero successes must have lower bound of 0.0."""
        lower, upper = wilson_interval(0, 100)
        assert lower == 0.0
        assert upper < 0.1

    def test_half_successes(self):
        """50% success rate produces interval around 0.5."""
        lower, upper = wilson_interval(50, 100)
        assert lower < 0.5 < upper
        assert 0.3 < lower < 0.5
        assert 0.5 < upper < 0.7

    def test_confidence_90(self):
        """90% confidence interval should be narrower than 95%."""
        l90, u90 = wilson_interval(50, 100, confidence=0.90)
        l95, u95 = wilson_interval(50, 100, confidence=0.95)
        assert (u90 - l90) < (u95 - l95)

    def test_confidence_99(self):
        """99% confidence interval should be wider than 95%."""
        l95, u95 = wilson_interval(50, 100, confidence=0.95)
        l99, u99 = wilson_interval(50, 100, confidence=0.99)
        assert (u99 - l99) > (u95 - l95)

    def test_unknown_confidence_defaults_to_95(self):
        """Unrecognized confidence level falls back to z=1.95996."""
        l_custom, u_custom = wilson_interval(50, 100, confidence=0.97)
        l_95, u_95 = wilson_interval(50, 100, confidence=0.95)
        assert l_custom == l_95
        assert u_custom == u_95

    def test_successes_clamped_to_trials(self):
        """Successes exceeding trials must be clamped."""
        _lower, upper = wilson_interval(200, 100)
        assert upper == 1.0

    def test_negative_successes_clamped_to_zero(self):
        """Negative successes must be clamped to 0."""
        lower, _upper = wilson_interval(-5, 100)
        assert lower == 0.0

    def test_small_sample(self):
        """Small sample (1 success in 1 trial) should have wide interval."""
        lower, upper = wilson_interval(1, 1)
        assert lower < 0.5
        assert upper == 1.0


# ---------------------------------------------------------------------------
# redteam/coverage - coverage_by_id (0% -> 100%)
# ---------------------------------------------------------------------------


class TestRedteamCoverage:
    """Test the attack coverage metadata registry."""

    def test_attack_coverage_is_nonempty(self):
        """ATTACK_COVERAGE must list at least the 17 core attacks."""
        assert len(ATTACK_COVERAGE) >= 17

    def test_coverage_by_id_returns_dict_keyed_by_attack_id(self):
        """coverage_by_id must return a dict of attack_id -> entry."""
        result = coverage_by_id()
        assert isinstance(result, dict)
        assert "RT-001" in result
        assert result["RT-001"]["attack_family"] == "authority"

    def test_coverage_by_id_returns_copies(self):
        """Entries must be copies so callers cannot mutate the registry."""
        result = coverage_by_id()
        result["RT-001"]["attack_family"] = "MUTATED"
        fresh = coverage_by_id()
        assert fresh["RT-001"]["attack_family"] == "authority"


# ---------------------------------------------------------------------------
# core/errors - uncovered error constructors (71% -> 100%)
# ---------------------------------------------------------------------------


class TestErrorHierarchy:
    """Test error class constructors for complete branch coverage."""

    def test_policy_violation_error_with_reasons(self):
        """PolicyViolationError must store reasons and optional policy_id."""
        err = PolicyViolationError(["too large", "unknown dest"], policy_id="POL-001")
        assert err.reasons == ["too large", "unknown dest"]
        assert err.policy_id == "POL-001"
        assert "POL-001" in str(err)

    def test_policy_violation_error_without_policy_id(self):
        """PolicyViolationError with no policy_id shows 'unknown'."""
        err = PolicyViolationError(["blocked"])
        assert err.policy_id is None
        assert "unknown" in str(err)

    def test_audit_integrity_error(self):
        """AuditIntegrityError must record index and hash values."""
        err = AuditIntegrityError(
            entry_index=42,
            expected_hash="a" * 64,
            computed_hash="b" * 64,
        )
        assert err.entry_index == 42
        assert err.expected_hash == "a" * 64
        assert err.computed_hash == "b" * 64
        assert "entry #42" in str(err)
