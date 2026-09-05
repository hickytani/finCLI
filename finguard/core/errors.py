"""Typed exception hierarchy for FIN//GUARD.

Every security-relevant failure has a distinct exception type.
This prevents catching overly broad exceptions and accidentally
swallowing security failures.

DESIGN PRINCIPLE: All exceptions in this hierarchy are fail-closed.
If any of these are raised during transaction processing, the
transaction MUST NOT proceed to signing.
"""


class FinguardError(Exception):
    """Base exception for all FIN//GUARD errors."""
    pass


class SecurityError(FinguardError):
    """Base for security-specific failures. Always fail closed."""
    pass


class AuthorityDeniedError(SecurityError):
    """Actor does not have authority for the requested operation."""
    pass


class PolicyViolationError(SecurityError):
    """Transaction violates one or more policy rules."""

    def __init__(self, reasons: list[str], policy_id: str | None = None):
        self.reasons = reasons
        self.policy_id = policy_id
        msg = f"Policy violation [{policy_id or 'unknown'}]: {'; '.join(reasons)}"
        super().__init__(msg)


class IntegrityError(SecurityError):
    """Cryptographic integrity check failed (tampering detected)."""
    pass


class ReplayError(SecurityError):
    """Duplicate nonce / idempotency key detected (replay attack)."""
    pass


class QuorumError(SecurityError):
    """Insufficient approval quorum for the requested operation."""
    pass


class KeystoreError(SecurityError):
    """Keystore operation failed (wrong password, corrupt key, etc.)."""
    pass


class ApprovalError(SecurityError):
    """Approval workflow violation (self-approval, duplicate, expired, etc.)."""
    pass


class AuditIntegrityError(SecurityError):
    """Audit ledger hash chain is broken (tamper detected)."""

    def __init__(self, entry_index: int, expected_hash: str, computed_hash: str):
        self.entry_index = entry_index
        self.expected_hash = expected_hash
        self.computed_hash = computed_hash
        super().__init__(
            f"Audit integrity failure at entry #{entry_index}: "
            f"expected={expected_hash[:16]}... computed={computed_hash[:16]}..."
        )


class ConfigurationError(FinguardError):
    """Invalid configuration or policy file."""
    pass


class TransactionError(FinguardError):
    """Transaction processing error (not necessarily security-related)."""
    pass
