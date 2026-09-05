"""Core domain enumerations for FIN//GUARD.

All security-relevant states are explicitly enumerated rather than passed
as raw strings, enforcing type safety as part of the security architecture.
"""

from enum import Enum, unique


@unique
class ActorType(str, Enum):
    """Type of entity requesting financial operations."""
    HUMAN = "human"
    HUMAN_OPERATOR = "human_operator"
    SERVICE = "service"
    AGENT = "agent"
    ADMINISTRATOR = "administrator"
    APPROVER = "approver"


@unique
class Currency(str, Enum):
    """Supported synthetic currencies."""
    INR = "INR"
    USD = "USD"
    EUR = "EUR"


@unique
class TransactionState(str, Enum):
    """Lifecycle state of a transaction."""
    CREATED = "created"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    SIGNED = "signed"
    EXECUTED = "executed"
    BLOCKED = "blocked"
    FAILED = "failed"


@unique
class DecisionType(str, Enum):
    """Outcome of a policy/security evaluation."""
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


@unique
class RiskLevel(str, Enum):
    """Risk classification levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@unique
class SignalType(str, Enum):
    """Types of security signals generated during transaction processing."""
    NEW_DESTINATION = "NEW_DESTINATION"
    AMOUNT_ANOMALY = "AMOUNT_ANOMALY"
    VELOCITY_SPIKE = "VELOCITY_SPIKE"
    OFF_HOURS = "OFF_HOURS"
    NEW_SESSION = "NEW_SESSION"
    AUTHORITY_VIOLATION = "AUTHORITY_VIOLATION"
    REPLAY_ATTEMPT = "REPLAY_ATTEMPT"
    TAMPERING_DETECTED = "TAMPERING_DETECTED"
    CREDENTIAL_ANOMALY = "CREDENTIAL_ANOMALY"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DESTINATION_MANIPULATION = "DESTINATION_MANIPULATION"


@unique
class ApprovalState(str, Enum):
    """State of an approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@unique
class IncidentSeverity(str, Enum):
    """Severity classification for security incidents."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
