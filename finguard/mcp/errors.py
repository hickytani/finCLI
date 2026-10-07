"""MCP structured error types.

Errors are safe, deterministic, and never expose secrets, keys, credentials,
or internal filesystem paths. Every error carries a stable code and an optional
correlation_id for tracing.
"""

from __future__ import annotations


class MCPBoundaryError(Exception):
    """Base for all MCP security boundary errors.

    code         — stable, machine-readable identifier
    message      — human-readable, MUST NOT contain secrets
    retryable    — caller hint; does not grant retry authority
    correlation_id — opaque tracing reference
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool = False,
        correlation_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.correlation_id = correlation_id

    def to_dict(self) -> dict:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "retryable": self.retryable,
                "correlation_id": self.correlation_id,
            }
        }


class MCPInputError(MCPBoundaryError):
    """Raised when MCP input fails schema or security validation."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "MCP_INPUT_INVALID",
        correlation_id: str | None = None,
    ) -> None:
        super().__init__(code, message, retryable=False, correlation_id=correlation_id)


class MCPRateLimitError(MCPBoundaryError):
    """Raised when a session exceeds its per-session rate limit."""

    def __init__(self, *, correlation_id: str | None = None) -> None:
        super().__init__(
            "MCP_RATE_LIMIT",
            "Per-session request limit exceeded. Wait before retrying.",
            retryable=True,
            correlation_id=correlation_id,
        )


class MCPForbiddenToolError(MCPBoundaryError):
    """Raised when the MCP caller attempts a prohibited operation."""

    def __init__(self, tool_name: str, *, correlation_id: str | None = None) -> None:
        super().__init__(
            "MCP_FORBIDDEN_TOOL",
            f"Tool '{tool_name}' is not available through the MCP boundary.",
            retryable=False,
            correlation_id=correlation_id,
        )


class MCPNotFoundError(MCPBoundaryError):
    """Raised when a requested resource does not exist."""

    def __init__(self, *, correlation_id: str | None = None) -> None:
        super().__init__(
            "MCP_NOT_FOUND",
            "The requested resource was not found.",
            retryable=False,
            correlation_id=correlation_id,
        )
