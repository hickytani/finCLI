"""Transaction lifecycle state machine for FIN//GUARD.

This module defines the authoritative transition graph for transactions. The
security boundary validates every lifecycle change through this deterministic
state table instead of allowing raw string mutation in callers.
"""

from __future__ import annotations

from typing import ClassVar

from finguard.core.enums import TransactionState


class InvalidTransitionError(ValueError):
    """Raised when the requested transition violates the lifecycle graph."""


class TransactionStateMachine:
    """Deterministic transition rules for a transaction lifecycle."""

    _VALID_TRANSITIONS: ClassVar[dict[TransactionState, set[TransactionState]]] = {
        TransactionState.CREATED: {
            TransactionState.PENDING_APPROVAL,
            TransactionState.SIGNED,
            TransactionState.BLOCKED,
            TransactionState.FAILED,
        },
        TransactionState.PENDING_APPROVAL: {
            TransactionState.APPROVED,
            TransactionState.SIGNED,
            TransactionState.BLOCKED,
            TransactionState.FAILED,
        },
        TransactionState.APPROVED: {
            TransactionState.SIGNED,
            TransactionState.BLOCKED,
            TransactionState.FAILED,
        },
        TransactionState.SIGNED: {
            TransactionState.EXECUTED,
            TransactionState.BLOCKED,
            TransactionState.FAILED,
        },
        TransactionState.EXECUTED: set(),
        TransactionState.BLOCKED: set(),
        TransactionState.FAILED: set(),
    }

    @staticmethod
    def normalize(state: TransactionState | str) -> TransactionState:
        if isinstance(state, TransactionState):
            return state
        if isinstance(state, str):
            try:
                return TransactionState(state)
            except ValueError as exc:  # pragma: no cover - defensive path
                raise InvalidTransitionError(f"Unknown transaction state: {state!r}") from exc
        raise InvalidTransitionError(f"Unsupported state type: {type(state).__name__}")

    @classmethod
    def allowed_next_states(cls, current_state: TransactionState | str) -> set[TransactionState]:
        normalized = cls.normalize(current_state)
        return cls._VALID_TRANSITIONS.get(normalized, set())

    @classmethod
    def validate_transition(cls, current_state: TransactionState | str, target_state: TransactionState | str) -> bool:
        current = cls.normalize(current_state)
        target = cls.normalize(target_state)

        if current == target:
            return True

        allowed = cls.allowed_next_states(current)
        if target not in allowed:
            allowed_values = sorted(state.value for state in allowed) if allowed else ["none (terminal state)"]
            raise InvalidTransitionError(
                f"Cannot transition transaction from '{current.value}' to '{target.value}'. "
                f"Allowed next states: {allowed_values}."
            )
        return True

    @classmethod
    def transition(
        cls,
        current_state: TransactionState | str,
        target_state: TransactionState | str,
        *,
        expected_version: int | None = None,
        current_version: int | None = None,
    ) -> TransactionState:
        cls.validate_transition(current_state, target_state)
        if expected_version is not None and current_version is not None and expected_version != current_version:
            raise InvalidTransitionError(
                f"Cannot transition transaction to '{cls.normalize(target_state).value}' with expected version {expected_version}; "
                f"current version is {current_version}."
            )
        return cls.normalize(target_state)

    @staticmethod
    def terminal_states() -> set[TransactionState]:
        return {TransactionState.EXECUTED, TransactionState.BLOCKED, TransactionState.FAILED}

    @staticmethod
    def is_terminal(state: TransactionState | str) -> bool:
        return TransactionStateMachine.normalize(state) in TransactionStateMachine.terminal_states()

    @staticmethod
    def is_valid_state(state: TransactionState | str) -> bool:
        try:
            TransactionStateMachine.normalize(state)
            return True
        except InvalidTransitionError:
            return False
