"""Strict structured-intent boundary above the deterministic transaction core."""

from __future__ import annotations

import datetime
import hashlib
import json
import math
import uuid
from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from finguard.audit.ledger import AuditLedger
from finguard.core.enums import ActorType, Currency
from finguard.core.errors import SecurityError
from finguard.core.transaction import Transaction
from finguard.decision import DecisionEngine, DecisionResult
from finguard.identity.registry import IdentityRegistry
from finguard.money import Money
from finguard.storage.database import get_session
from finguard.storage.models import NonceRecord
from finguard.storage.repositories import TransactionRepository

INTENT_DOMAIN = b"finguard.agent.intent.v1\x00"
MAX_INTENT_BYTES = 16_384
MAX_CONTEXT_BYTES = 4_096
MAX_CONTEXT_DEPTH = 8
_AMBIGUOUS_RECIPIENTS = {"unknown", "none", "null", "undefined", "unresolved"}
_AUTHORITY_CONTEXT_KEYS = {
    "action",
    "actor",
    "actorid",
    "approved",
    "approval",
    "approvalid",
    "authorized",
    "authorization",
    "capability",
    "decision",
    "execute",
    "execution",
    "key",
    "keyid",
    "idempotency",
    "idempotencykey",
    "nonce",
    "policy",
    "policyversion",
    "sessionid",
    "signingkey",
    "signature",
    "signer",
    "state",
    "transactionid",
}


class _DuplicateField(ValueError):
    pass


class IntentValidationError(SecurityError):
    """Structured, deterministic rejection of untrusted intent input."""

    def __init__(
        self,
        code: str,
        reasons: list[str],
        *,
        correlation_id: str | None = None,
    ):
        super().__init__(code)
        self.code = code
        self.reasons = tuple(reasons)
        self.correlation_id = correlation_id


class StructuredIntent(BaseModel):
    """Normalized request data; none of these fields constitute authorization."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    intent_id: uuid.UUID
    correlation_id: uuid.UUID
    action: Literal["propose_transaction"]
    capability: Literal["transaction.propose"]
    from_account: str = Field(min_length=1, max_length=128)
    recipient: str = Field(min_length=1, max_length=128)
    currency: Currency
    amount: str | int
    reason: str = Field(min_length=1, max_length=256)
    context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("from_account", "recipient")
    @classmethod
    def identifiers_are_canonical(cls, value: str) -> str:
        normalized = Transaction.validate_signed_identifier(value.strip())
        if normalized != value.strip():
            raise ValueError("Identifier is not canonical")
        if normalized == "*":
            raise ValueError("Wildcard is not an identifier")
        return normalized

    @field_validator("recipient")
    @classmethod
    def recipient_is_explicit(cls, value: str) -> str:
        if value.casefold() in _AMBIGUOUS_RECIPIENTS:
            raise ValueError("Recipient is ambiguous")
        return value

    @field_validator("amount", mode="before")
    @classmethod
    def amount_is_exact_input(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise TypeError("Amount must be a decimal string or integer")
        if len(str(value)) > 64:
            raise ValueError("Amount exceeds supported input length")
        return value

    @field_validator("amount")
    @classmethod
    def amount_is_exact(cls, value: str | int, info) -> str:
        currency = info.data.get("currency")
        if currency is None:
            raise ValueError("Currency is required before amount normalization")
        return Money.from_decimal(value, currency).to_decimal_string()

    @field_validator("reason")
    @classmethod
    def reason_is_descriptive_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Reason must not be empty")
        return normalized

    @field_validator("context")
    @classmethod
    def context_is_bounded_non_authoritative_data(cls, value: dict[str, Any]) -> dict[str, Any]:
        _validate_context(value)
        encoded = _canonical_json(value)
        if len(encoded) > MAX_CONTEXT_BYTES:
            raise ValueError("Context exceeds supported size")
        return value

    def canonical_bytes(self) -> bytes:
        return INTENT_DOMAIN + _canonical_json(self.model_dump(mode="json"))

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class StructuredIntentBoundary:
    """Validate agent intent, bind it into Transaction v2, and call DecisionEngine."""

    def __init__(
        self,
        *,
        actor_id: str,
        session_id: str,
        registry: IdentityRegistry | None = None,
        clock: Callable[[], datetime.datetime] | None = None,
    ):
        self._registry = registry or IdentityRegistry()
        actor = self._registry.get_actor(actor_id)
        if actor is None or actor.actor_type != ActorType.AGENT or not actor.active:
            raise SecurityError("Structured intent boundary requires an active registered AGENT")
        if not session_id:
            raise ValueError("A server-bound agent session is required")
        self._actor = actor
        self._session_id = Transaction.validate_signed_identifier(session_id)
        self._clock = clock or (lambda: datetime.datetime.now(datetime.UTC))

    def submit(
        self,
        raw_intent: object,
        *,
        ai_assessment: dict[str, Any] | None = None,
    ) -> DecisionResult:
        try:
            raw_bytes = self._input_bytes(raw_intent)
        except IntentValidationError as exc:
            input_digest = self._fallback_input_digest(raw_intent)
            correlation_hint = None
            self._audit(
                "AGENT_INTENT_RECEIVED",
                correlation_hint,
                {"input_digest": input_digest},
            )
            self._record_rejection(exc, input_digest, correlation_hint, None)
            raise
        input_digest = hashlib.sha256(raw_bytes).hexdigest()
        correlation_hint = self._correlation_hint(raw_bytes)
        intent_id_hint = self._intent_id_hint(raw_bytes)
        self._audit(
            "AGENT_INTENT_RECEIVED",
            correlation_hint,
            {"input_digest": input_digest, "intent_id": intent_id_hint},
        )

        try:
            intent = self._parse(raw_bytes)
        except IntentValidationError as exc:
            self._record_rejection(
                exc, input_digest, correlation_hint, intent_id_hint
            )
            raise

        transaction_id, idempotency_key, nonce = self._transaction_keys(intent)
        intent_digest = intent.digest()
        existing = self._find_existing(idempotency_key)
        if existing is not None:
            try:
                transaction = self._transaction_for_replay(
                    intent, intent_digest, transaction_id, idempotency_key, nonce, existing
                )
            except IntentValidationError as exc:
                self._record_rejection(
                    exc,
                    input_digest,
                    str(intent.correlation_id),
                    str(intent.intent_id),
                )
                raise
        else:
            if self._nonce_is_used(nonce):
                error = IntentValidationError(
                    "NONCE_REPLAY",
                    ["server-derived nonce is already bound to another transaction"],
                    correlation_id=str(intent.correlation_id),
                )
                self._record_rejection(
                    error,
                    input_digest,
                    str(intent.correlation_id),
                    str(intent.intent_id),
                )
                raise error
            transaction = self._transaction_from_intent(
                intent,
                intent_digest,
                transaction_id,
                idempotency_key,
                nonce,
                self._current_time(),
            )

        try:
            decision = DecisionEngine(registry=self._registry).decide(
                transaction,
                ai_assessment=ai_assessment,
            )
        except ValueError:
            replay = self._find_existing(idempotency_key)
            if replay is None:
                raise
            try:
                replay_transaction = self._transaction_for_replay(
                    intent, intent_digest, transaction_id, idempotency_key, nonce, replay
                )
            except IntentValidationError as exc:
                self._record_rejection(
                    exc,
                    input_digest,
                    str(intent.correlation_id),
                    str(intent.intent_id),
                )
                raise
            decision = DecisionEngine(registry=self._registry).decide(
                replay_transaction,
                ai_assessment=ai_assessment,
            )

        self._audit(
            "AGENT_INTENT_ACCEPTED",
            str(intent.correlation_id),
            {
                "intent_id": str(intent.intent_id),
                "intent_digest": intent_digest,
                "transaction_id": decision.transaction.transaction_id,
                "transaction_hash": decision.transaction.transaction_hash(),
                "receipt_id": decision.receipt.receipt_id,
                "decision": decision.decision.value,
                "authorization": "none",
            },
            transaction_id=decision.transaction.transaction_id,
            result="VALIDATED_NOT_AUTHORIZED",
        )
        return decision

    @staticmethod
    def _input_bytes(raw_intent: object) -> bytes:
        try:
            if isinstance(raw_intent, bytes):
                encoded = raw_intent
            elif isinstance(raw_intent, str):
                encoded = raw_intent.encode("utf-8", errors="strict")
            elif isinstance(raw_intent, StructuredIntent):
                encoded = _canonical_json(raw_intent.model_dump(mode="json"))
            elif isinstance(raw_intent, dict):
                _validate_json_value(raw_intent)
                encoded = _canonical_json(raw_intent)
            else:
                raise TypeError
        except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
            raise IntentValidationError(
                "MALFORMED_INPUT",
                ["input must be a JSON object, string, or UTF-8 bytes"],
            ) from exc
        if len(encoded) > MAX_INTENT_BYTES:
            raise IntentValidationError(
                "INTENT_TOO_LARGE",
                ["intent exceeds the maximum encoded size"],
            )
        return encoded

    @staticmethod
    def _fallback_input_digest(raw_intent: object) -> str:
        if isinstance(raw_intent, (str, bytes)):
            raw_bytes = (
                raw_intent.encode("utf-8", errors="replace")
                if isinstance(raw_intent, str)
                else raw_intent
            )
            return hashlib.sha256(raw_bytes).hexdigest()
        return hashlib.sha256(type(raw_intent).__name__.encode("utf-8")).hexdigest()

    @staticmethod
    def _parse(raw_bytes: bytes) -> StructuredIntent:
        try:
            payload = json.loads(
                raw_bytes.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_fields,
                parse_constant=_reject_nonfinite_constant,
            )
        except _DuplicateField as exc:
            raise IntentValidationError(
                "DUPLICATE_FIELD",
                ["JSON contains a duplicate object field"],
            ) from exc
        except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise IntentValidationError(
                "MALFORMED_JSON",
                ["input is not valid bounded UTF-8 JSON"],
            ) from exc
        if type(payload) is not dict:
            raise IntentValidationError(
                "SCHEMA_VALIDATION_FAILED",
                ["top-level intent must be an object"],
            )
        try:
            return StructuredIntent.model_validate(payload)
        except TypeError as exc:
            if str(exc).startswith("Amount must"):
                raise IntentValidationError(
                    "INVALID_AMOUNT",
                    ["amount must be a decimal string or integer"],
                ) from exc
            raise IntentValidationError(
                "SCHEMA_VALIDATION_FAILED",
                ["intent contains a value of an unsupported type"],
            ) from exc
        except ValidationError as exc:
            raise StructuredIntentBoundary._schema_error(exc) from exc

    @staticmethod
    def _schema_error(exc: ValidationError) -> IntentValidationError:
        errors = exc.errors()
        locations = sorted(".".join(str(part) for part in item["loc"]) for item in errors)
        codes = {item["loc"][0] for item in errors if item["loc"]}
        if any(item["type"] == "missing" for item in errors):
            reason = "required intent fields are missing"
            code = "SCHEMA_VALIDATION_FAILED"
        elif any(item["type"] == "extra_forbidden" for item in errors):
            reason = "UNEXPECTED_FIELD"
            code = reason
        elif "action" in codes:
            reason = "action must be propose_transaction"
            code = "UNSUPPORTED_ACTION"
        elif "capability" in codes:
            reason = "capability must be transaction.propose"
            code = "UNSUPPORTED_CAPABILITY"
        elif "amount" in codes:
            reason = "amount is invalid or not exactly representable"
            code = "INVALID_AMOUNT"
        elif "recipient" in codes:
            reason = "recipient is invalid or ambiguous"
            code = "INVALID_RECIPIENT"
        else:
            reason = "intent fields are missing or invalid"
            code = "SCHEMA_VALIDATION_FAILED"
        return IntentValidationError(code, [f"{reason}: {', '.join(locations)}"])

    @staticmethod
    def _correlation_hint(raw_bytes: bytes) -> str | None:
        try:
            payload = json.loads(raw_bytes.decode("utf-8"))
            value = payload.get("correlation_id") if isinstance(payload, dict) else None
            return str(uuid.UUID(value)) if isinstance(value, str) else None
        except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError):
            return None

    @staticmethod
    def _intent_id_hint(raw_bytes: bytes) -> str | None:
        try:
            payload = json.loads(raw_bytes.decode("utf-8"))
            value = payload.get("intent_id") if isinstance(payload, dict) else None
            return str(uuid.UUID(value)) if isinstance(value, str) else None
        except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError):
            return None

    def _transaction_keys(self, intent: StructuredIntent) -> tuple[str, str, str]:
        material = (
            self._actor.actor_id.encode("utf-8")
            + b"\x00"
            + intent.intent_id.bytes
        )
        key_digest = hashlib.sha256(b"finguard.intent.id.v1\x00" + material).hexdigest()
        nonce = hashlib.sha256(b"finguard.intent.nonce.v1\x00" + material).hexdigest()
        return f"INT-{key_digest[:24].upper()}", f"intent-v1-{key_digest}", nonce

    def _transaction_for_replay(
        self,
        intent: StructuredIntent,
        intent_digest: str,
        transaction_id: str,
        idempotency_key: str,
        nonce: str,
        record,
    ) -> Transaction:
        try:
            metadata = json.loads(record.metadata_json or "{}")
            if not isinstance(metadata, dict):
                raise TypeError("Stored transaction metadata must be an object")
            binding = metadata["agent_intent"]
            if not isinstance(binding, dict):
                raise TypeError("Stored intent binding must be an object")
            if (
                binding.get("intent_id") != str(intent.intent_id)
                or binding.get("intent_digest") != intent_digest
                or record.transaction_id != transaction_id
                or record.idempotency_key != idempotency_key
                or record.actor_id != self._actor.actor_id
                or record.nonce != nonce
                or record.amount_minor is None
            ):
                raise ValueError
            transaction = self._transaction_from_intent(
                intent,
                intent_digest,
                transaction_id,
                idempotency_key,
                nonce,
                record.timestamp,
            )
            if transaction.transaction_hash() != record.canonical_hash:
                raise ValueError
            session = get_session()
            try:
                nonce_record = session.get(NonceRecord, nonce)
                if nonce_record is None or nonce_record.transaction_id != transaction_id:
                    raise ValueError
            finally:
                session.close()
            return transaction
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IntentValidationError(
                "INTENT_ID_CONFLICT",
                ["intent_id is already bound to different or invalid transaction evidence"],
                correlation_id=str(intent.correlation_id),
            ) from exc

    def _transaction_from_intent(
        self,
        intent: StructuredIntent,
        intent_digest: str,
        transaction_id: str,
        idempotency_key: str,
        nonce: str,
        timestamp: datetime.datetime,
    ) -> Transaction:
        metadata = {
            "purpose": intent.reason,
            "intent_context": intent.context,
            "agent_intent": {
                "schema_version": intent.schema_version,
                "intent_id": str(intent.intent_id),
                "correlation_id": str(intent.correlation_id),
                "actor_id": self._actor.actor_id,
                "action": intent.action,
                "capability": intent.capability,
                "intent_digest": intent_digest,
            },
        }
        return Transaction(
            transaction_id=transaction_id,
            actor_id=self._actor.actor_id,
            session_id=self._session_id,
            from_account=intent.from_account,
            to_account=intent.recipient,
            amount=intent.amount,
            currency=intent.currency,
            nonce=nonce,
            timestamp=timestamp,
            metadata=metadata,
            idempotency_key=idempotency_key,
            initiating_actor_type=ActorType.AGENT.value,
        )

    def _find_existing(self, idempotency_key: str):
        session = get_session()
        try:
            return TransactionRepository(session).get_by_idempotency_key(idempotency_key)
        finally:
            session.close()

    @staticmethod
    def _nonce_is_used(nonce: str) -> bool:
        session = get_session()
        try:
            return session.get(NonceRecord, nonce) is not None
        finally:
            session.close()

    def _current_time(self) -> datetime.datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Intent boundary clock must return an aware datetime")
        return value.astimezone(datetime.UTC)

    def _record_rejection(
        self,
        error: IntentValidationError,
        input_digest: str,
        correlation_id: str | None,
        intent_id: str | None,
    ) -> None:
        correlation = error.correlation_id or correlation_id
        self._audit(
            "AGENT_INTENT_REJECTED",
            correlation,
            {
                "input_digest": input_digest,
                "intent_id": intent_id,
                "reason_code": error.code,
                "reasons": list(error.reasons),
            },
            result="REJECTED",
        )

    def _audit(
        self,
        action: str,
        correlation_id: str | None,
        metadata: dict[str, Any],
        *,
        transaction_id: str | None = None,
        result: str = "PASS",
    ) -> None:
        AuditLedger().append(
            action=action,
            actor_id=self._actor.actor_id,
            transaction_id=transaction_id,
            result=result,
            metadata={
                **metadata,
                "correlation_id": correlation_id,
            },
        )


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateField(key)
        result[key] = value
    return result


def _reject_nonfinite_constant(value: str) -> None:
    raise ValueError(f"Non-finite JSON constant is unsupported: {value}")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8", errors="strict")


def _validate_json_value(value: Any, depth: int = 0) -> None:
    if depth > MAX_CONTEXT_DEPTH:
        raise ValueError("JSON nesting limit exceeded")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite numbers are unsupported")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth + 1)
        return
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        for item in value.values():
            _validate_json_value(item, depth + 1)
        return
    raise TypeError("Value is not JSON-compatible")


def _validate_context(value: dict[str, Any]) -> None:
    _validate_json_value(value)
    if any(not isinstance(key, str) for key in value):
        raise ValueError("Context keys must be strings")

    def reject_authority_keys(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                normalized = "".join(character for character in key.casefold() if character.isalnum())
                if normalized in _AUTHORITY_CONTEXT_KEYS or any(
                    marker in normalized
                    for marker in (
                        "approved",
                        "approval",
                        "authoriz",
                        "signature",
                        "signer",
                        "execute",
                        "decision",
                        "nonce",
                        "idempotency",
                        "policy",
                    )
                ):
                    raise ValueError("Context cannot contain authority or execution fields")
                reject_authority_keys(child)
        elif isinstance(item, list):
            for child in item:
                reject_authority_keys(child)

    reject_authority_keys(value)
