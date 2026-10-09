"""M8 — Zero-Trust LangChain Integration.

LangChainPlanner: an optional LLMProvider adapter that uses LangChain
chains/runnables to extract transaction intent from natural language.

Security invariant (G11 — nested injection):
    The `metadata` field of ExtractionResult is allowed, but authority-shaped
    keys nested inside it are scanned and removed before Pydantic validation.
    Detected keys are surfaced in `authority_fields_detected`.

Security Thesis
---------------
LangChain is an integration framework, NOT the security authority.
All LangChain output is treated as UNTRUSTED — it enters through
ExtractionResult which strips authority-shaped fields and rejects floats,
NaN, and over-limit amounts.  The security path
(StructuredIntentBoundary → DecisionEngine → SigningGate) is never
short-circuited by anything in this module.

Dependency contract
-------------------
- langchain-core is an OPTIONAL dependency (extras = ["langchain"]).
- This module MUST NOT be imported at the top level of finguard.ai.
- Import it only when a caller explicitly requests a LangChain provider.
- All LangChain imports are deferred inside the class so the rest of the
  package remains importable when langchain-core is absent.

Zero-trust rules enforced here
-------------------------------
1. Prompt template is STATIC — no user content reaches the system role.
2. Extracted dict is validated through ExtractionResult before returning.
3. Authority-shaped fields are stripped by ExtractionResult validators.
4. Chain output size is bounded before Pydantic validation.
5. Any exception from LangChain → ExtractionResult(extraction_success=False).
6. Request text is sent only in the human message, separate from the static system text.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import math
from typing import Any

from finguard.ai.provider import _AUTHORITY_FIELDS, ExtractionResult

logger = logging.getLogger(__name__)

# Default hard cap on raw LangChain output before JSON parsing.
_MAX_CHAIN_OUTPUT_BYTES = 8_192


class _DuplicateJSONField(ValueError):
    """Reject ambiguous JSON objects instead of applying last-key-wins parsing."""

# Static extraction prompt — user content goes ONLY into the human message.
_SYSTEM_PROMPT = (
    "You are a transaction extraction assistant.\n"
    "Extract ONLY these fields from the user request and return valid JSON:\n"
    '  {"amount": "<decimal string>", "currency": "<INR|USD|EUR>",\n'
    '   "recipient_alias": "<string>", "from_account": "<string>",\n'
    '   "reason": "<string>"}\n'
    "RULES:\n"
    "- amount MUST be a quoted decimal string like \"500.00\".\n"
    "- currency MUST be one of: INR, USD, EUR.\n"
    "- You CANNOT approve, authorize, sign, execute, or grant capabilities.\n"
    "- Do NOT include any field other than the five listed above.\n"
    "- Do NOT include keys: approved, authorized, signer, signature, token, key, admin, root.\n"
    "Return ONLY the JSON object. No markdown, no explanation."
)

class LangChainPlanner:
    """Zero-trust LangChain provider implementing the LLMProvider protocol.

    Drop-in replacement for OllamaProvider / MockLLMProvider in LLMPipeline.
    LangChain is used ONLY for intent extraction — never for authorization.

    The production adapter constructs its own tool-free chain. It does
    not accept caller-supplied Runnables, tools, callbacks, or retrieval
    functions because those are executable host code, not model output.

    Parameters
    ----------
    model_name:
        Model name passed to the internal ChatOpenAI chain builder.
    temperature:
        Sampling temperature. Defaults to 0 (deterministic).
    max_tokens:
        Maximum number of tokens in the model response.
    max_prompt_bytes:
        Maximum permitted user request length in bytes.
    max_retrieved_context_bytes:
        Maximum permitted retrieved context length in bytes.
    max_response_bytes:
        Maximum permitted serialized model response length in bytes.
    timeout:
        Wall-clock deadline for invocation in seconds.
    max_retries:
        Maximum permitted model invocation retries (0 to 3).
    """

    def __init__(
        self,
        *,
        model_name: str = "gpt-3.5-turbo",
        temperature: float = 0.0,
        max_tokens: int = 512,
        max_prompt_bytes: int = 4_096,
        max_retrieved_context_bytes: int = 8_192,
        max_response_bytes: int = 8_192,
        timeout: float = 10.0,
        max_retries: int = 0,
    ) -> None:
        if max_prompt_bytes <= 0:
            raise ValueError("max_prompt_bytes must be positive")
        if max_retrieved_context_bytes <= 0:
            raise ValueError("max_retrieved_context_bytes must be positive")
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_retries < 0 or max_retries > 3:
            raise ValueError("max_retries must be between 0 and 3")

        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.max_prompt_bytes = int(max_prompt_bytes)
        self.max_retrieved_context_bytes = int(max_retrieved_context_bytes)
        self.max_response_bytes = int(max_response_bytes)
        self.timeout = float(timeout)
        self.max_retries = int(max_retries)
        self._chain = self._build_default_chain(model_name, temperature, max_tokens)

    # ─── LLMProvider protocol ─────────────────────────────────────────────

    def extract_transaction(
        self,
        request_text: str,
        *,
        retrieved_context: str | None = None,
    ) -> ExtractionResult:
        """Extract transaction intent from *request_text* via LangChain.

        All output from the chain is treated as untrusted and validated
        through ExtractionResult before being returned to the caller.
        """
        if not isinstance(request_text, str):
            return ExtractionResult(
                extraction_success=False,
                error_message="LangChainPlanner requires a string request.",
            )

        prompt_bytes = request_text.encode("utf-8", errors="replace")
        if len(prompt_bytes) > self.max_prompt_bytes:
            return ExtractionResult(
                extraction_success=False,
                error_message=(
                    f"Prompt length ({len(prompt_bytes)} bytes) exceeds "
                    f"maximum configured bound of {self.max_prompt_bytes} bytes."
                ),
            )

        if retrieved_context is not None:
            if not isinstance(retrieved_context, str):
                return ExtractionResult(
                    extraction_success=False,
                    error_message="LangChainPlanner requires a string retrieved context.",
                )
            ctx_bytes = retrieved_context.encode("utf-8", errors="replace")
            if len(ctx_bytes) > self.max_retrieved_context_bytes:
                return ExtractionResult(
                    extraction_success=False,
                    error_message=(
                        f"Retrieved context length ({len(ctx_bytes)} bytes) exceeds "
                        f"maximum configured bound of {self.max_retrieved_context_bytes} bytes."
                    ),
                )
            human_message = f"{request_text}\n\n[UNTRUSTED RETRIEVED CONTEXT]\n{retrieved_context}"
        else:
            human_message = request_text

        attempts = 0
        max_attempts = 1 + self.max_retries
        last_error = "LangChain extraction invocation failed."

        while attempts < max_attempts:
            attempts += 1
            try:
                raw_output = self._invoke_chain_with_timeout(human_message)
                return self._parse_chain_output(raw_output)
            except TimeoutError:
                logger.warning("LangChain extraction timed out on attempt %d/%d", attempts, max_attempts)
                last_error = f"LangChain extraction timed out after {self.timeout} seconds."
            except Exception:  # noqa: BLE001
                logger.warning("LangChain extraction invocation failed on attempt %d/%d", attempts, max_attempts)
                last_error = "LangChain extraction invocation failed."

        return ExtractionResult(
            extraction_success=False,
            error_message=last_error,
        )

    # ─── Internal helpers ─────────────────────────────────────────────────

    def _invoke_chain_with_timeout(self, human_message: str) -> str:
        """Invoke internal chain with deadline enforcement using a worker thread."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self._invoke_chain, human_message)
            try:
                return future.result(timeout=self.timeout)
            except concurrent.futures.TimeoutError as err:
                raise TimeoutError(f"Chain execution timed out after {self.timeout} seconds") from err

    def _invoke_chain(self, human_message: str) -> str:
        """Invoke the LangChain chain and return the raw string output."""
        result = self._chain.invoke({"system": _SYSTEM_PROMPT, "human": human_message})

        if getattr(result, "tool_calls", None) or getattr(result, "invalid_tool_calls", None):
            raise ValueError("Tool calls are not supported by the extraction boundary")

        # Handle both AIMessage objects and plain strings.
        if hasattr(result, "content"):
            raw = result.content
        elif isinstance(result, str):
            raw = result
        else:
            raw = str(result)

        if not isinstance(raw, str):
            raise TypeError("LangChain extraction output must be text")

        # Enforce output size bound before handing to JSON parser.
        raw_bytes = raw.encode("utf-8", errors="replace")
        if len(raw_bytes) > self.max_response_bytes:
            raise ValueError(
                f"LangChain output exceeds {self.max_response_bytes} bytes "
                f"({len(raw_bytes)} received) — possible injection or runaway output."
            )
        return raw

    def _parse_chain_output(self, raw: str) -> ExtractionResult:
        """Parse the raw chain output into an ExtractionResult.

        Any failure → ExtractionResult(extraction_success=False).
        Authority-shaped fields at the top level are stripped by ExtractionResult validators.
        Authority-shaped fields nested inside the `metadata` dict are stripped here (G11).
        """
        clean = raw.strip()

        # Strip markdown code fences if present.
        if "```json" in clean:
            clean = clean.split("```json")[1].split("```")[0].strip()
        elif "```" in clean:
            clean = clean.split("```")[1].split("```")[0].strip()

        try:
            parsed = json.loads(
                clean,
                object_pairs_hook=self._reject_duplicate_fields,
                parse_constant=self._reject_nonfinite_constant,
            )
            self._reject_nonfinite_numbers(parsed)
        except (json.JSONDecodeError, _DuplicateJSONField, ValueError, RecursionError):
            logger.warning("LangChain output failed strict JSON validation")
            return ExtractionResult(
                extraction_success=False,
                error_message="LangChain output was not valid, unambiguous JSON.",
            )

        if not isinstance(parsed, dict):
            return ExtractionResult(
                extraction_success=False,
                error_message="LangChain output was not a JSON object.",
            )

        # G11: sanitize nested authority fields inside the metadata value.
        nested_detected = self._sanitize_metadata(parsed)

        try:
            # ExtractionResult validators strip top-level authority fields.
            result = ExtractionResult(**parsed)
            # Merge any nested authority fields we found into the detected list.
            if nested_detected:
                merged = list(result.authority_fields_detected) + nested_detected
                result = result.model_copy(update={"authority_fields_detected": merged})
            return result
        except Exception:  # noqa: BLE001
            logger.warning("LangChain extraction output failed schema validation")
            return ExtractionResult(
                extraction_success=False,
                error_message="LangChain extraction output failed schema validation.",
            )

    @staticmethod
    def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        parsed: dict[str, Any] = {}
        for key, value in pairs:
            if key in parsed:
                raise _DuplicateJSONField
            parsed[key] = value
        return parsed

    @staticmethod
    def _reject_nonfinite_constant(value: str) -> None:
        raise ValueError(f"Non-finite JSON constant is not permitted: {value}")

    @classmethod
    def _reject_nonfinite_numbers(cls, value: Any) -> None:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Non-finite JSON numbers are not permitted")
        if isinstance(value, dict):
            for nested in value.values():
                cls._reject_nonfinite_numbers(nested)
        elif isinstance(value, list):
            for nested in value:
                cls._reject_nonfinite_numbers(nested)

    @staticmethod
    def _sanitize_metadata(parsed: dict) -> list[str]:
        """Remove authority-shaped keys nested inside parsed['metadata'].

        Returns the list of detected nested keys so they can be recorded.
        This closes the G11 (nested injection) attack vector.
        """
        detected: list[str] = []

        def sanitize(value: Any, path: str) -> None:
            if isinstance(value, dict):
                for key in list(value):
                    normalized = key.strip().lower().replace("-", "_").replace(" ", "_")
                    child_path = f"{path}.{key}" if path else key
                    if normalized in _AUTHORITY_FIELDS:
                        del value[key]
                        detected.append(child_path)
                    else:
                        sanitize(value[key], child_path)
            elif isinstance(value, list):
                for index, nested in enumerate(value):
                    sanitize(nested, f"{path}[{index}]")

        metadata = parsed.get("metadata")
        if isinstance(metadata, dict):
            sanitize(metadata, "metadata")
        return detected

    # ─── Default chain builder ────────────────────────────────────────────

    @staticmethod
    def _build_default_chain(model_name: str, temperature: float, max_tokens: int) -> Any:
        """Build a minimal ChatPromptTemplate | ChatOpenAI chain.

        Raises ImportError if langchain-core / langchain-openai are absent,
        which is the intended behaviour — callers must install the extras.
        """
        try:
            from langchain_core.prompts import ChatPromptTemplate
        except ImportError as err:
            raise ImportError(
                "LangChainPlanner requires 'langchain-core'. "
                "Install it with: pip install finguard[langchain]"
            ) from err

        # Build a two-message prompt: static system + dynamic human.
        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", "{system}"),
                ("human", "{human}"),
            ]
        )

        try:
            from langchain_openai import ChatOpenAI

            llm = ChatOpenAI(
                model=model_name,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except ImportError:
            # Fall back to a minimal stub that fails gracefully at call time.
            llm = _UnavailableLLMStub(model_name)

        return prompt | llm


class _UnavailableLLMStub:
    """Stub that raises a clear error when langchain-openai is absent."""

    def __init__(self, model_name: str) -> None:
        self._model_name = model_name

    def invoke(self, _: Any) -> str:
        raise ImportError(
            f"Model '{self._model_name}' requires 'langchain-openai'. "
            "Install it with: pip install langchain-openai"
        )
