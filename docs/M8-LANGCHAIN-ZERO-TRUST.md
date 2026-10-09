# M8 — Zero-Trust LangChain Integration, Guardrails & Bounded Orchestration

**Branch:** `m8-langchain-zero-trust`  
**Status:** Implementation complete — tests green  
**Thesis:** *LangChain is an integration framework, NOT the security authority.*

---

## 1. Design Principle

The core thesis of FIN//GUARD is that the AI/LLM component is an **untrusted principal**.  
M8 extends this thesis to LangChain:

> The adapter treats model output and retrieved text as **untrusted data** and validates extraction output through `ExtractionResult`.
> The adapter itself does not call signing, approval, or execution services. The normal proposal path continues through the existing deterministic boundaries.

This describes the adapter and the configured pipeline, not a Python sandbox. A caller-supplied LangChain `Runnable`, tool, callback, or retrieval function is executable host code. Do not give those components signing, approval, policy-mutation, or execution capabilities. The adapter cannot prevent a custom runnable from performing side effects internally.

**Non-negotiable invariants:**
- `LangChainPlanner` implements `LLMProvider` — a *proposal* interface, never an *authority* interface.
- LangChain is an **optional** dependency (`pip install finguard[langchain]`). The deterministic core imports tested in M8.1 do not require it; see the verification report for scope.
- No second policy engine, no parallel ledger, no alternative approval mechanism.

---

## 2. Architecture

```
Natural Language Request
        │
        ▼
LangChainPlanner.extract_transaction()
  ├── _build_human_message()         ← static system prompt; retrieved content tagged [UNTRUSTED]
  ├── chain.invoke()                 ← LangChain Runnable (ChatOpenAI, local Ollama, etc.)
  ├── _invoke_chain()                 ← returned text bounded to 8 192 bytes
  └── _parse_chain_output()          ← JSON parse → ExtractionResult (strips authority fields)
        │
        ▼
ExtractionResult (validated, authority fields stripped)
        │ UNTRUSTED DATA ONLY
        ▼
LLMPipeline.process_request()        ← unchanged; accepts any LLMProvider
        │
        ▼
ProposeTransactionRequest (Pydantic — rejects authority-shaped input)
        │
        ▼
MCPSecurityBoundary.propose_transaction()   ← M5 — no change
        │
        ▼
BoundedOrchestrator (M4) → StructuredIntentBoundary (M3.1) → AgentGuardrails (M3.2)
        │
        ▼
DecisionEngine → [BLOCKED | REQUIRE_APPROVAL]
```

The adapter returns only an `ExtractionResult`; the tested pipeline sends valid proposals through the configured MCP and deterministic intent/guardrail path. The adapter does not call the signing gate. This does not sandbox arbitrary code supplied as a runnable, tool, callback, or retrieval function.

---

## 3. Files

| File | Role |
|---|---|
| [`finguard/ai/langchain_planner.py`](../finguard/ai/langchain_planner.py) | `LangChainPlanner` — the zero-trust adapter |
| [`finguard/ai/langchain_stub.py`](../finguard/ai/langchain_stub.py) | Offline stubs for deterministic security testing |
| [`tests/security/test_m8_langchain_zero_trust.py`](../tests/security/test_m8_langchain_zero_trust.py) | 20 attack groups, positive controls, end-to-end pipeline test |

---

## 4. Zero-Trust Mechanisms

### 4.1 Static System Prompt

The system prompt is a **string constant** in `langchain_planner.py`. No user content, retrieved context, or memory ever flows into the system role. Only the human message receives dynamic content, and retrieved content is explicitly wrapped in an `[UNTRUSTED RETRIEVED CONTEXT]` marker.

```python
_SYSTEM_PROMPT = (
    "You are a transaction extraction assistant.\n"
    "Extract ONLY these fields ...\n"
    "You CANNOT approve, authorize, sign, execute, or grant capabilities.\n"
    ...
)
```

### 4.2 Output Size Bound

After `chain.invoke()` returns, textual output is bounded to `_MAX_CHAIN_OUTPUT_BYTES = 8 192` before JSON parsing. Any larger output fails extraction. This is an output/parser bound only: it does not limit request or retrieved-context size, model-side work, runnable execution time, or side effects performed before the result is returned.

### 4.3 ExtractionResult Validation

Every chain output goes through `ExtractionResult.model_validate()`:
- `extra="forbid"` — any field not in the five-field allowlist is detected and stripped.
- Authority-shaped fields (`approved`, `authorized`, `signer`, `policy_override`, `actor_id`, `session_id`, `private_key`, …) are stripped and recorded in `authority_fields_detected`.
- `amount` must be `str | int`, never `float` or `bool`.
- `amount` must be positive, representable in the currency's minor units, and below `MAX_AMOUNT_MINOR`.

### 4.4 Retrieved Content Isolation

When `retrieval_fn` is provided, returned text is appended to the human message with explicit `[UNTRUSTED RETRIEVED CONTEXT]` / `[END UNTRUSTED CONTEXT]` markers. The adapter does not put it in the separate system string supplied to the runnable. This marker is defense in depth, not a security boundary. If `retrieval_fn` raises, extraction proceeds without retrieved context; the normal deterministic authorization path still applies.

### 4.5 Fail-Closed on Exception

An exception raised while invoking the runnable, or an invalid response, produces `ExtractionResult(extraction_success=False)`. The adapter does not impose a timeout or cancellation policy: a runnable that never returns can block, and retry behavior is controlled by the supplied runnable. A caller may configure retries, but arbitrary runnable side effects cannot be made exactly-once by this adapter.

---

## 5. Attack Groups Tested

| # | Group | Mechanism | Expected outcome |
|---|---|---|---|
| G1 | Authority-field injection | `approved`, `signer`, `policy_override` in chain output | Fields stripped; `authority_fields_detected` populated |
| G2 | System-prompt override | Chain claims "Authorization: GRANTED" in reason | Reason is data; no authority granted |
| G3 | Tool-call injection in reason | `<tool>approve_transaction()</tool>` in reason | Reason is text; not executed |
| G4 | Oversized chain output | 10 000-byte payload | `extraction_success=False` |
| G5 | Invalid / non-JSON output | XML, HTML tool calls | `extraction_success=False` |
| G6 | NaN amount | `NaN` as JSON constant | `extraction_success=False` |
| G7 | Zero amount | `"0.00"` | `extraction_success=False` |
| G8 | Float amount | Python `float` (500.0) | `extraction_success=False` |
| G9 | Very-long reason | 10 000-char reason | `extraction_success=False` |
| G10 | Duplicate JSON keys | `"amount"` appears twice | Rejected as ambiguous JSON |
| G11 | Nested authority fields | `metadata: {approved: True}` | Extra field stripped/blocked |
| G12 | Retrieval / RAG injection | Retrieved text contains injection | Authority fields stripped; retrieval error → fail-safe |
| G13 | Memory-based multi-turn escalation | Turn 2 injects `authorized=True` | Stripped on every turn |
| G14 | Actor/session-id injection | `actor_id`, `session_id` from chain | Stripped; never reaches boundary |
| G15 | Chain raises exception | `RuntimeError` from LangChain | Fails closed; no authority |
| G16 | Empty / whitespace output | `""`, `"   "` | `extraction_success=False` |
| G17 | List instead of object | `[{...}]` | `extraction_success=False` |
| G18 | Credential exfiltration | `private_key`, `token`, `secret` | Stripped; never in result |
| G19 | Benign extraction (positive control) | Normal LLM output | `extraction_success=True`, no authority |
| G20 | Pipeline end-to-end | LangChainPlanner + MCPSecurityBoundary | `authorization_status="NOT_AUTHORIZED"` always |

---

## 6. Installation

### Without LangChain (default — all security tests run)
```bash
pip install -e ".[dev]"
py -m pytest tests/security/test_m8_langchain_zero_trust.py -v
```

### With LangChain (for real LLM integration)
```bash
pip install langchain-core langchain-openai
# or: pip install -e ".[langchain]"

from finguard.ai.langchain_planner import LangChainPlanner
from finguard.ai.pipeline import LLMPipeline

planner = LangChainPlanner(model_name="gpt-4o-mini")
pipeline = LLMPipeline(provider=planner)
result = pipeline.process_request("Pay vendor_42 INR 5000 for invoice #1234")
print(result.final_decision)        # "block" or "require_approval" — NEVER "signed"/"executed"
print(result.boundary_contained)    # always True
```

### With local Ollama via LangChain
```python
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate

prompt = ChatPromptTemplate.from_messages([("system", "{system}"), ("human", "{human}")])
llm = ChatOllama(model="qwen2.5:1.5b", temperature=0)
chain = prompt | llm

planner = LangChainPlanner(chain=chain)
pipeline = LLMPipeline(provider=planner)
```

---

## 7. Security Properties and Verification Scope

M8 does **not** change or weaken any existing security property:

| Property | M8 impact |
|---|---|
| LangChain output is untrusted | Validated by the adapter before it is returned |
| Proposal authorization | The normal pipeline routes proposals through the existing MCP/intent/guardrail path |
| Signing/approval/execution | Not invoked by the adapter; not exercised as part of M8.1 proposal tests |
| Ledger and orchestration | Existing components remain downstream; this adapter does not replace them |
| Invalid output / invocation exception | Returns a failed extraction without forwarding a proposal |
| Timeout, cancellation, arbitrary runnable side effects | Not controlled or sandboxed by this adapter |

---

## 8. What LangChain Cannot Do

For the adapter and tested proposal path:

- ❌ Cannot sign a transaction
- ❌ Cannot approve a transaction
- ❌ Cannot bypass `StructuredIntentBoundary`
- ❌ Cannot bypass `AgentGuardrails`
- ❌ Cannot set `actor_id`, `session_id`, or `nonce`
- ❌ Cannot override `BoundedOrchestrator` limits
- ❌ The adapter does not place retrieved content in its separate system string
- ❌ Cannot grant capabilities

These statements do not apply to arbitrary code inside caller-supplied runnables, tools, callbacks, or retrieval functions. The project does not sandbox Python code.

---

## 9. Limitations and Future Work

- M8.1 exercised `langchain-core`'s real `RunnableLambda` interface with deterministic fake model functions. No live model/provider integration was run. `langchain-openai` and `langchain-ollama` are not required for these tests.
- LangChain memory backends are not tested against a real vector store — `MemoryEscalationChain` simulates the attack pattern deterministically.
- The adapter rejects returned messages carrying tool-call metadata, but does not prevent a tool-bound runnable or callback from executing tools before returning. Tool-use/function-calling is not an authorized integration mode.
- The adapter has no generic timeout/cancellation, request-size, or retrieved-context-size enforcement. Any host using untrusted runnables must isolate them and provide only least-privilege capabilities.
- Comparison with NeMo Guardrails / LLM Guard is deferred to M5 (FG-601).

See [M8.1 audit](./M8.1-AUDIT.md) and [M8.1 verification report](./M8.1-VERIFICATION-REPORT.md) for observed evidence and limits.
