# M8 — Zero-Trust LangChain Integration, Guardrails & Bounded Orchestration

**Branch:** `m8-langchain-zero-trust`  
**Status:** Implementation complete — tests green  
**Thesis:** *LangChain is an integration framework, NOT the security authority.*

---

## 1. Design Principle

The core thesis of FIN//GUARD is that the AI/LLM component is an **untrusted principal**.  
M8 extends this thesis to LangChain:

> All LangChain output — chain output, tool output, retrieved content, and memory — is treated as **untrusted data**.  
> It enters the system through the same `ExtractionResult` boundary that governs every other LLM provider.  
> The security enforcement path (`StructuredIntentBoundary → DecisionEngine → SigningGate`) is never touched by LangChain.

**Non-negotiable invariants:**
- `LangChainPlanner` implements `LLMProvider` — a *proposal* interface, never an *authority* interface.
- LangChain is an **optional** dependency (`pip install finguard[langchain]`). The rest of the package is fully importable without it.
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
  ├── _invoke_chain()                ← output size-bounded to 8 192 bytes
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

LangChain **stops** at `ExtractionResult`. It never reaches the signing gate.

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

Before any JSON parsing, the chain output is bounded to `_MAX_CHAIN_OUTPUT_BYTES = 8 192`. Any larger output raises a `ValueError` → `ExtractionResult(extraction_success=False)`.

### 4.3 ExtractionResult Validation

Every chain output goes through `ExtractionResult.model_validate()`:
- `extra="forbid"` — any field not in the five-field allowlist is detected and stripped.
- Authority-shaped fields (`approved`, `authorized`, `signer`, `policy_override`, `actor_id`, `session_id`, `private_key`, …) are stripped and recorded in `authority_fields_detected`.
- `amount` must be `str | int`, never `float` or `bool`.
- `amount` must be positive, representable in the currency's minor units, and below `MAX_AMOUNT_MINOR`.

### 4.4 Retrieved Content Isolation

When `retrieval_fn` is provided, the retrieved text is appended to the human message with explicit `[UNTRUSTED RETRIEVED CONTEXT]` / `[END UNTRUSTED CONTEXT]` markers. The retrieved content is **never** injected into the system role. If `retrieval_fn` raises, extraction proceeds without context (fail-safe).

### 4.5 Fail-Closed on Exception

Any exception from LangChain (network error, timeout, bad output, import error) produces `ExtractionResult(extraction_success=False)`. This propagates as `final_decision="EXTRACTION_FAILED"` in the pipeline — never as an authorized action.

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
| G10 | Duplicate JSON keys | `"amount"` appears twice | Handled safely; no authority |
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

## 7. Security Properties Preserved

M8 does **not** change or weaken any existing security property:

| Property | M8 impact |
|---|---|
| LLM output is untrusted | ✅ Preserved — LangChain output goes through `ExtractionResult` |
| MCP cannot authorize | ✅ Preserved — `MCPSecurityBoundary` unchanged |
| SigningGate re-validates | ✅ Preserved — never imported by this module |
| Ledger is append-only | ✅ Preserved — not touched |
| M4 orchestration bounds | ✅ Preserved — `BoundedOrchestrator` config unchanged |
| Fail-closed on exception | ✅ Preserved — any LangChain error → `extraction_success=False` |

---

## 8. What LangChain Cannot Do

By construction (structural enforcement, not prompting):

- ❌ Cannot sign a transaction
- ❌ Cannot approve a transaction
- ❌ Cannot bypass `StructuredIntentBoundary`
- ❌ Cannot bypass `AgentGuardrails`
- ❌ Cannot set `actor_id`, `session_id`, or `nonce`
- ❌ Cannot override `BoundedOrchestrator` limits
- ❌ Cannot inject retrieved content into the system role
- ❌ Cannot grant capabilities

---

## 9. Limitations and Future Work

- The real-world Ollama + LangChain integration requires `langchain-ollama`; the test suite uses offline stubs.
- LangChain memory backends are not tested against a real vector store — `MemoryEscalationChain` simulates the attack pattern deterministically.
- LangChain tool-use / function-calling mode is not yet integrated; if added, each tool must be explicitly allowlisted and sandboxed.
- Comparison with NeMo Guardrails / LLM Guard is deferred to M5 (FG-601).
