# FIN//GUARD Current MVP Limitations & Scope (M6)

## Purpose & Research Scope

FIN//GUARD is a **research-grade security architecture** demonstrating how financial agents can operate safely under the assumption that the LLM is an **untrusted principal**.

To maintain technical credibility, this document explicitly lists what the current MVP **does and does not prove**.

---

## What the Current MVP Proves
1. **Model non-authority**: A compromised or prompt-injected LLM returning `approved=true`, `signer=root`, `grant_capability=admin`, or `private_key=secret` cannot bypass deterministic security boundaries.
2. **Structural boundary isolation**: The MCP server (`finguard.mcp`) and LLM pipeline (`finguard.ai`) do not import or access signing gates, keystores, or financial simulator execution functions.
3. **Exact money & integer arithmetic**: All financial amounts use exact integer minor units (`Money`). Floats are forbidden in core decision/signing/simulation paths.
4. **Audit trail integrity**: All decisions, receipts, and guardrail checks generate sequence-bound audit records verified by signed checkpoints.

---

## Technical & Operational Limitations

### 1. LLM Provider Scope
- **Current Support**: Local Ollama instance (default `qwen3:0.6b` or `qwen2.5:1.5b`) and `MockLLMProvider` / `CompromisedLLMProvider` for CI testing.
- **Not Implemented**: Cloud LLM provider adapters (OpenAI, Anthropic, Bedrock) are not integrated in the default CLI pipeline.

### 2. Financial Execution Environment
- **Current Support**: In-memory / SQLite virtual ledger simulator (`finguard.simulator`). Synthetic currencies (`INR`, `USD`, `EUR`).
- **Not Implemented**: Real banking APIs, ACH networks, ISO 20022 wire protocols, or live crypto wallets. Real money movement is explicitly out of scope.

### 3. Human Approval Interface
- **Current Support**: CLI approval subcommand (`finguard approval approve`) and programmatic `ApprovalService`.
- **Not Implemented**: Web dashboard UI or push-notification approval workflow. Human approval requires executing a CLI command with an authorized approver key.

### 4. Persistence & Distributed Anchoring
- **Current Support**: Local SQLite database with WAL mode, `BEGIN IMMEDIATE` transaction locking, and SQLite append-only trigger protection.
- **Not Implemented**: Distributed multi-node consensus, public blockchain anchoring, or external RFC 3161 timestamping authorities.

### 5. Adversarial Benchmark Scope
- **Current Support**: 52-case adversarial catalog across 42 categories and 15 composed multi-step agent attack scenarios.
- **Not Implemented**: Continuous automated fuzzing against live multi-agent environments.
