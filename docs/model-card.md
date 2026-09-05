# Model card

## Phase 2C local LLM adapter

FinGuard can call the locally installed Ollama model `qwen3:0.6b` solely to
extract an explicit payment request and produce advisory risk text. The adapter
uses Ollama's local loopback API, requests JSON, bounds input to 4,000
characters, and validates every response with Pydantic before any SDK call.

The model is untrusted: invalid, unavailable, ambiguous, or malformed output
creates no transaction. Valid output flows only through the request-only SDK
and the deterministic DecisionEngine. It cannot sign, approve, retrieve keys,
change identity, change policy, or override authority, risk, nonce, or policy
controls. No model quality, accuracy, fraud-detection, or financial-performance
metric is claimed. Fine-tuning was not performed.
