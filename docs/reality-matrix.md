# Reality matrix

## Implemented

Ed25519 signing, encrypted local keystore, signed identity registry, canonical
transaction hashing, deterministic policy/risk, hash-chain audit, SQLite replay
constraints, decision receipts, bounded SDK, mandatory agent approval, final
signing revalidation, Ollama/Qwen structured extraction, and executable
regression tests.

The local financial simulator has virtual accounts only. It verifies the
stored canonical transaction and Ed25519 signature before atomically settling
one virtual movement and emitting audit evidence.

## Partial

Local AI extraction is real but untrusted and advisory. It has no measured
accuracy, fraud-detection performance, or reliability claim. The simulator is
a security demo, not a banking ledger or payment rail.

## Future / not performed

Bank APIs, real funds, HSM/KMS, commercial fraud feeds, public ML training,
and LoRA/QLoRA fine-tuning. **No model, dataset size, metric, latency, or
attack rate is claimed where it was not measured.**
