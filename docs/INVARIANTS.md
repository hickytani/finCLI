# FIN//GUARD Security Invariants Specification (I1 - I14)

| Invariant | Description | Enforcement Point | Proving Test | Attack Test | Current Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **I1** | A transaction is signed at most once. | `signing/gate.py` CAS update | `test_security_core_phase2b.py` | `test_concurrent_sign_attempts` | Partial (F4 pending) |
| **I2** | SIGNED requires a stored ALLOW receipt or APPROVED approval bound to exact tx hash. | `signing/gate.py` | `test_direct_signing_without_decision_receipt_is_rejected` | `test_forged_approval_hash_mismatch` | Proven |
| **I3** | tx hash at signing == tx hash at decision == tx hash at approval == execution. | `signing/gate.py`, `approvals/service.py` | `test_transaction_mutation_blocks_final_signing` | `test_stale_transaction_mutation` | Proven |
| **I4** | A nonce is consumed at most once; idempotency key reuse with different body rejected. | `storage/models.py` (UniqueConstraint), `audit/nonce_store.py` | `test_transaction_replay_with_same_nonce` | `test_transaction_replay_with_same_nonce_fails_closed` | Partial (F3/F4 pending) |
| **I5** | Approver != requester; approver holds APPROVER authority; approval single-use & expiring. | `approvals/service.py` | `test_agent_cannot_approve_own_transaction` | `test_maker_checker_self_approval_rejected` | Partial (F2/Appendix A fix pending) |
| **I6** | AI/MCP output never sets actor, nonce, signature, policy, decision, state. | `ai/analyzer.py`, `ai/schemas.py` | `test_model_failure_does_not_become_a_transaction` | `test_prompt_injected_llm_output_cannot_create_executable_high_value_transfer` | Proven |
| **I7** | Ledger is append-only, gap-free (seq), hash-linked; head covered by signed checkpoint. | `audit/ledger.py` | `test_audit_ledger_append_and_verify_integrity` | `test_audit_ledger_hash_chain_tamper_detection` | Partial (F5 pending) |
| **I8** | Money is exact; no float in canonical bytes or comparisons. | `core/canonical.py`, `core/transaction.py` | `test_canonical_amount_fixed_point` | `test_positive_amount_never_signs_as_zero` | Partial (M1 / FG-201 pending) |
| **I9** | Any exception in decision or signing paths results in BLOCKED/FAILED (fail-closed). | `decision/engine.py`, `signing/gate.py` | `test_unknown_identity_fails_closed` | `test_malformed_model_output_is_not_security_blocking` | Proven |
| **I10** | MCP surface cannot reach signing, approval, key, or policy-mutation code paths. | `finguard/mcp/server.py` | `test_mcp_surface_restrictions` | `test_mcp_tool_execution_bypass` | Unproven (M4 / FG-501 pending) |
| **I11** | Private keys never appear in logs, errors, receipts or exceptions. | `crypto/keystore.py`, `crypto/signing.py` | `test_keystore_generate_and_unlock` | `test_key_leakage_in_error_logs` | Proven |
| **I12** | Decision + nonce claim + receipt + ledger entry are atomic. | `decision/engine.py` (Unit of Work) | `test_atomic_decision_unit_of_work` | `test_fault_injection_partial_state` | Unproven (M2 / FG-301 pending) |
| **I13** | Authority defaults deny; wildcard is explicit and audited. | `core/authority.py`, `identity/registry.py` | `test_default_authority_does_not_allow_arbitrary_destinations` | `test_authority_wildcard_bypass` | Partial (M1 / FG-203 pending) |
| **I14** | Balance conservation: sum of simulator balances invariant across executed transfers. | `simulator/service.py` | `test_simulator_balance_conservation` | `test_simulator_float_drift_attack` | Partial (M1 / FG-205 pending) |
