# Milestone M11 — Identity, Account Disambiguation & Tenant Isolation Report

## Executive Summary

Milestone **M11** implements production-grade account alias resolution, NFKC Unicode normalization, mixed-script homoglyph rejection, zero-width control character rejection, and cross-tenant boundary isolation.

### Key Architectural Enhancements
1. **Account Registry (`finguard/identity/account_registry.py`)**:
   - Enforces strict regex validation for account IDs (`^[a-z0-9][a-z0-9_.-]{1,62}$`).
   - Normalizes aliases using **Unicode NFKC + casefold**.
   - Explicitly rejects confusable mixed-script characters (homoglyphs) and zero-width control characters (`\u200b`, `\u200c`, `\ufeff`, etc.).
   - Rejects ambiguous alias mappings (`AMBIGUOUS_ALIAS`) where an alias resolves to multiple active account IDs.
   - Enforces tenant boundary validation (`validate_tenant_boundary`) to prevent cross-tenant balance drains or unauthorized transfers.
2. **Decision Engine Integration (`finguard/decision/engine.py`)**:
   - Integrates `AccountRegistry` directly into `DecisionEngine.decide()`.
   - Normalizes and resolves `from_account` and `to_account` prior to policy evaluation.
   - Rejects agent wildcard `"*"` source or destination permissions, enforcing strict explicit allowlists.

---

## Verification Evidence

### Test Suite (`tests/security/test_m11_identity_isolation.py`)
- `test_m11_alias_nfkc_and_casefold_normalization`: PASSED
- `test_m11_zero_width_and_control_character_rejection`: PASSED
- `test_m11_mixed_script_homoglyph_rejection`: PASSED
- `test_m11_account_registry_alias_resolution`: PASSED
- `test_m11_ambiguous_alias_rejection`: PASSED
- `test_m11_tenant_boundary_validation`: PASSED
- `test_m11_transaction_blocks_zero_width_destination`: PASSED
- `test_m11_agent_wildcard_source_and_destination_forbidden`: PASSED

```powershell
.\.venv\Scripts\python.exe -m pytest tests/security/test_m11_identity_isolation.py -v
```
Result: **8 passed in 2.41s**
