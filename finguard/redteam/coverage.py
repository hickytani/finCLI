"""Explicit coverage metadata for every current red-team runner entry."""

ATTACK_COVERAGE = [
    {"attack_id": "RT-001", "attack_family": "authority", "boundary": "identity authority limit", "independence": "independent", "evidence": "DecisionReceipt, simulator rejection, balance snapshot", "status": "measured"},
    {"attack_id": "RT-002", "attack_family": "tool surface", "boundary": "agent-to-signing capability boundary", "independence": "independent", "evidence": "request SDK cannot submit signing operation", "status": "not_applicable_for_balance"},
    {"attack_id": "RT-003", "attack_family": "prompt injection", "boundary": "AI input remains advisory", "independence": "variant of authority", "evidence": "DecisionReceipt, simulator rejection, balance snapshot", "status": "measured"},
    {"attack_id": "RT-004", "attack_family": "execution bypass", "boundary": "SigningGate to simulator", "independence": "independent", "evidence": "Simulator rejection and balance snapshot", "status": "measured"},
    {"attack_id": "RT-005", "attack_family": "authority", "boundary": "identity authority limit", "independence": "duplicate of RT-001", "evidence": "YAML result and expected-reason assertion", "status": "scenario-measured"},
    {"attack_id": "RT-006", "attack_family": "integrity", "boundary": "approval-bound transaction hash", "independence": "variant of RT-007", "evidence": "hash mismatch and scenario signing assertion", "status": "scenario-measured"},
    {"attack_id": "RT-007", "attack_family": "integrity", "boundary": "approval-bound transaction hash", "independence": "variant of RT-006", "evidence": "hash mismatch and scenario signing assertion", "status": "scenario-measured"},
    {"attack_id": "RT-008", "attack_family": "nonce replay", "boundary": "nonce registration", "independence": "independent", "evidence": "nonce reuse and expected-reason assertion", "status": "scenario-measured"},
    {"attack_id": "RT-009", "attack_family": "execution replay", "boundary": "simulator execution uniqueness", "independence": "variant of RT-008", "evidence": "first settlement, second rejection, balance snapshot", "status": "measured"},
    {"attack_id": "RT-010", "attack_family": "approval forgery", "boundary": "approval signature integrity", "independence": "independent", "evidence": "SigningGate rejection and unchanged balances", "status": "measured"},
    {"attack_id": "RT-011", "attack_family": "approval reuse", "boundary": "approval transaction binding", "independence": "independent", "evidence": "cross-transaction SigningGate rejection", "status": "measured"},
    {"attack_id": "RT-012", "attack_family": "policy integrity", "boundary": "policy version/hash at signing", "independence": "independent", "evidence": "SigningGate rejection and unchanged balances", "status": "measured"},
    {"attack_id": "RT-013", "attack_family": "concurrent replay", "boundary": "atomic simulator execution record", "independence": "independent", "evidence": "one authorized winner, three rejected duplicates, balance snapshot", "status": "measured"},
    {"attack_id": "RT-014", "attack_family": "identity", "boundary": "signed actor type and identity", "independence": "independent", "evidence": "DecisionReceipt BLOCK reason and unchanged balances", "status": "measured"},
    {"attack_id": "RT-015", "attack_family": "session", "boundary": "required agent session binding", "independence": "independent", "evidence": "DecisionReceipt BLOCK reason and unchanged balances", "status": "measured"},
    {"attack_id": "RT-016", "attack_family": "AI/tool bypass", "boundary": "SigningGate and simulator", "independence": "independent", "evidence": "signing and simulator rejection with balance snapshots", "status": "measured"},
    {"attack_id": "RT-017", "attack_family": "multi-step chain", "boundary": "decision, approval, signing, execution", "independence": "independent", "evidence": "mutation signing rejection and unchanged balances", "status": "measured"},
]


def coverage_by_id() -> dict[str, dict]:
    return {entry["attack_id"]: entry.copy() for entry in ATTACK_COVERAGE}
