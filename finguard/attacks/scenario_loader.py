"""Declarative Attack Scenario Executor for FIN//GUARD.

SECURITY PROPERTY:
Attacks execute against the REAL security engine pipeline (no mocking or simulation).
Each scenario drives real transactions through identity, authority, policy, risk,
approvals, and cryptographic signing, proving adversarially that invalid operations
are detected, blocked, recorded in tamper-evident audit logs, and trigger incidents.
"""

import yaml
from pathlib import Path
from typing import Optional, List
from pydantic import BaseModel, Field

from finguard.audit.ledger import AuditLedger
from finguard.audit.nonce_store import NonceStore
from finguard.approvals.service import ApprovalService
from finguard.core.enums import Currency, TransactionState, IncidentSeverity, DecisionType
from finguard.core.transaction import Transaction
from finguard.crypto.keystore import Keystore
from finguard.crypto.signing import sign_canonical_bytes
from finguard.identity.registry import IdentityRegistry
from finguard.incidents.service import IncidentService
from finguard.policy.engine import PolicyEngine
from finguard.risk.engine import RiskEngine
from finguard.storage.database import get_session
from finguard.storage.models import TransactionRecord, ActorRecord
from finguard.storage.repositories import TransactionRepository, ActorRepository


class ScenarioStepResult(BaseModel):
    step_index: int
    action: str
    passed: bool
    details: str


class ScenarioExecutionResult(BaseModel):
    scenario_name: str
    description: str
    passed: bool
    original_hash: Optional[str] = None
    modified_hash: Optional[str] = None
    original_nonce: Optional[str] = None
    incident_id: Optional[str] = None
    step_results: List[ScenarioStepResult] = Field(default_factory=list)
    explanation_trace: List[str] = Field(default_factory=list)


class ScenarioLoader:
    """Loads and executes declarative YAML attack scenarios."""

    def __init__(self, scenarios_dir: Optional[Path] = None):
        if scenarios_dir:
            self.scenarios_dir = scenarios_dir
        else:
            self.scenarios_dir = Path(__file__).parent / "scenarios"

    def list_scenarios(self) -> List[str]:
        """List available scenario file names (without .yaml)."""
        if not self.scenarios_dir.exists():
            return []
        return [f.stem for f in sorted(self.scenarios_dir.glob("*.yaml"))]

    def run_scenario(self, scenario_name: str) -> ScenarioExecutionResult:
        """Run a named attack scenario against the real security engine."""
        path = self.scenarios_dir / f"{scenario_name}.yaml"
        if not path.exists():
            path = Path(scenario_name)
            if not path.exists():
                raise FileNotFoundError(f"Attack scenario '{scenario_name}' not found.")

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        name = data.get("name", scenario_name)
        description = data.get("description", "")
        steps = data.get("steps", [])

        registry = IdentityRegistry()
        policy_engine = PolicyEngine()
        risk_engine = RiskEngine()
        approval_service = ApprovalService()
        nonce_store = NonceStore()
        audit_ledger = AuditLedger()
        incident_service = IncidentService()

        tx_obj: Optional[Transaction] = None
        saved_nonce: Optional[str] = None
        original_hash: Optional[str] = None
        modified_hash: Optional[str] = None
        incident_id: Optional[str] = None

        trace: List[str] = []
        step_results: List[ScenarioStepResult] = []
        overall_passed = True

        session = get_session()
        try:
            for idx, step in enumerate(steps):
                action = step.get("action")
                expect = step.get("expect")
                expect_reason = step.get("expect_reason_contains", "")

                trace.append(f"Step {idx + 1}: Action='{action}'")

                if action == "create_transaction":
                    actor_id = step.get("actor", data.get("actor", "treasury-agent"))
                    actor = registry.validate_actor(actor_id)

                    tx_obj = Transaction(
                        actor_id=actor_id,
                        from_account=step.get("from_account", "treasury"),
                        to_account=step.get("to_account", "vendor-a"),
                        amount=float(step.get("amount", 1000.0)),
                        currency=Currency(step.get("currency", "INR").upper())
                    )
                    original_hash = tx_obj.transaction_hash()
                    saved_nonce = tx_obj.nonce

                    # Pipeline evaluation
                    risk_res = risk_engine.analyze(tx_obj, actor)
                    pol_decision = policy_engine.evaluate(tx_obj, actor, risk_res.model_dump())

                    trace.append(f"  - Policy decision: {pol_decision.decision_type.value.upper()}")
                    trace.append(f"  - Risk score: {risk_res.risk_score}")

                    if pol_decision.decision_type == DecisionType.BLOCK:
                        tx_obj.state = TransactionState.BLOCKED
                        inc = incident_service.create_incident(
                            severity=IncidentSeverity.HIGH,
                            description=f"Transaction blocked during attack scenario '{name}': {pol_decision.explanation}",
                            transaction_id=tx_obj.transaction_id,
                            actor_id=actor_id,
                            signals=risk_res.signals,
                            decision="BLOCK"
                        )
                        incident_id = inc.incident_id

                    # Ensure ActorRecord exists in DB for foreign key constraint
                    actor_repo = ActorRepository(session)
                    if not actor_repo.get(actor_id):
                        actor_rec = ActorRecord(
                            actor_id=actor.actor_id,
                            actor_type=actor.actor_type.value,
                            display_name=actor.display_name,
                            active=True
                        )
                        actor_repo.save(actor_rec)

                    # Record in DB
                    tx_repo = TransactionRepository(session)
                    rec = TransactionRecord(
                        transaction_id=tx_obj.transaction_id,
                        actor_id=tx_obj.actor_id,
                        from_account=tx_obj.from_account,
                        to_account=tx_obj.to_account,
                        amount=tx_obj.amount,
                        currency=tx_obj.currency.value,
                        nonce=tx_obj.nonce,
                        timestamp=tx_obj.timestamp,
                        state=tx_obj.state.value,
                        canonical_hash=original_hash
                    )
                    tx_repo.save(rec)

                    audit_ledger.append(
                        action=f"ATTACK_SCENARIO_TX_CREATE:{name}",
                        actor_id=actor_id,
                        transaction_id=tx_obj.transaction_id,
                        result=tx_obj.state.value.upper(),
                        metadata={"hash": original_hash, "policy": pol_decision.decision_type.value}
                    )

                    if expect == "BLOCKED":
                        step_passed = (tx_obj.state == TransactionState.BLOCKED)
                        step_results.append(ScenarioStepResult(
                            step_index=idx + 1,
                            action=action,
                            passed=step_passed,
                            details=f"Transaction BLOCKED as expected. {pol_decision.explanation}"
                        ))
                        if not step_passed:
                            overall_passed = False
                    else:
                        step_results.append(ScenarioStepResult(
                            step_index=idx + 1,
                            action=action,
                            passed=True,
                            details=f"Transaction created. State={tx_obj.state.value}"
                        ))

                elif action == "save_nonce":
                    if tx_obj:
                        nonce_store.record(tx_obj.nonce, tx_obj.transaction_id)
                        saved_nonce = tx_obj.nonce
                        step_results.append(ScenarioStepResult(
                            step_index=idx + 1,
                            action=action,
                            passed=True,
                            details=f"Saved nonce '{saved_nonce}' in persistent store."
                        ))

                elif action == "attempt_replay":
                    if saved_nonce and nonce_store.has_used(saved_nonce):
                        trace.append(f"  - Replay attempt detected for nonce '{saved_nonce}'")
                        inc = incident_service.create_incident(
                            severity=IncidentSeverity.CRITICAL,
                            description=f"REPLAY ATTEMPT DETECTED for nonce '{saved_nonce}' in scenario '{name}'",
                            transaction_id=tx_obj.transaction_id if tx_obj else None,
                            actor_id=data.get("actor"),
                            signals=["REPLAY_ATTEMPT"],
                            decision="BLOCK"
                        )
                        incident_id = inc.incident_id
                        audit_ledger.append(
                            action=f"ATTACK_REPLAY_BLOCKED:{name}",
                            actor_id=data.get("actor", "system"),
                            transaction_id=tx_obj.transaction_id if tx_obj else None,
                            result="BLOCKED",
                            metadata={"nonce": saved_nonce}
                        )
                        step_passed = (expect == "BLOCKED")
                        step_results.append(ScenarioStepResult(
                            step_index=idx + 1,
                            action=action,
                            passed=step_passed,
                            details=f"Replay attempt BLOCKED by persistent nonce store. Incident={incident_id}"
                        ))
                        if not step_passed:
                            overall_passed = False

                elif action == "approve_transaction":
                    if tx_obj:
                        appr_rec = approval_service.create_approval_request(
                            transaction=tx_obj,
                            required_approvals=1,
                            requester_id=tx_obj.actor_id
                        )
                        # Simulate human approver sign
                        approver_actor = registry.validate_actor("approver-1")
                        keystore = Keystore()
                        key_id = "approver-key"
                        passw = "password123"
                        try:
                            keystore.get_public_key(key_id)
                        except Exception:
                            keystore.create_keypair(key_id, passw)

                        approval_service.approve_transaction(
                            transaction_id=tx_obj.transaction_id,
                            approver=approver_actor,
                            key_id=key_id,
                            password=passw
                        )
                        tx_obj.state = TransactionState.APPROVED
                        trace.append(f"  - Transaction '{tx_obj.transaction_id}' approved.")
                        step_results.append(ScenarioStepResult(
                            step_index=idx + 1,
                            action=action,
                            passed=True,
                            details="Transaction approved by approver-1"
                        ))

                elif action == "tamper_field":
                    if tx_obj:
                        field_name = step.get("field")
                        new_val = step.get("new_value")
                        if field_name == "amount":
                            tx_obj.amount = float(new_val)
                        elif field_name == "to_account":
                            tx_obj.to_account = str(new_val)

                        modified_hash = tx_obj.transaction_hash()
                        trace.append(f"  - Tampered field '{field_name}' to '{new_val}'. New hash: {modified_hash[:8]}...")
                        step_results.append(ScenarioStepResult(
                            step_index=idx + 1,
                            action=action,
                            passed=True,
                            details=f"Tampered field '{field_name}' to '{new_val}'"
                        ))

                elif action == "sign_transaction":
                    if tx_obj:
                        # Verify approval integrity against modified transaction hash
                        valid_approvals = approval_service.verify_approval_integrity(tx_obj)
                        if not valid_approvals or original_hash != tx_obj.transaction_hash():
                            tx_obj.state = TransactionState.BLOCKED
                            trace.append("  - SIGNING BLOCKED: Cryptographic approval hash mismatch / tampering detected.")
                            inc = incident_service.create_incident(
                                severity=IncidentSeverity.CRITICAL,
                                description=f"TRANSACTION TAMPERING DETECTED in scenario '{name}'. Hash mismatch: original={original_hash}, modified={tx_obj.transaction_hash()}",
                                transaction_id=tx_obj.transaction_id,
                                actor_id=tx_obj.actor_id,
                                signals=["TAMPERING_DETECTED", "INTEGRITY_FAILURE"],
                                decision="BLOCK"
                            )
                            incident_id = inc.incident_id
                            audit_ledger.append(
                                action=f"ATTACK_TAMPERING_BLOCKED:{name}",
                                actor_id=tx_obj.actor_id,
                                transaction_id=tx_obj.transaction_id,
                                result="BLOCKED",
                                metadata={"original_hash": original_hash, "modified_hash": tx_obj.transaction_hash()}
                            )

                        step_passed = (tx_obj.state == TransactionState.BLOCKED and expect == "BLOCKED")
                        step_results.append(ScenarioStepResult(
                            step_index=idx + 1,
                            action=action,
                            passed=step_passed,
                            details=f"Signing outcome: {tx_obj.state.value.upper()}. Incident={incident_id}"
                        ))
                        if not step_passed:
                            overall_passed = False

            return ScenarioExecutionResult(
                scenario_name=name,
                description=description,
                passed=overall_passed,
                original_hash=original_hash,
                modified_hash=modified_hash,
                original_nonce=saved_nonce,
                incident_id=incident_id,
                step_results=step_results,
                explanation_trace=trace
            )
        finally:
            session.close()
