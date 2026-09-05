"""Maker-Checker Approval Service for FIN//GUARD.

SECURITY PROPERTY:
- Pending transactions requiring approval produce an ApprovalRequest record.
- Approvals bind an approver's Ed25519 signature directly to `transaction_hash`.
- Modifying a transaction post-approval changes its `transaction_hash`, invalidating all existing approvals.
- Enforces human approval floor for agent-initiated transactions.
"""

import uuid
import datetime
import json
from typing import Optional
from sqlalchemy.orm import Session

from finguard.core.enums import TransactionState, ActorType, ApprovalState
from finguard.core.errors import SecurityError, IntegrityError
from finguard.core.transaction import Transaction
from finguard.crypto.keystore import Keystore
from finguard.crypto.signing import sign_canonical_bytes, verify_signature
from finguard.crypto.hashing import sha256_hash
from finguard.core.canonical import canonical_serialize
from finguard.policy.engine import PolicyEngine
from finguard.identity.registry import ActorConfig
from finguard.storage.database import get_session
from finguard.storage.models import ApprovalRecord, ApprovalRequestRecord, TransactionRecord, ActorRecord
from finguard.storage.repositories import ApprovalRepository, TransactionRepository, ActorRepository


class ApprovalService:
    """Manages transaction approval workflows and cryptographic signature binding."""

    def __init__(self, session: Optional[Session] = None):
        self._external_session = session

    def _get_session(self) -> tuple[Session, bool]:
        if self._external_session:
            return self._external_session, False
        return get_session(), True

    def create_approval_request(
        self,
        transaction: Transaction,
        required_approvals: int,
        requester_id: str
    ) -> ApprovalRequestRecord:
        """Create a new approval request for a transaction requiring maker-checker authorization."""
        session, is_local = self._get_session()
        try:
            repo = ApprovalRepository(session)
            existing = repo.get_request(transaction.transaction_id)
            if existing:
                return existing

            policy = PolicyEngine().policy
            policy_hash = sha256_hash(canonical_serialize(policy.model_dump(mode="json")))
            req = ApprovalRequestRecord(
                request_id=f"REQ-{uuid.uuid4().hex[:10].upper()}",
                transaction_id=transaction.transaction_id,
                transaction_hash=transaction.transaction_hash(),
                required_approvals=required_approvals,
                current_approvals=0,
                state=ApprovalState.PENDING.value,
                requester_id=requester_id,
                policy_version=str(policy.version),
                policy_hash=policy_hash,
                created_at=datetime.datetime.now(datetime.timezone.utc)
            )
            repo.save_request(req)

            # Update tx state to PENDING_APPROVAL
            tx_repo = TransactionRepository(session)
            tx_rec = tx_repo.get(transaction.transaction_id)
            if tx_rec:
                tx_rec.state = TransactionState.PENDING_APPROVAL.value
                tx_repo.save(tx_rec)

            return req
        finally:
            if is_local:
                session.close()

    def approve_transaction(
        self,
        transaction_id: str,
        approver: ActorConfig,
        key_id: str,
        password: str
    ) -> ApprovalRecord:
        """Approve a pending transaction using an approver's cryptographic key signature."""
        session, is_local = self._get_session()
        try:
            tx_repo = TransactionRepository(session)
            tx_rec = tx_repo.get(transaction_id)
            if not tx_rec:
                raise SecurityError(f"Transaction '{transaction_id}' not found.")

            if tx_rec.state not in (TransactionState.PENDING_APPROVAL.value, TransactionState.CREATED.value):
                raise SecurityError(f"Transaction '{transaction_id}' is in state '{tx_rec.state}', cannot approve.")

            if approver.actor_type not in (ActorType.APPROVER, ActorType.HUMAN_OPERATOR, ActorType.HUMAN):
                raise SecurityError(f"Actor '{approver.actor_id}' of type '{approver.actor_type}' cannot approve transactions.")
            if approver.actor_id == tx_rec.actor_id:
                raise SecurityError("Requester cannot approve its own transaction.")

            # Ensure approver ActorRecord exists in DB for foreign key constraint
            actor_repo = ActorRepository(session)
            if not actor_repo.get(approver.actor_id):
                actor_repo.save(ActorRecord(
                    actor_id=approver.actor_id,
                    actor_type=approver.actor_type.value,
                    display_name=approver.display_name,
                    active=True
                ))

            appr_repo = ApprovalRepository(session)
            req = appr_repo.get_request(transaction_id)

            if not req:
                req = self.create_approval_request(
                    transaction=Transaction(
                        transaction_id=tx_rec.transaction_id,
                        actor_id=tx_rec.actor_id,
                        session_id=tx_rec.session_id,
                        from_account=tx_rec.from_account,
                        to_account=tx_rec.to_account,
                        amount=tx_rec.amount,
                        currency=tx_rec.currency,
                        nonce=tx_rec.nonce,
                        timestamp=tx_rec.timestamp
                    ),
                    required_approvals=1,
                    requester_id=tx_rec.actor_id
                )

            if req.transaction_hash != tx_rec.canonical_hash:
                raise SecurityError("Approval request is stale due to transaction mutation.")
            policy = PolicyEngine().policy
            policy_hash = sha256_hash(canonical_serialize(policy.model_dump(mode="json")))
            if req.policy_version != str(policy.version) or req.policy_hash != policy_hash:
                raise SecurityError("Approval request is stale due to policy change.")

            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            expires_at = now + datetime.timedelta(minutes=30)
            payload = {
                "transaction_hash": tx_rec.canonical_hash, "request_id": req.request_id,
                "approver_id": approver.actor_id, "approval_type": "human_approval",
                "policy_version": req.policy_version, "policy_hash": req.policy_hash,
                "timestamp": now.isoformat(), "expires_at": expires_at.isoformat(),
            }
            keystore = Keystore()
            signature = sign_canonical_bytes(canonical_serialize(payload), keystore.load_private_key(key_id, password))

            approval_record = ApprovalRecord(
                approval_id=f"APPR-{uuid.uuid4().hex[:10].upper()}",
                transaction_id=transaction_id,
                transaction_hash=tx_rec.canonical_hash,
                request_id=req.request_id,
                policy_version=req.policy_version,
                policy_hash=req.policy_hash,
                approval_type="human_approval",
                expires_at=expires_at,
                signing_key_id=key_id,
                approval_payload_hash=sha256_hash(canonical_serialize(payload)),
                approver_id=approver.actor_id,
                approver_signature=signature,
                state=ApprovalState.APPROVED.value,
                nonce=uuid.uuid4().hex[:16],
                created_at=now,
                decided_at=now
            )
            appr_repo.save_approval(approval_record)

            # Update count
            existing_approvals = appr_repo.get_approvals(transaction_id)
            valid_count = len([a for a in existing_approvals if a.transaction_hash == tx_rec.canonical_hash])

            req.current_approvals = valid_count
            if req.current_approvals >= req.required_approvals:
                req.state = ApprovalState.APPROVED.value
                tx_rec.state = TransactionState.APPROVED.value
                tx_repo.save(tx_rec)
            appr_repo.save_request(req)

            return approval_record
        finally:
            if is_local:
                session.close()

    def verify_approval_integrity(self, transaction: Transaction) -> bool:
        """Check if all existing approvals match current transaction hash.

        If transaction fields were modified post-approval, returns False.
        """
        session, is_local = self._get_session()
        try:
            appr_repo = ApprovalRepository(session)
            req = appr_repo.get_request(transaction.transaction_id)
            if not req:
                return False

            policy = PolicyEngine().policy
            policy_hash = sha256_hash(canonical_serialize(policy.model_dump(mode="json")))
            if req.transaction_hash != transaction.transaction_hash() or req.policy_version != str(policy.version) or req.policy_hash != policy_hash:
                return False

            approvals = appr_repo.get_approvals(transaction.transaction_id)
            if not approvals:
                return False

            valid = 0
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            for appr in approvals:
                if (appr.transaction_hash != transaction.transaction_hash() or appr.request_id != req.request_id
                        or appr.policy_version != req.policy_version or appr.policy_hash != req.policy_hash
                        or not appr.expires_at or appr.expires_at < now or not appr.signing_key_id):
                    return False
                payload = {
                    "transaction_hash": appr.transaction_hash, "request_id": appr.request_id,
                    "approver_id": appr.approver_id, "approval_type": appr.approval_type,
                    "policy_version": appr.policy_version, "policy_hash": appr.policy_hash,
                    "timestamp": appr.created_at.isoformat(), "expires_at": appr.expires_at.isoformat(),
                }
                if sha256_hash(canonical_serialize(payload)) != appr.approval_payload_hash:
                    return False
                try:
                    pub = Keystore().get_public_key(appr.signing_key_id)
                    verify_signature(canonical_serialize(payload), appr.approver_signature, bytes.fromhex(pub))
                except Exception:
                    return False
                valid += 1
            return valid >= req.required_approvals
        finally:
            if is_local:
                session.close()
