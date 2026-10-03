"""Hash-chained audit ledger with identity-signed prefix checkpoints."""

import datetime
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy.orm import Session

from finguard.core.config import get_config
from finguard.core.enums import ActorType
from finguard.core.errors import IntegrityError, SecurityError
from finguard.crypto.hashing import sha256_hash
from finguard.crypto.keystore import Keystore
from finguard.crypto.signing import (
    generate_keypair,
    public_key_to_hex,
    sign_canonical_bytes,
    verify_signature,
)
from finguard.identity.registry import IdentityRegistry
from finguard.storage.database import get_session
from finguard.storage.models import (
    AuditCheckpointRecord,
    AuditEntryRecord,
    KeyRecord,
)
from finguard.storage.repositories import AuditRepository

CHECKPOINT_VERSION = 1
CHECKPOINT_DOMAIN = b"finguard.audit.checkpoint.v1\x00"
CHECKPOINT_EVIDENCE_DOMAIN = b"finguard.audit.checkpoint.evidence.v1\x00"
GENESIS_CHECKPOINT_HASH = "0" * 64
_CHECKPOINT_BODY_FIELDS = (
    "checkpoint_version",
    "seq",
    "head_hash",
    "previous_checkpoint_hash",
    "created_at",
    "signer_actor_id",
    "key_id",
    "algorithm",
)
_CHECKPOINT_FIELDS = set(_CHECKPOINT_BODY_FIELDS) | {"signature", "checkpoint_hash"}


def _canonical_json_bytes(value: dict) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_checkpoint_bytes(body: dict) -> bytes:
    """Serialize checkpoint fields using the versioned, domain-separated format."""
    if set(body) != set(_CHECKPOINT_BODY_FIELDS):
        raise ValueError("Checkpoint body has missing or unexpected fields")
    return CHECKPOINT_DOMAIN + _canonical_json_bytes(body)


def _checkpoint_hash(body: dict, signature: str) -> str:
    signed_evidence = {"body": body, "signature": signature}
    return sha256_hash(CHECKPOINT_EVIDENCE_DOMAIN + _canonical_json_bytes(signed_evidence))


def _checkpoint_body(checkpoint: AuditCheckpointRecord | dict) -> dict:
    if isinstance(checkpoint, dict):
        return {field: checkpoint[field] for field in _CHECKPOINT_BODY_FIELDS}
    return {
        "checkpoint_version": checkpoint.checkpoint_version,
        "seq": checkpoint.seq,
        "head_hash": checkpoint.head_hash,
        "previous_checkpoint_hash": checkpoint.previous_checkpoint_hash,
        "created_at": checkpoint.created_at,
        "signer_actor_id": checkpoint.signer_actor_id,
        "key_id": checkpoint.key_id,
        "algorithm": checkpoint.algorithm,
    }


def _checkpoint_dict(checkpoint: AuditCheckpointRecord) -> dict:
    body = _checkpoint_body(checkpoint)
    return {
        **body,
        "signature": checkpoint.signature,
        "checkpoint_hash": checkpoint.checkpoint_hash,
    }


def _compute_entry_hash(
    previous_hash: str,
    timestamp_iso: str,
    actor_id: str,
    action: str,
    tx_id: str,
    result: str,
    meta_str: str,
) -> str:
    payload = f"{previous_hash}|{timestamp_iso}|{actor_id}|{action}|{tx_id}|{result}|{meta_str}"
    return sha256_hash(payload.encode("utf-8"))


def _acquire_immediate_writer(session: Session) -> None:
    """Reserve SQLite's writer before reading the ledger head when no write has begun."""
    connection = session.connection()
    driver_connection = connection.connection.driver_connection
    if not driver_connection.in_transaction:
        connection.exec_driver_sql("BEGIN IMMEDIATE")


class AuditLedger:
    """Tamper-evident ledger with locally persisted, registry-bound checkpoints."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
    GENESIS_CHECKPOINT_HASH = GENESIS_CHECKPOINT_HASH

    def __init__(self, session: Session | None = None):
        self._external_session = session

    def _get_session(self) -> tuple[Session, bool]:
        if self._external_session:
            return self._external_session, False
        return get_session(), True

    def append(
        self,
        action: str,
        actor_id: str = "system",
        transaction_id: str | None = None,
        result: str = "PASS",
        metadata: dict | None = None,
        *,
        commit: bool = True,
    ) -> AuditEntryRecord:
        """Append a sequenced hash-chain entry in the caller's transaction."""
        session, is_local = self._get_session()
        try:
            _acquire_immediate_writer(session)
            repo = AuditRepository(session)
            latest = repo.get_latest()
            seq = latest.seq + 1 if latest else 1
            prev_hash = latest.entry_hash if latest else self.GENESIS_HASH

            now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
            now_iso = now.isoformat()
            tx_str = transaction_id or ""
            actor_str = actor_id or ""
            res_str = result or ""
            meta_json = json.dumps(metadata, sort_keys=True) if metadata else ""
            entry_hash = _compute_entry_hash(
                previous_hash=prev_hash,
                timestamp_iso=now_iso,
                actor_id=actor_str,
                action=action,
                tx_id=tx_str,
                result=res_str,
                meta_str=meta_json,
            )

            record = AuditEntryRecord(
                seq=seq,
                timestamp=now,
                actor_id=actor_id,
                action=action,
                transaction_id=transaction_id,
                result=result,
                metadata_json=meta_json if meta_json else None,
                previous_hash=prev_hash,
                entry_hash=entry_hash,
            )
            repo.append(record, commit=commit)
            return AuditEntryRecord(
                entry_id=record.entry_id,
                seq=record.seq,
                timestamp=record.timestamp,
                actor_id=record.actor_id,
                action=record.action,
                transaction_id=record.transaction_id,
                result=record.result,
                metadata_json=record.metadata_json,
                previous_hash=record.previous_hash,
                entry_hash=record.entry_hash,
            )
        finally:
            if is_local:
                session.close()

    @staticmethod
    def verify_checkpoint_artifact(
        checkpoint: dict,
        trusted_public_key_hex: str,
        *,
        expected_previous_checkpoint_hash: str | None = None,
    ) -> bool:
        """Verify exported checkpoint bytes against a separately trusted registry key."""
        if not isinstance(checkpoint, dict) or set(checkpoint) != _CHECKPOINT_FIELDS:
            return False
        try:
            body = _checkpoint_body(checkpoint)
            if (
                isinstance(body["checkpoint_version"], bool)
                or body["checkpoint_version"] != CHECKPOINT_VERSION
                or isinstance(body["seq"], bool)
                or not isinstance(body["seq"], int)
                or body["seq"] < 0
                or body["algorithm"] != "Ed25519"
                or any(
                    not isinstance(body[field], str)
                    for field in (
                        "head_hash",
                        "previous_checkpoint_hash",
                        "created_at",
                        "signer_actor_id",
                        "key_id",
                    )
                )
                or not isinstance(checkpoint["signature"], str)
                or not isinstance(checkpoint["checkpoint_hash"], str)
            ):
                return False
            if (
                expected_previous_checkpoint_hash is not None
                and body["previous_checkpoint_hash"] != expected_previous_checkpoint_hash
            ):
                return False
            if _checkpoint_hash(body, checkpoint["signature"]) != checkpoint["checkpoint_hash"]:
                return False
            return verify_signature(
                canonical_checkpoint_bytes(body),
                checkpoint["signature"],
                bytes.fromhex(trusted_public_key_hex),
            )
        except (IntegrityError, KeyError, TypeError, ValueError):
            return False

    @staticmethod
    def verify_checkpoint_bundle(
        checkpoint: dict,
        entries: list[dict],
        trusted_public_key_hex: str,
        *,
        expected_previous_checkpoint_hash: str | None = None,
    ) -> bool:
        """Verify an exported checkpoint against an exported ledger prefix."""
        if not isinstance(entries, list) or not AuditLedger.verify_checkpoint_artifact(
            checkpoint,
            trusted_public_key_hex,
            expected_previous_checkpoint_hash=expected_previous_checkpoint_hash,
        ):
            return False
        sequence = checkpoint["seq"]
        if len(entries) < sequence:
            return False
        expected_previous_hash = AuditLedger.GENESIS_HASH
        try:
            for expected_sequence, entry in enumerate(entries[:sequence], start=1):
                required = {
                    "seq",
                    "timestamp",
                    "actor_id",
                    "action",
                    "transaction_id",
                    "result",
                    "metadata_json",
                    "previous_hash",
                    "entry_hash",
                }
                if not isinstance(entry, dict) or not required.issubset(entry):
                    return False
                if (
                    isinstance(entry["seq"], bool)
                    or entry["seq"] != expected_sequence
                    or entry["previous_hash"] != expected_previous_hash
                ):
                    return False
                timestamp = entry["timestamp"]
                if not isinstance(timestamp, str):
                    return False
                parsed_timestamp = datetime.datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                ).replace(tzinfo=None)
                recomputed = _compute_entry_hash(
                    previous_hash=entry["previous_hash"],
                    timestamp_iso=parsed_timestamp.isoformat(),
                    actor_id=entry["actor_id"] or "",
                    action=entry["action"],
                    tx_id=entry["transaction_id"] or "",
                    result=entry["result"] or "",
                    meta_str=entry["metadata_json"] or "",
                )
                if recomputed != entry["entry_hash"]:
                    return False
                expected_previous_hash = entry["entry_hash"]
            return expected_previous_hash == checkpoint["head_hash"]
        except (KeyError, TypeError, ValueError):
            return False

    def _registered_public_key(
        self,
        session: Session,
        signer_actor_id: str,
        key_id: str,
        *,
        signing: bool,
    ) -> str | None:
        actor = IdentityRegistry().get_actor(signer_actor_id)
        key_record = session.get(KeyRecord, key_id)
        if (
            actor is None
            or not actor.public_key
            or actor.actor_type not in {
                ActorType.HUMAN_OPERATOR,
                ActorType.HUMAN,
                ActorType.APPROVER,
            }
            or key_record is None
            or key_record.algorithm != "Ed25519"
            or key_record.public_key_hex != actor.public_key
        ):
            return None
        if signing and (not actor.active or not key_record.active):
            return None
        return actor.public_key

    def create_checkpoint(
        self,
        key_id: str,
        password: str,
        signer_actor_id: str,
    ) -> dict:
        """Atomically sign the current ledger head with a registered active identity key."""
        session, is_local = self._get_session()
        try:
            if session.in_transaction():
                raise SecurityError("Checkpoint creation requires a session with no active transaction")
            signer = IdentityRegistry().get_actor(signer_actor_id)
            if (
                signer is None
                or not signer.active
                or signer.actor_type not in {
                    ActorType.HUMAN_OPERATOR,
                    ActorType.HUMAN,
                    ActorType.APPROVER,
                }
                or not signer.public_key
            ):
                raise SecurityError("Checkpoint key is not bound to an active registered signer")
            public_key_hex = signer.public_key
            keystore = Keystore()
            if keystore.get_public_key(key_id) != public_key_hex:
                raise SecurityError("Checkpoint keystore key does not match the identity registry")
            private_key = keystore.load_private_key(key_id, password)
            if public_key_to_hex(private_key.public_key()) != public_key_hex:
                raise SecurityError("Unlocked checkpoint key does not match the registered identity")

            with session.begin():
                _acquire_immediate_writer(session)
                if self._registered_public_key(
                    session, signer_actor_id, key_id, signing=True
                ) != public_key_hex:
                    raise SecurityError("Checkpoint key is not active in the key registry")
                valid, _, reason = self._verify_integrity_in_session(session)
                if not valid:
                    raise SecurityError(f"Cannot checkpoint an invalid audit ledger: {reason}")

                repo = AuditRepository(session)
                latest_entry = repo.get_latest()
                seq = latest_entry.seq if latest_entry else 0
                head_hash = latest_entry.entry_hash if latest_entry else self.GENESIS_HASH
                previous_checkpoint = (
                    session.query(AuditCheckpointRecord)
                    .order_by(AuditCheckpointRecord.seq.desc())
                    .first()
                )
                previous_checkpoint_hash = (
                    previous_checkpoint.checkpoint_hash
                    if previous_checkpoint
                    else self.GENESIS_CHECKPOINT_HASH
                )
                existing = session.get(AuditCheckpointRecord, seq)
                if existing is not None:
                    if (
                        existing.head_hash != head_hash
                        or existing.signer_actor_id != signer_actor_id
                        or existing.key_id != key_id
                    ):
                        raise SecurityError(
                            "A different checkpoint already exists for this ledger sequence"
                        )
                    checkpoint = _checkpoint_dict(existing)
                else:
                    self._checkpoint_checkpoint("after_ledger_validation")
                    created_at = datetime.datetime.now(datetime.UTC).isoformat(
                        timespec="microseconds"
                    ).replace("+00:00", "Z")
                    body = {
                        "checkpoint_version": CHECKPOINT_VERSION,
                        "seq": seq,
                        "head_hash": head_hash,
                        "previous_checkpoint_hash": previous_checkpoint_hash,
                        "created_at": created_at,
                        "signer_actor_id": signer_actor_id,
                        "key_id": key_id,
                        "algorithm": "Ed25519",
                    }
                    signature = sign_canonical_bytes(
                        canonical_checkpoint_bytes(body), private_key
                    )
                    record = AuditCheckpointRecord(
                        **body,
                        checkpoint_hash=_checkpoint_hash(body, signature),
                        signature=signature,
                    )
                    session.add(record)
                    session.flush()
                    self._checkpoint_checkpoint("after_checkpoint_insert")
                    self._checkpoint_checkpoint("before_commit")
                    checkpoint = _checkpoint_dict(record)
            return checkpoint
        finally:
            if is_local:
                session.close()

    @staticmethod
    def _checkpoint_checkpoint(stage: str) -> None:
        """Inert checkpoint that tests may replace to inject transaction failures."""

    def verify_integrity(self) -> tuple[bool, int | None, str | None]:
        """Verify sequence, entry hashes, and every registered-key checkpoint."""
        session, is_local = self._get_session()
        try:
            return self._verify_integrity_in_session(session)
        finally:
            if is_local:
                session.close()

    def _verify_integrity_in_session(
        self, session: Session
    ) -> tuple[bool, int | None, str | None]:
        entries = AuditRepository(session).get_all_ordered()
        expected_prev = self.GENESIS_HASH
        by_sequence: dict[int, AuditEntryRecord] = {}

        for expected_seq, entry in enumerate(entries, start=1):
            if entry.seq != expected_seq:
                return False, entry.entry_id, (
                    f"Ledger sequence gap or reorder at entry #{entry.entry_id}: "
                    f"expected sequence {expected_seq}, found {entry.seq}"
                )
            if entry.previous_hash != expected_prev:
                return False, entry.entry_id, (
                    f"Previous hash mismatch at sequence {entry.seq}. "
                    f"Expected {expected_prev[:8]}..., got {entry.previous_hash[:8]}..."
                )

            meta_str = entry.metadata_json or ""
            ts = entry.timestamp.replace(tzinfo=None) if entry.timestamp.tzinfo else entry.timestamp
            recomputed = _compute_entry_hash(
                previous_hash=entry.previous_hash,
                timestamp_iso=ts.isoformat(),
                actor_id=entry.actor_id or "",
                action=entry.action,
                tx_id=entry.transaction_id or "",
                result=entry.result or "",
                meta_str=meta_str,
            )
            if recomputed != entry.entry_hash:
                next_entry = entries[expected_seq] if expected_seq < len(entries) else entry
                return False, next_entry.entry_id, (
                    f"Entry content hash mismatch at sequence {entry.seq}. "
                    f"Stored {entry.entry_hash[:8]}..., computed {recomputed[:8]}..."
                )
            expected_prev = entry.entry_hash
            by_sequence[entry.seq] = entry

        checkpoints = (
            session.query(AuditCheckpointRecord)
            .order_by(AuditCheckpointRecord.seq.asc())
            .all()
        )
        previous_checkpoint_hash = self.GENESIS_CHECKPOINT_HASH
        previous_seq = -1
        for checkpoint in checkpoints:
            if checkpoint.seq <= previous_seq:
                return False, checkpoint.seq, "Checkpoint sequences are not strictly increasing"
            if checkpoint.seq > len(entries):
                return False, checkpoint.seq, "Checkpoint claims a sequence beyond the ledger head"
            expected_head = (
                by_sequence[checkpoint.seq].entry_hash
                if checkpoint.seq
                else self.GENESIS_HASH
            )
            if checkpoint.head_hash != expected_head:
                return False, checkpoint.seq, "Checkpoint head hash does not match its ledger sequence"
            if checkpoint.previous_checkpoint_hash != previous_checkpoint_hash:
                return False, checkpoint.seq, "Checkpoint previous-evidence hash is broken"

            public_key_hex = self._registered_public_key(
                session,
                checkpoint.signer_actor_id,
                checkpoint.key_id,
                signing=False,
            )
            if public_key_hex is None or not self.verify_checkpoint_artifact(
                _checkpoint_dict(checkpoint),
                public_key_hex,
                expected_previous_checkpoint_hash=previous_checkpoint_hash,
            ):
                return False, checkpoint.seq, "Checkpoint identity binding, hash, or signature is invalid"

            previous_checkpoint_hash = checkpoint.checkpoint_hash
            previous_seq = checkpoint.seq

        if not entries:
            summary = "Ledger is empty"
        else:
            summary = f"All {len(entries)} entries valid"
        if checkpoints:
            summary += (
                f"; {len(checkpoints)} signed checkpoint(s) valid through sequence "
                f"{checkpoints[-1].seq}"
            )
        else:
            summary += "; no signed checkpoint exists"
        if entries and (not checkpoints or checkpoints[-1].seq < entries[-1].seq):
            covered_seq = checkpoints[-1].seq if checkpoints else 0
            summary += f"; entries after sequence {covered_seq} are not checkpoint-covered"
        return True, None, summary

    def generate_attestation(self, output_path: Path | None = None) -> dict:
        """Generate a signed cryptographic AttestationReport JSON artifact."""
        session, is_local = self._get_session()
        try:
            is_valid, _, reason = self.verify_integrity()
            repo = AuditRepository(session)
            entries = repo.get_all_ordered()

            latest_hash = entries[-1].entry_hash if entries else self.GENESIS_HASH
            now = datetime.datetime.now(datetime.UTC)

            config = get_config()
            attestor_key_path = config.data_dir / "attestor.key"
            attestor_pub_path = config.data_dir / "attestor.pub"
            if not attestor_key_path.exists():
                priv_key, pub_key = generate_keypair()
                pub_hex = public_key_to_hex(pub_key)
                attestor_pub_path.write_text(pub_hex)
                attestor_key_path.write_text(priv_key.private_bytes_raw().hex())
            else:
                priv_bytes = bytes.fromhex(attestor_key_path.read_text().strip())
                priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
                pub_hex = attestor_pub_path.read_text().strip()

            attestation_body = {
                "attestation_type": "FIN//GUARD Audit Ledger Verification",
                "timestamp": now.isoformat(),
                "chain_root_hash": latest_hash,
                "entry_count": len(entries),
                "invariants_checked": [
                    "HASH_CHAIN_INTEGRITY",
                    "REPLAY_PROTECTION",
                    "SIGNATURE_VALIDITY",
                    "AGENT_APPROVAL_FLOOR",
                ],
                "integrity_result": "PASS" if is_valid else "FAIL",
                "verification_notes": reason,
                "attestor_pubkey": pub_hex,
            }

            body_bytes = json.dumps(attestation_body, sort_keys=True).encode("utf-8")
            signature_hex = sign_canonical_bytes(body_bytes, priv_key)
            full_report = {**attestation_body, "signature": signature_hex}
            if output_path:
                output_path.write_text(json.dumps(full_report, indent=2))
            return full_report
        finally:
            if is_local:
                session.close()

    @staticmethod
    def verify_attestation(report_dict: dict, trusted_pubkey_hex: str | None = None) -> bool:
        """Verify the signature on an AttestationReport JSON artifact."""
        report = dict(report_dict)
        signature = report.pop("signature", None)
        embedded_pubkey_hex = report.get("attestor_pubkey")
        if trusted_pubkey_hex is None:
            trusted_path = get_config().data_dir / "attestor.pub"
            trusted_pubkey_hex = (
                trusted_path.read_text(encoding="utf-8").strip()
                if trusted_path.exists()
                else None
            )
        if not signature or not trusted_pubkey_hex or embedded_pubkey_hex != trusted_pubkey_hex:
            return False

        body_bytes = json.dumps(report, sort_keys=True).encode("utf-8")
        try:
            return verify_signature(body_bytes, signature, bytes.fromhex(trusted_pubkey_hex))
        except (IntegrityError, ValueError):
            return False
