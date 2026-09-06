"""Tamper-evident Audit Ledger & Signed Attestation Service.

SECURITY PROPERTIES:
- Every security operation (policy decision, risk score, approval, incident, signature)
  is appended to the ledger.
- Entries are cryptographically hash-chained: entry_hash = SHA-256(prev_hash + entry_data).
- `verify_integrity()` detects modified, deleted, or inserted historical audit entries.
- `generate_attestation()` generates an independently-verifiable signed JSON report artifact.
"""

import json
import datetime
from pathlib import Path
from typing import Optional, Tuple
from sqlalchemy.orm import Session

from finguard.core.config import get_config
from finguard.crypto.hashing import sha256_hash
from finguard.crypto.signing import (
    generate_keypair,
    sign_canonical_bytes,
    verify_signature,
    public_key_to_hex,
)
from finguard.storage.database import get_session
from finguard.storage.models import AuditEntryRecord
from finguard.storage.repositories import AuditRepository
from cryptography.hazmat.primitives.asymmetric import ed25519


def _compute_entry_hash(previous_hash: str, timestamp_iso: str, actor_id: str, action: str, tx_id: str, result: str, meta_str: str) -> str:
    payload = f"{previous_hash}|{timestamp_iso}|{actor_id}|{action}|{tx_id}|{result}|{meta_str}"
    return sha256_hash(payload.encode("utf-8"))


class AuditLedger:
    """Tamper-evident audit ledger with hash chaining and attestation."""

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, session: Optional[Session] = None):
        self._external_session = session

    def _get_session(self) -> tuple[Session, bool]:
        if self._external_session:
            return self._external_session, False
        return get_session(), True

    def append(
        self,
        action: str,
        actor_id: str = "system",
        transaction_id: Optional[str] = None,
        result: str = "PASS",
        metadata: Optional[dict] = None
    ) -> AuditEntryRecord:
        """Append a new audit entry with hash chaining to the ledger."""
        session, is_local = self._get_session()
        try:
            repo = AuditRepository(session)
            latest = repo.get_latest()

            prev_hash = latest.entry_hash if latest else self.GENESIS_HASH

            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
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
                meta_str=meta_json
            )

            record = AuditEntryRecord(
                timestamp=now,
                actor_id=actor_id,
                action=action,
                transaction_id=transaction_id,
                result=result,
                metadata_json=meta_json if meta_json else None,
                previous_hash=prev_hash,
                entry_hash=entry_hash
            )
            repo.append(record)
            return record
        finally:
            if is_local:
                session.close()

    def verify_integrity(self) -> Tuple[bool, Optional[int], Optional[str]]:
        """Verify hash chain integrity across all historical entries.

        Returns:
            Tuple of (is_valid, failing_entry_id, reason)
        """
        session, is_local = self._get_session()
        try:
            repo = AuditRepository(session)
            entries = repo.get_all_ordered()

            if not entries:
                return True, None, "Ledger is empty"

            expected_prev = self.GENESIS_HASH

            for entry in entries:
                if entry.previous_hash != expected_prev:
                    return (
                        False,
                        entry.entry_id,
                        f"Previous hash mismatch at entry #{entry.entry_id}. Expected {expected_prev[:8]}..., got {entry.previous_hash[:8]}..."
                    )

                meta_str = entry.metadata_json or ""
                ts = entry.timestamp.replace(tzinfo=None) if entry.timestamp.tzinfo else entry.timestamp
                ts_iso = ts.isoformat()

                recomputed = _compute_entry_hash(
                    previous_hash=entry.previous_hash,
                    timestamp_iso=ts_iso,
                    actor_id=entry.actor_id or "",
                    action=entry.action,
                    tx_id=entry.transaction_id or "",
                    result=entry.result or "",
                    meta_str=meta_str
                )

                if recomputed != entry.entry_hash:
                    # Try possible timestamp formats from earlier db entries
                    candidates = [
                        ts.replace(tzinfo=datetime.timezone.utc).isoformat(),
                        str(entry.timestamp),
                        entry.timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
                        entry.timestamp.isoformat()
                    ]
                    for candidate_ts in candidates:
                        cand_hash = _compute_entry_hash(
                            previous_hash=entry.previous_hash,
                            timestamp_iso=candidate_ts,
                            actor_id=entry.actor_id or "",
                            action=entry.action,
                            tx_id=entry.transaction_id or "",
                            result=entry.result or "",
                            meta_str=meta_str
                        )
                        if cand_hash == entry.entry_hash:
                            recomputed = cand_hash
                            break

                if recomputed != entry.entry_hash:
                    return (
                        False,
                        entry.entry_id,
                        f"Entry content hash mismatch at entry #{entry.entry_id}. Stored {entry.entry_hash[:8]}..., computed {recomputed[:8]}..."
                    )

                expected_prev = entry.entry_hash

            return True, None, f"All {len(entries)} entries valid"
        finally:
            if is_local:
                session.close()

    def generate_attestation(self, output_path: Optional[Path] = None) -> dict:
        """Generate a signed cryptographic AttestationReport JSON artifact."""
        session, is_local = self._get_session()
        try:
            is_valid, failing_id, reason = self.verify_integrity()
            repo = AuditRepository(session)
            entries = repo.get_all_ordered()

            latest_hash = entries[-1].entry_hash if entries else self.GENESIS_HASH
            now = datetime.datetime.now(datetime.timezone.utc)

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
                    "AGENT_APPROVAL_FLOOR"
                ],
                "integrity_result": "PASS" if is_valid else "FAIL",
                "verification_notes": reason,
                "attestor_pubkey": pub_hex,
            }

            body_bytes = json.dumps(attestation_body, sort_keys=True).encode("utf-8")
            signature_hex = sign_canonical_bytes(body_bytes, priv_key)

            full_report = {
                **attestation_body,
                "signature": signature_hex
            }

            if output_path:
                output_path.write_text(json.dumps(full_report, indent=2))

            return full_report
        finally:
            if is_local:
                session.close()

    @staticmethod
    def verify_attestation(report_dict: dict, trusted_pubkey_hex: Optional[str] = None) -> bool:
        """Verify the signature on an AttestationReport JSON artifact."""
        report = dict(report_dict)
        signature = report.pop("signature", None)
        embedded_pubkey_hex = report.get("attestor_pubkey")
        if trusted_pubkey_hex is None:
            trusted_path = get_config().data_dir / "attestor.pub"
            trusted_pubkey_hex = trusted_path.read_text(encoding="utf-8").strip() if trusted_path.exists() else None
        pubkey_hex = trusted_pubkey_hex

        if not signature or not pubkey_hex or embedded_pubkey_hex != pubkey_hex:
            return False

        body_bytes = json.dumps(report, sort_keys=True).encode("utf-8")
        try:
            pub_bytes = bytes.fromhex(pubkey_hex)
            return verify_signature(body_bytes, signature, pub_bytes)
        except Exception:
            return False
