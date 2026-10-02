"""Dry-run-first migration of legacy transaction amounts to exact minor units."""

import datetime
import sqlite3
import uuid
from decimal import Decimal
from pathlib import Path
from typing import Any

from finguard.core.enums import Currency, TransactionState
from finguard.money import MAX_AMOUNT_MINOR, get_currency_exponent

_UNSIGNED_LEGACY_STATES = {
    TransactionState.CREATED.value,
    TransactionState.PENDING_APPROVAL.value,
    TransactionState.APPROVED.value,
}


def _minor_units_from_legacy(value: Any, currency_text: str) -> tuple[int | None, str | None]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None, "legacy amount is not a numeric SQLite value"
    try:
        currency = Currency(currency_text)
        exponent = get_currency_exponent(currency)
    except ValueError:
        return None, "unsupported legacy currency"
    exact_value = Decimal.from_float(value) if isinstance(value, float) else Decimal(value)
    if not exact_value.is_finite():
        return None, "legacy amount is non-finite"
    scaled = exact_value * (10 ** exponent)
    if scaled != scaled.to_integral_value():
        return None, "legacy binary float is not exactly representable at currency precision"
    minor_units = int(scaled)
    if minor_units <= 0:
        return None, "legacy amount is not positive"
    if minor_units > MAX_AMOUNT_MINOR:
        return None, "legacy amount exceeds MAX_AMOUNT_MINOR"
    return minor_units, None


def migrate_legacy_money(
    database_path: str | Path,
    *,
    dry_run: bool = True,
    backup_path: str | Path | None = None,
) -> dict[str, Any]:
    """Audit legacy float amounts; writes require a new SQLite backup path.

    Dry-run performs no schema or row writes. Apply mode creates a consistent
    SQLite backup before adding migration fields, backfilling exact values,
    quarantining inexact values, and failing unsigned legacy transactions closed.
    """
    database = Path(database_path).resolve()
    if not database.is_file():
        raise FileNotFoundError("Database file does not exist")

    backup = Path(backup_path).resolve() if backup_path is not None else None
    if not dry_run:
        if backup is None:
            raise ValueError("Apply mode requires an explicit backup_path")
        if backup == database:
            raise ValueError("Backup path must differ from database path")
        if backup.exists():
            raise FileExistsError("Backup path already exists; choose a new backup path")
        backup.parent.mkdir(parents=True, exist_ok=True)

    report: dict[str, Any] = {
        "migration_id": uuid.uuid4().hex,
        "dry_run": dry_run,
        "rows_migrated": [],
        "rows_quarantined": [],
        "rows_failed": [],
        "rows_failed_resubmit": [],
        "backup_path": str(backup) if backup else None,
    }

    connection = sqlite3.connect(database)
    try:
        if not dry_run:
            assert backup is not None
            backup_connection = sqlite3.connect(backup)
            try:
                connection.backup(backup_connection)
            finally:
                backup_connection.close()
            connection.execute("BEGIN IMMEDIATE")
            existing_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(transactions)")
            }
            if not existing_columns:
                raise ValueError("Database has no transactions table")
            if "amount_minor" not in existing_columns:
                connection.execute("ALTER TABLE transactions ADD COLUMN amount_minor BIGINT")
            if "canonical_version" not in existing_columns:
                connection.execute(
                    "ALTER TABLE transactions ADD COLUMN canonical_version INTEGER NOT NULL DEFAULT 1"
                )
            if "failure_reason" not in existing_columns:
                connection.execute("ALTER TABLE transactions ADD COLUMN failure_reason TEXT")
            connection.execute(
                """CREATE TABLE IF NOT EXISTS legacy_money_quarantine (
                    transaction_id TEXT PRIMARY KEY,
                    currency TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    quarantined_at TEXT NOT NULL
                )"""
            )
            existing_columns.update({"amount_minor", "canonical_version", "failure_reason"})
        else:
            connection.execute("PRAGMA query_only = ON")
            existing_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(transactions)")
            }
            if not existing_columns:
                raise ValueError("Database has no transactions table")

        required = {"transaction_id", "amount", "currency", "state"}
        missing = sorted(required - existing_columns)
        if missing:
            raise ValueError(f"transactions table missing required columns: {', '.join(missing)}")

        select_columns = ["transaction_id", "amount", "currency", "state"]
        if "amount_minor" in existing_columns:
            select_columns.append("amount_minor")
        query = "SELECT " + ", ".join(select_columns) + " FROM transactions"
        prior_quarantine: set[str] = set()
        if not dry_run:
            prior_quarantine = {
                row[0] for row in connection.execute(
                    "SELECT transaction_id FROM legacy_money_quarantine"
                )
            }

        rows = connection.execute(query).fetchall()
        for row in rows:
            transaction_id, legacy_amount, currency_text, state = row[:4]
            current_minor = row[4] if len(row) > 4 else None
            if current_minor is not None or transaction_id in prior_quarantine:
                continue

            minor_units, error = _minor_units_from_legacy(legacy_amount, currency_text)
            if error:
                report["rows_quarantined"].append({"transaction_id": transaction_id, "reason": error})
                if not dry_run:
                    connection.execute(
                        "INSERT INTO legacy_money_quarantine VALUES (?, ?, ?, ?)",
                        (transaction_id, currency_text, error, datetime.datetime.now(datetime.UTC).isoformat()),
                    )
            else:
                report["rows_migrated"].append({"transaction_id": transaction_id, "amount_minor": minor_units})
                if not dry_run:
                    connection.execute(
                        "UPDATE transactions SET amount_minor = ?, canonical_version = 1 WHERE transaction_id = ?",
                        (minor_units, transaction_id),
                    )

            if state in _UNSIGNED_LEGACY_STATES:
                report["rows_failed_resubmit"].append(transaction_id)
                report["rows_failed"].append({
                    "transaction_id": transaction_id,
                    "reason": "MIGRATED_REQUIRES_RESUBMIT",
                })
                if not dry_run:
                    connection.execute(
                        "UPDATE transactions SET state = ?, failure_reason = ? WHERE transaction_id = ?",
                        (TransactionState.FAILED.value, "MIGRATED_REQUIRES_RESUBMIT", transaction_id),
                    )

        if not dry_run:
            connection.commit()
    except Exception:
        if not dry_run:
            connection.rollback()
        raise
    finally:
        connection.close()

    return report