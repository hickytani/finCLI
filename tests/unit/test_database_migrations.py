"""Additive migration tests for canonical transaction versioning."""

import sqlite3

import pytest

from finguard.core.config import reset_config
from finguard.storage.database import Base, init_db, reset_db
from finguard.storage.money_migration import migrate_legacy_money


def test_existing_rows_gain_minor_units_and_legacy_v1_version(tmp_path, monkeypatch):
    data_dir = tmp_path / "legacy-data"
    data_dir.mkdir()
    database_path = data_dir / "finguard.db"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TABLE transactions (transaction_id TEXT PRIMARY KEY, amount FLOAT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE decision_receipts (receipt_id TEXT PRIMARY KEY)"
        )
        connection.execute("INSERT INTO transactions VALUES ('legacy-tx', 12.34)")
        connection.execute("INSERT INTO decision_receipts VALUES ('legacy-receipt')")

    monkeypatch.setenv("FINGUARD_DATA_DIR", str(data_dir))
    reset_config()
    reset_db()
    monkeypatch.setattr(Base.metadata, "create_all", lambda engine: None)

    init_db()

    with sqlite3.connect(database_path) as connection:
        transaction_columns = {
            row[1]: row for row in connection.execute("PRAGMA table_info(transactions)")
        }
        receipt_columns = {
            row[1]: row for row in connection.execute("PRAGMA table_info(decision_receipts)")
        }
        assert "amount_minor" in transaction_columns
        assert transaction_columns["canonical_version"][4] == "1"
        assert "canonical_version" in receipt_columns
        assert connection.execute(
            "SELECT canonical_version FROM transactions WHERE transaction_id='legacy-tx'"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT canonical_version FROM decision_receipts WHERE receipt_id='legacy-receipt'"
        ).fetchone() == (1,)


def _legacy_money_database(database_path):
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """CREATE TABLE transactions (
                transaction_id TEXT PRIMARY KEY,
                amount REAL NOT NULL,
                currency TEXT NOT NULL,
                state TEXT NOT NULL
            )"""
        )
        connection.executemany(
            "INSERT INTO transactions (transaction_id, amount, currency, state) VALUES (?, ?, ?, ?)",
            [
                ("exact-pending", 12.5, "INR", "pending_approval"),
                ("inexact-pending", 12.34, "INR", "pending_approval"),
                ("exact-signed", 1.25, "USD", "signed"),
                ("nonfinite-signed", float("inf"), "INR", "signed"),
            ],
        )


def test_legacy_money_migration_dry_run_never_mutates_database(tmp_path):
    database_path = tmp_path / "dry-run.db"
    _legacy_money_database(database_path)

    report = migrate_legacy_money(database_path, dry_run=True)

    assert {item["transaction_id"] for item in report["rows_migrated"]} == {
        "exact-pending", "exact-signed"
    }
    assert report["rows_quarantined"] == [{
        "transaction_id": "inexact-pending",
        "reason": "legacy binary float is not exactly representable at currency precision",
    }, {
        "transaction_id": "nonfinite-signed",
        "reason": "legacy amount is non-finite",
    }]
    assert set(report["rows_failed_resubmit"]) == {"exact-pending", "inexact-pending"}
    assert {item["transaction_id"] for item in report["rows_failed"]} == {
        "exact-pending", "inexact-pending"
    }
    with sqlite3.connect(database_path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(transactions)")}
        assert "amount_minor" not in columns
        assert connection.execute(
            "SELECT state FROM transactions WHERE transaction_id='exact-pending'"
        ).fetchone() == ("pending_approval",)


def test_legacy_money_apply_requires_backup_quarantines_and_is_idempotent(tmp_path):
    database_path = tmp_path / "apply.db"
    backup_path = tmp_path / "backups" / "apply.before.db"
    _legacy_money_database(database_path)

    with pytest.raises(ValueError, match="backup_path"):
        migrate_legacy_money(database_path, dry_run=False)

    report = migrate_legacy_money(database_path, dry_run=False, backup_path=backup_path)
    assert backup_path.is_file()
    assert len(report["rows_migrated"]) == 2
    assert len(report["rows_quarantined"]) == 2
    assert set(report["rows_failed_resubmit"]) == {"exact-pending", "inexact-pending"}

    with sqlite3.connect(database_path) as connection:
        rows = {
            row[0]: row[1:]
            for row in connection.execute(
                "SELECT transaction_id, amount_minor, canonical_version, state, failure_reason FROM transactions"
            )
        }
        assert rows["exact-pending"] == (1250, 1, "failed", "MIGRATED_REQUIRES_RESUBMIT")
        assert rows["exact-signed"] == (125, 1, "signed", None)
        assert rows["inexact-pending"] == (None, 1, "failed", "MIGRATED_REQUIRES_RESUBMIT")
        assert rows["nonfinite-signed"] == (None, 1, "signed", None)
        assert connection.execute(
            "SELECT reason FROM legacy_money_quarantine WHERE transaction_id='inexact-pending'"
        ).fetchone()[0].startswith("legacy binary float")

    rerun = migrate_legacy_money(
        database_path, dry_run=False, backup_path=tmp_path / "backups" / "apply.rerun.db"
    )
    assert rerun["rows_migrated"] == []
    assert rerun["rows_quarantined"] == []