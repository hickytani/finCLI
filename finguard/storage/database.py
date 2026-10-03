"""Database engine and session management for FIN//GUARD.

Uses SQLite for local persistence. The database stores all transactions,
actors, approvals, incidents, audit entries, and security events.

SECURITY NOTE: SQLite provides file-level access control only.
The database is NOT encrypted at rest in the MVP. Production deployments
should use encrypted storage or full-disk encryption.
"""

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import sessionmaker, Session, DeclarativeBase

from finguard.core.config import get_config


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for all ORM models."""
    pass


_engine = None
_session_factory = None


def get_engine():
    """Get or create the SQLAlchemy engine.

    Enables WAL mode and foreign keys for SQLite.
    """
    global _engine
    if _engine is None:
        config = get_config()
        config.ensure_dirs()
        db_url = f"sqlite:///{config.db_path}"
        _engine = create_engine(db_url, echo=False)

        # Enable WAL mode and foreign keys for SQLite
        @event.listens_for(_engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Get or create the session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(bind=get_engine())
    return _session_factory


def get_session() -> Session:
    """Create a new database session."""
    factory = get_session_factory()
    return factory()


def init_db() -> None:
    """Create all tables. Idempotent.

    Also applies safe column-level migrations for new fields added to existing
    tables (SQLite does not support schema changes other than ADD COLUMN).
    """
    from finguard.storage import models as _  # noqa: F401 — ensure models are imported
    engine = get_engine()
    Base.metadata.create_all(engine)

    # Column migrations: tables -> {column_name: DDL_type}
    column_migrations = {
        "transactions": {
            "amount_minor": "BIGINT",
            "canonical_version": "INTEGER NOT NULL DEFAULT 1",
            "version": "INTEGER NOT NULL DEFAULT 1",
            "signed_version": "INTEGER",
            "failure_reason": "TEXT",
        },
        "decision_receipts": {
            "canonical_version": "INTEGER NOT NULL DEFAULT 1",
            "transaction_version": "INTEGER NOT NULL DEFAULT 1",
        },
        "approvals": {
            "request_id": "VARCHAR",
            "policy_version": "VARCHAR",
            "policy_hash": "VARCHAR",
            "approval_type": "VARCHAR",
            "expires_at": "DATETIME",
            "signing_key_id": "VARCHAR",
            "approval_payload_hash": "VARCHAR",
            "transaction_version": "INTEGER NOT NULL DEFAULT 1",
        },
        "approval_requests": {
            "policy_version": "VARCHAR",
            "policy_hash": "VARCHAR",
            "transaction_version": "INTEGER NOT NULL DEFAULT 1",
        },
        "audit_entries": {
            "seq": "INTEGER",
        },
        # Incident lifecycle additions
        "incidents": {
            "resolved_by": "VARCHAR",
            "state_note": "TEXT",
        },
    }

    # Index migrations: CREATE INDEX IF NOT EXISTS is safe to repeat
    index_migrations = [
        "CREATE INDEX IF NOT EXISTS ix_incidents_actor ON incidents (actor_id)",
        "CREATE INDEX IF NOT EXISTS ix_incidents_state ON incidents (state)",
        "CREATE INDEX IF NOT EXISTS ix_incidents_transaction ON incidents (transaction_id)",
        "CREATE INDEX IF NOT EXISTS ix_signals_transaction ON security_signals (transaction_id)",
    ]

    inspector = inspect(engine)
    with engine.begin() as connection:
        for table, columns in column_migrations.items():
            # Table may not exist yet on a brand-new db (create_all handles it)
            try:
                existing = {col["name"] for col in inspector.get_columns(table)}
            except Exception:
                continue
            for name, ddl_type in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl_type}"))

        for stmt in index_migrations:
            try:
                connection.execute(text(stmt))
            except Exception:
                pass  # Index may already exist under a different name — not fatal

        audit_tables = set(inspect(connection).get_table_names())
        if "audit_entries" in audit_tables:
            unsequenced = connection.execute(
                text("SELECT entry_id FROM audit_entries WHERE seq IS NULL ORDER BY entry_id")
            ).scalars().all()
            if unsequenced:
                if "audit_checkpoints" in audit_tables and connection.execute(
                    text("SELECT 1 FROM audit_checkpoints LIMIT 1")
                ).first():
                    raise RuntimeError("Cannot backfill audit sequences after checkpoints exist")
                all_entry_ids = connection.execute(
                    text("SELECT entry_id FROM audit_entries ORDER BY entry_id")
                ).scalars().all()
                for sequence, entry_id in enumerate(all_entry_ids, start=1):
                    connection.execute(
                        text("UPDATE audit_entries SET seq = :seq WHERE entry_id = :entry_id"),
                        {"seq": sequence, "entry_id": entry_id},
                    )
            connection.execute(
                text("CREATE UNIQUE INDEX IF NOT EXISTS ux_audit_entry_seq ON audit_entries (seq)")
            )


def reset_db() -> None:
    """Drop and recreate all tables. FOR TESTING ONLY."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None
