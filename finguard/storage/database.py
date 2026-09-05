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
    """Create all tables. Idempotent."""
    from finguard.storage import models as _  # noqa: F401 — ensure models are imported
    engine = get_engine()
    Base.metadata.create_all(engine)
    expected = {
        "approvals": {"request_id": "VARCHAR", "policy_version": "VARCHAR", "policy_hash": "VARCHAR", "approval_type": "VARCHAR", "expires_at": "DATETIME", "signing_key_id": "VARCHAR", "approval_payload_hash": "VARCHAR"},
        "approval_requests": {"policy_version": "VARCHAR", "policy_hash": "VARCHAR"},
    }
    inspector = inspect(engine)
    with engine.begin() as connection:
        for table, columns in expected.items():
            existing = {column["name"] for column in inspector.get_columns(table)}
            for name, ddl_type in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl_type}"))


def reset_db() -> None:
    """Drop and recreate all tables. FOR TESTING ONLY."""
    global _engine, _session_factory
    _engine = None
    _session_factory = None
