"""Transaction boundary for atomic SQLite write operations."""

from collections.abc import Callable
from types import TracebackType

from sqlalchemy.orm import Session

from finguard.storage.database import get_session


class UnitOfWork:
    """Own one session and reserve SQLite's writer before transactional reads."""

    def __init__(self, session_factory: Callable[[], Session] | None = None) -> None:
        self._session_factory = session_factory or get_session
        self._session: Session | None = None
        self._transaction = None

    def __enter__(self) -> Session:
        session = self._session_factory()
        self._session = session
        try:
            if session.get_bind().dialect.name != "sqlite":
                raise RuntimeError("Immediate-write UnitOfWork requires SQLite")
            transaction = session.begin()
            transaction.__enter__()
            self._transaction = transaction
            connection = session.connection()
            driver_connection = connection.connection.driver_connection
            if driver_connection.in_transaction:
                raise RuntimeError("UnitOfWork requires a fresh SQLite session")
            connection.exec_driver_sql("BEGIN IMMEDIATE")
        except BaseException:
            try:
                session.rollback()
            finally:
                session.close()
                self._session = None
            raise
        return session

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if self._session is None or self._transaction is None:
            raise RuntimeError("UnitOfWork was not entered")
        try:
            return bool(self._transaction.__exit__(exc_type, exc_value, traceback))
        finally:
            self._session.close()
            self._session = None
            self._transaction = None
