"""SQLite backend: zero-setup, single host (CLI, single-node server)."""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from piisafe.storage.sql import SCHEMA, SQLStore

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows: in-process locking only
    fcntl = None  # type: ignore[assignment]

_MEMORY_LOCKS: dict[str, threading.RLock] = {}
_MEMORY_MUTEX = threading.Lock()


class SQLiteStore(SQLStore):
    dialect = "sqlite"
    day_expr = "date(ts, 'unixepoch', 'localtime')"

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self._memory = self.path == ":memory:"
        if not self._memory:
            db = Path(self.path)
            db.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not db.exists():
                db.touch(mode=0o600)
        # isolation_level=None -> autocommit; writes that must be atomic use _tx().
        # check_same_thread=False: the web server hands a guard's connection between
        # worker threads; callers serialise access with the session lock.
        self._conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        if not self._memory:
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA synchronous = NORMAL")
        self._tx_depth = 0
        self._apply_schema()

    # ------------------------------------------------------------ primitives

    def _rows(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> list[dict[str, Any]]:
        return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def _exec(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> int:
        return self._conn.execute(sql, params).rowcount

    def _exec_many(self, sql: str, seq: Sequence[Sequence[Any] | dict[str, Any]]) -> None:
        self._conn.executemany(sql, seq)

    @contextmanager
    def _tx(self) -> Iterator[None]:
        if self._tx_depth:
            self._tx_depth += 1
            try:
                yield
            finally:
                self._tx_depth -= 1
            return
        self._conn.execute("BEGIN IMMEDIATE")
        self._tx_depth = 1
        try:
            yield
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        else:
            self._conn.execute("COMMIT")
        finally:
            self._tx_depth = 0

    def _schema_sql(self) -> str:
        return SCHEMA.format(blob="BLOB", real="REAL", serial="INTEGER PRIMARY KEY AUTOINCREMENT")

    def _schema_version(self) -> int:
        try:
            row = self._one("SELECT value FROM meta WHERE key = 'schema_version'")
        except sqlite3.OperationalError:
            return 0
        return int(row["value"]) if row else 0

    @contextmanager
    def session_lock(self, session_id: str) -> Iterator[None]:
        """Thread lock + advisory file lock, so the CLI and the server never interleave."""
        key = f"{self.path}\x00{session_id}"
        with _MEMORY_MUTEX:
            rlock = _MEMORY_LOCKS.setdefault(key, threading.RLock())
        with rlock:
            if self._memory or fcntl is None:
                yield
                return
            lock_dir = Path(self.path).parent / "locks"
            lock_dir.mkdir(exist_ok=True, mode=0o700)
            name = hashlib.sha256(session_id.encode()).hexdigest()[:32]
            with open(lock_dir / f"{name}.lock", "a+") as fh:
                fcntl.flock(fh, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(fh, fcntl.LOCK_UN)

    def close(self) -> None:
        self._conn.close()
