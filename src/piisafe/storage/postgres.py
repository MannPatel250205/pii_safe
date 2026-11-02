"""PostgreSQL backend: shared state for several API replicas and CLI hosts.

    PIISAFE_DATABASE_URL=postgresql://piisafe:***@db.internal:5432/piisafe

Requires `pip install 'piisafe[postgres]'` (psycopg 3). Session exclusivity uses
transaction-independent advisory locks, so it holds across hosts.
"""

from __future__ import annotations

import hashlib
import re
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from piisafe.storage.sql import SCHEMA, SQLStore

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError as exc:  # pragma: no cover
    raise ImportError("PostgreSQL support needs psycopg: pip install 'piisafe[postgres]'") from exc

_NAMED = re.compile(r"(?<![:\w]):([A-Za-z_]\w*)")
_SCHEMA_LOCK = 0x5049_4953_4146_45  # advisory lock id for migrations ("PIISAFE")


def _translate(sql: str) -> str:
    """'?' and ':name' placeholders -> psycopg's '%s' and '%(name)s'."""
    return _NAMED.sub(r"%(\1)s", sql.replace("?", "%s"))


class PostgresStore(SQLStore):
    dialect = "postgres"
    day_expr = "to_char(to_timestamp(ts), 'YYYY-MM-DD')"

    def __init__(self, url: str) -> None:
        self.url = url
        self._conn = psycopg.connect(url, autocommit=True, row_factory=dict_row)
        self._lock = threading.RLock()  # psycopg connections are not for concurrent use
        self._held: dict[str, int] = {}
        self._apply_schema()

    @property
    def path(self) -> str:  # for display; never includes the password
        info = self._conn.info
        return f"postgresql://{info.user}@{info.host}:{info.port}/{info.dbname}"

    # ------------------------------------------------------------ primitives

    def _rows(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(_translate(sql), params or None)
            return list(cur.fetchall()) if cur.description else []

    def _exec(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> int:
        with self._lock:
            return int(self._conn.execute(_translate(sql), params or None).rowcount)

    def _exec_many(self, sql: str, seq: Sequence[Sequence[Any] | dict[str, Any]]) -> None:
        with self._lock, self._conn.cursor() as cur:
            cur.executemany(_translate(sql), seq)

    @contextmanager
    def _tx(self) -> Iterator[None]:
        with self._lock, self._conn.transaction():
            yield

    def _schema_sql(self) -> str:
        return SCHEMA.format(blob="BYTEA", real="DOUBLE PRECISION", serial="BIGSERIAL PRIMARY KEY")

    def _schema_version(self) -> int:
        row = self._one("SELECT to_regclass('meta') IS NOT NULL AS present")
        if not row or not row["present"]:
            return 0
        v = self._one("SELECT value FROM meta WHERE key = 'schema_version'")
        return int(v["value"]) if v else 0

    def _apply_schema(self) -> None:
        # Serialise migrations when several replicas start at once.
        with self._lock:
            self._conn.execute("SELECT pg_advisory_lock(%s)", (_SCHEMA_LOCK,))
            try:
                super()._apply_schema()
            finally:
                self._conn.execute("SELECT pg_advisory_unlock(%s)", (_SCHEMA_LOCK,))

    @staticmethod
    def _lock_id(session_id: str) -> int:
        return int.from_bytes(hashlib.sha256(session_id.encode()).digest()[:8], "big", signed=True)

    @contextmanager
    def session_lock(self, session_id: str) -> Iterator[None]:
        """Session-level advisory lock: exclusive across every replica and CLI host."""
        with self._lock:
            depth = self._held.get(session_id, 0)
            if depth == 0:
                self._conn.execute("SELECT pg_advisory_lock(%s)", (self._lock_id(session_id),))
            self._held[session_id] = depth + 1
        try:
            yield
        finally:
            with self._lock:
                self._held[session_id] -= 1
                if self._held[session_id] == 0:
                    del self._held[session_id]
                    self._conn.execute("SELECT pg_advisory_unlock(%s)", (self._lock_id(session_id),))

    def close(self) -> None:
        with self._lock:
            self._conn.close()
