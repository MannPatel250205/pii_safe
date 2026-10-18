"""Storage contract: what PIISafeGuard needs from a backend.

SQLiteStore and PostgresStore (both SQLStore) implement it. A custom backend
(e.g. Redis-cached, multi-tenant) only needs this protocol for the SDK, CLI
sanitise/restore and the MCP server. The dashboard additionally uses SQLStore's
runs / stats / review / API-key methods.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from contextlib import AbstractContextManager
from typing import Any, Protocol


class EntityRow(Protocol):
    alias: str
    entity_type: str
    fingerprint: str
    payload: bytes
    mentions: int
    merged_into: str | None


class Store(Protocol):
    # sessions
    def get_session(self, session_id: str) -> dict[str, Any] | None: ...
    def create_session(self, session_id: str, key_check: str) -> None: ...
    def set_session_turn(self, session_id: str, turn: int) -> None: ...
    def list_sessions(self) -> list[dict[str, Any]]: ...
    def delete_session(self, session_id: str) -> int: ...
    def session_version(self, session_id: str) -> int: ...
    def session_lock(self, session_id: str) -> AbstractContextManager[None]:
        """Exclusive across threads, processes and (for shared databases) hosts."""
        ...

    # registry
    def load_entities(self, session_id: str) -> list[dict[str, Any]]: ...
    def load_fingerprints(self, session_id: str) -> list[tuple[str, str, str]]: ...
    def load_counters(self, session_id: str) -> dict[str, int]: ...
    def save_registry(
        self,
        session_id: str,
        entities: Iterable[dict[str, Any]],
        fingerprints: Iterable[tuple[str, str, str]],
        counters: dict[str, int],
        turn: int,
        version: int | None = None,
    ) -> None: ...

    # audit + events
    def insert_audit(self, rows: Sequence[dict[str, Any]]) -> None: ...
    def query_audit(
        self,
        session_id: str | None = None,
        decision: str | None = None,
        entity_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]: ...
    def log_event(self, session_id: str, kind: str, detail: dict[str, Any]) -> None: ...
    def query_events(self, session_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]: ...

    # key-value metadata (wrapped master key for managed key providers)
    def get_meta(self, key: str) -> str | None: ...
    def set_meta(self, key: str, value: str) -> None: ...
    def set_meta_if_absent(self, key: str, value: str) -> bool: ...

    def close(self) -> None: ...
