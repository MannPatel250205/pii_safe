"""Long-lived guards, one per session, each behind its own (in-process) lock.

Loading a session decrypts its whole registry, so guards are cached (LRU).
The per-session lock is what keeps aliases correct under concurrency: two
requests for the same session can never both allocate USER_005.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from piisafe.exceptions import SessionNotFoundError
from piisafe.guard import PIISafeGuard
from piisafe.policy import Policy


class GuardPool:
    def __init__(
        self,
        state_dir: Path,
        policy: Callable[[], Policy],
        max_size: int = 32,
        database_url: str | None = None,
        key_provider: str | None = None,
    ) -> None:
        self.state_dir = state_dir
        self._database_url = database_url
        self._key_provider = key_provider
        self._policy = policy
        self._max = max_size
        self._guards: OrderedDict[str, PIISafeGuard] = OrderedDict()
        self._built_at: dict[str, int] = {}
        self._generation = 0
        self._locks: dict[str, threading.Lock] = {}
        self._mutex = threading.Lock()

    def _lock_for(self, session_id: str) -> threading.Lock:
        with self._mutex:
            return self._locks.setdefault(session_id, threading.Lock())

    @contextmanager
    def session(self, session_id: str, *, create: bool = True, store_exists: Callable[[str], bool] | None = None
                ) -> Iterator[PIISafeGuard]:
        lock = self._lock_for(session_id)
        with lock:
            guard = self._guards.get(session_id)
            if guard is not None and self._built_at.get(session_id) != self._generation:
                with self._mutex:  # policy changed since this guard was built: rebuild it
                    self._guards.pop(session_id, None)
                guard.close()
                guard = None
            if guard is None:
                if not create and store_exists is not None and not store_exists(session_id):
                    raise SessionNotFoundError(f"session '{session_id}' not found")
                guard = PIISafeGuard(self._policy(), session_id, state_dir=self.state_dir,
                                     database_url=self._database_url, key_provider=self._key_provider)
                with self._mutex:
                    self._guards[session_id] = guard
                    self._built_at[session_id] = self._generation
            with self._mutex:
                self._guards.move_to_end(session_id)
            try:
                # exclusive(): cross-process lock + reload if another replica / the CLI
                # changed this session; writes everything back on exit.
                with guard.exclusive():
                    yield guard
            finally:
                guard.block_mode = "raise"
        self._evict()

    def _evict(self) -> None:
        while True:
            with self._mutex:
                if len(self._guards) <= self._max:
                    return
                sid = next(iter(self._guards))
            self.drop(sid)

    def drop(self, session_id: str) -> None:
        """Close and forget a session's guard (after delete, merge-by-CLI, policy change)."""
        lock = self._lock_for(session_id)
        with lock:
            with self._mutex:
                guard = self._guards.pop(session_id, None)
            if guard is not None:
                guard.close()

    def invalidate(self) -> None:
        """Policy changed: guards are rebuilt lazily on their next use (safe from any thread)."""
        with self._mutex:
            self._generation += 1

    def clear(self) -> None:
        with self._mutex:
            sids = list(self._guards)
        for sid in sids:
            self.drop(sid)
