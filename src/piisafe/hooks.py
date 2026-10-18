"""Hook registry (Observer pattern).

Hooks register a handler by name; the guard dispatches to it. A v2 hook such
as ``on_tool_result`` is one ``register`` call — no dispatcher changes.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from piisafe.exceptions import PIISafeError

Handler = Callable[..., Any]


class HookRegistry:
    def __init__(self) -> None:
        self._handlers: dict[str, Handler] = {}

    def register(self, name: str, handler: Handler) -> None:
        self._handlers[name] = handler

    def dispatch(self, name: str, *args: Any, **kwargs: Any) -> Any:
        try:
            handler = self._handlers[name]
        except KeyError:
            raise PIISafeError(
                f"no handler registered for hook '{name}' (have: {', '.join(self.names())})"
            ) from None
        return handler(*args, **kwargs)

    def names(self) -> list[str]:
        return sorted(self._handlers)
