"""Web service + dashboard. Requires the `server` extra: pip install 'piisafe[server]'."""

from __future__ import annotations

from typing import Any

__all__ = ["create_app", "ensure_admin_key"]


def __getattr__(name: str) -> Any:
    # Lazy, so `piisafe.server.pool` (used by the MCP server) imports without FastAPI.
    if name in __all__:
        from piisafe.server import app

        return getattr(app, name)
    raise AttributeError(name)
