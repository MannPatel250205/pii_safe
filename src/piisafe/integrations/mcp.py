"""MCP server: PII-Safe as tools for any MCP client (Claude Desktop, Claude Code, Cursor …).

    piisafe mcp                                   # stdio (what desktop clients launch)
    piisafe mcp --transport streamable-http       # HTTP on 127.0.0.1:8766/mcp

Tools:
    sanitize        text -> aliased text, risk score, entity counts (persisted per session)
    scan            dry run: entity types, positions and masked previews; nothing stored
    score_exposure  0-100 exposure score of a text; nothing stored
    restore         aliases -> real values. Disabled unless started with --allow-restore,
                    because it hands real PII back to the model. Every call is logged.

Tool results never contain detected values, only aliases, types and masked previews.
State (registry, audit, keys) is the same as the CLI and dashboard use, so a session
sanitised here shows up in the dashboard's review queue.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from piisafe.config import default_state_dir
from piisafe.guard import PIISafeGuard
from piisafe.models import Action
from piisafe.normalize import normalize_text
from piisafe.policy import Policy
from piisafe.server.pool import GuardPool
from piisafe.storage import open_store

try:  # mcp >= 2 renamed FastMCP to MCPServer
    from mcp.server.mcpserver import MCPServer as _Server
except ImportError:  # pragma: no cover
    try:
        from mcp.server.fastmcp import FastMCP as _Server  # type: ignore[attr-defined,no-redef]
    except ImportError as exc:
        raise ImportError("The MCP server needs the MCP SDK: pip install 'piisafe[mcp]'") from exc

SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
HOOK_RE = re.compile(r"^[a-z][a-z0-9_]{0,40}$")
MAX_TEXT = 1_000_000

INSTRUCTIONS = (
    "PII-Safe replaces personal data (emails, IPs, names, cards, secrets …) with stable aliases "
    "such as USER_001 or MAIL_002. Call `sanitize` on logs, tickets or user text before reasoning "
    "over them, and refer to people and hosts by their aliases. Use the same session_id for one "
    "investigation so aliases stay consistent."
)


def _mask(value: str) -> str:
    if len(value) <= 2:
        return "•" * len(value)
    keep = max(1, len(value) // 5)
    return value[:keep] + "•" * min(len(value) - 2 * keep, 10) + value[-keep:]


def _check(text: str, session_id: str | None = None, hook: str = "on_prompt") -> None:
    if len(text) > MAX_TEXT:
        raise ValueError(f"text is longer than {MAX_TEXT:,} characters")
    if session_id is not None and not SESSION_RE.match(session_id):
        raise ValueError("session_id: 1-64 chars of letters, digits and . _ : -")
    if not HOOK_RE.match(hook):
        raise ValueError("invalid hook")


def build_server(
    policy: str | Path | Policy | None = None,
    *,
    state_dir: str | Path | None = None,
    database_url: str | None = None,
    key_provider: str | None = None,
    allow_restore: bool = False,
    host: str = "127.0.0.1",
    port: int = 8766,
) -> Any:
    pol = policy if isinstance(policy, Policy) else Policy.load(policy) if policy else Policy.default()
    state = Path(state_dir).expanduser() if state_dir else default_state_dir()
    pool = GuardPool(state, lambda: pol, database_url=database_url, key_provider=key_provider)
    kwargs: dict[str, Any] = {"instructions": INSTRUCTIONS}
    if _Server.__name__ == "FastMCP":  # mcp 1.x takes the HTTP bind address here
        kwargs.update(host=host, port=port)
    server = _Server("piisafe", **kwargs)

    def _dry_run(text: str, hook: str) -> tuple[PIISafeGuard, Any]:
        guard = PIISafeGuard(pol, "mcp-scan", ephemeral=True, block_mode="redact")
        return guard, guard.sanitize(text, hook)

    @server.tool(description="Replace PII in text with stable aliases. Same session_id = same aliases.")
    def sanitize(text: str, session_id: str = "mcp-default", hook: str = "on_prompt") -> dict[str, Any]:
        _check(text, session_id, hook)
        with pool.session(session_id) as guard:
            r = guard.sanitize(text, hook, source="mcp")
        return {
            "sanitised_text": r.sanitised_text,
            "session_id": r.session_id,
            "risk_score": r.risk_score,
            "residual_risk": r.residual_risk,
            "entities_found": r.entities_found,
            "needs_review": len(r.deferred),
        }

    @server.tool(description="Dry run: list PII found in text (types, positions, masked previews). Stores nothing.")
    def scan(text: str, hook: str = "on_prompt") -> dict[str, Any]:
        _check(text, hook=hook)
        guard, r = _dry_run(text, hook)
        guard.close()
        norm = normalize_text(text)
        findings = [
            {"entity_type": f.entity_type, "start": f.start, "end": f.end, "action": f.action.value,
             "confidence": round(f.confidence, 3), "preview": _mask(norm[f.start:f.end])}
            for f in r.findings
        ]
        return {"count": len(findings), "risk_score": r.risk_score, "findings": findings}

    @server.tool(description="Privacy exposure score (0-100) of a text, plus counts per PII type. Stores nothing.")
    def score_exposure(text: str, hook: str = "on_prompt") -> dict[str, Any]:
        _check(text, hook=hook)
        guard, r = _dry_run(text, hook)
        guard.close()
        return {
            "risk_score": r.risk_score,
            "residual_risk": r.residual_risk,
            "entities_found": r.entities_found,
            "would_leave_in_clear": sorted({f.entity_type for f in r.findings if f.action is Action.ALLOW}),
        }

    if allow_restore:
        @server.tool(description="Replace aliases (USER_001 …) with the real values. Audited. Returns real PII.")
        def restore(text: str, session_id: str) -> dict[str, Any]:
            _check(text, session_id)
            with pool.session(session_id, create=False, store_exists=session_exists) as guard:
                return {"text": guard.restore(text)}

        def session_exists(sid: str) -> bool:
            store = open_store(database_url, state)
            try:
                return store.get_session(sid) is not None
            finally:
                store.close()

    server.piisafe_pool = pool  # type: ignore[attr-defined]  # for tests and clean shutdown
    return server


def run(transport: str = "stdio", host: str = "127.0.0.1", port: int = 8766, **kwargs: Any) -> None:
    server = build_server(host=host, port=port, **kwargs)
    try:
        if transport == "stdio" or _Server.__name__ == "FastMCP":
            server.run(transport)
        else:
            server.run(transport, host=host, port=port)
    finally:
        server.piisafe_pool.clear()
