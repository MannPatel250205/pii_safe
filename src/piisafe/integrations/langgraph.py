"""LangGraph integration: a node that sanitises graph state before the model sees it.

    from langgraph.graph import START, MessagesState, StateGraph
    from piisafe.integrations.langgraph import sanitize_node

    g = StateGraph(MessagesState)
    g.add_node("pii_guard", sanitize_node(guard))
    g.add_node("agent", call_model)
    g.add_edge(START, "pii_guard")
    g.add_edge("pii_guard", "agent")

The node returns every message in `keys` with its content sanitised and its id
unchanged, so the `add_messages` reducer replaces the originals in place: the raw
text is not kept in the checkpointed state either. Plain (non-reducer) keys are
simply overwritten. Sanitising is idempotent, so running the node every turn is safe.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from piisafe.guard import PIISafeGuard
from piisafe.integrations.langchain import sanitize_value


def sanitize_node(
    guard: PIISafeGuard, keys: Sequence[str] = ("messages",), hook: str = "on_prompt"
) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
    """Build a LangGraph node that sanitises the given state keys."""
    keys = tuple(keys)

    def piisafe_sanitize(state: Mapping[str, Any]) -> dict[str, Any]:
        return {k: sanitize_value(guard, state[k], hook) for k in keys if k in state}

    return piisafe_sanitize
