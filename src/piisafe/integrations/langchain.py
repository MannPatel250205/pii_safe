"""LangChain integration.

    from piisafe import PIISafeGuard
    from piisafe.integrations.langchain import PIISafeCallbackHandler, restore_runnable, sanitize_runnable

    guard = PIISafeGuard(session_id="INC-001")
    chain = sanitize_runnable(guard) | prompt | llm
    chain.invoke({"question": "Why was raj.mehta@corp.com locked out?"},
                 config={"callbacks": [PIISafeCallbackHandler(guard)]})

* `sanitize_runnable` rewrites what flows through it (strings, messages, prompt
  values, documents, dicts / lists of those) before it reaches the model.
* `PIISafeCallbackHandler` is a guard rail: LangChain callbacks cannot change
  inputs, so it *checks* every prompt sent to an LLM and raises
  `UnsanitisedPIIError` (or warns) if raw PII got past the sanitiser.
* `restore_runnable` turns aliases in the model's answer back into real values.
  Only put it at the very end, in front of a user allowed to see them; every
  restore is written to the events log.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from typing import Any

from piisafe.exceptions import PIISafeError
from piisafe.guard import PIISafeGuard
from piisafe.models import Action

try:
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.documents import Document
    from langchain_core.messages import BaseMessage
    from langchain_core.prompt_values import ChatPromptValue, PromptValue, StringPromptValue
    from langchain_core.runnables import RunnableLambda
except ImportError as exc:  # pragma: no cover
    raise ImportError("The LangChain integration needs langchain-core: pip install 'piisafe[langchain]'") from exc

log = logging.getLogger("piisafe.langchain")


class UnsanitisedPIIError(PIISafeError):
    """Raw PII was about to be sent to an LLM."""

    def __init__(self, entity_types: Sequence[str]) -> None:
        self.entity_types = sorted(set(entity_types))
        super().__init__(f"unsanitised PII in LLM prompt: {', '.join(self.entity_types)}")


# ===================================================================== values


def _text(guard: PIISafeGuard, text: str, hook: str) -> str:
    return guard.sanitize(text, hook).sanitised_text


def _content(guard: PIISafeGuard, content: Any, hook: str) -> Any:
    """Message content is a string or a list of parts ({'type': 'text', 'text': ...})."""
    if isinstance(content, str):
        return _text(guard, content, hook)
    if isinstance(content, list):
        out: list[Any] = []
        for part in content:
            if isinstance(part, str):
                out.append(_text(guard, part, hook))
            elif isinstance(part, Mapping) and isinstance(part.get("text"), str):
                out.append({**part, "text": _text(guard, part["text"], hook)})
            else:
                out.append(part)  # images, audio … are passed through untouched
        return out
    return content


def sanitize_value(guard: PIISafeGuard, value: Any, hook: str = "on_prompt") -> Any:
    """Sanitise anything LangChain passes between steps. Unknown types pass through."""
    with guard.turn():  # one turn: shared co-occurrence context for name resolution
        return _walk(guard, value, hook)


def _walk(guard: PIISafeGuard, value: Any, hook: str) -> Any:
    if isinstance(value, str):
        return _text(guard, value, hook)
    if isinstance(value, BaseMessage):
        return value.model_copy(update={"content": _content(guard, value.content, hook)})
    if isinstance(value, Document):
        return value.model_copy(update={"page_content": _text(guard, value.page_content, "on_context")})
    if isinstance(value, StringPromptValue):
        return StringPromptValue(text=_text(guard, value.text, hook))
    if isinstance(value, PromptValue):
        return ChatPromptValue(messages=[_walk(guard, m, hook) for m in value.to_messages()])
    if isinstance(value, Mapping):
        return {k: _walk(guard, v, hook) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_walk(guard, v, hook) for v in value)
    return value


def restore_value(guard: PIISafeGuard, value: Any) -> Any:
    """Replace aliases with the original values (audited). Use only for the final answer."""
    if isinstance(value, str):
        return guard.restore(value)
    if isinstance(value, BaseMessage):
        content = value.content
        if isinstance(content, str):
            content = guard.restore(content)
        elif isinstance(content, list):
            content = [
                {**p, "text": guard.restore(p["text"])} if isinstance(p, Mapping) and isinstance(p.get("text"), str)
                else guard.restore(p) if isinstance(p, str) else p
                for p in content
            ]
        return value.model_copy(update={"content": content})
    if isinstance(value, Mapping):
        return {k: restore_value(guard, v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(restore_value(guard, v) for v in value)
    return value


# ================================================================== runnables


def sanitize_runnable(guard: PIISafeGuard, hook: str = "on_prompt") -> RunnableLambda:
    """A Runnable that sanitises its input. Put it first in a chain: `sanitize_runnable(g) | prompt | llm`."""
    return RunnableLambda(lambda value: sanitize_value(guard, value, hook), name="piisafe_sanitize")


def restore_runnable(guard: PIISafeGuard) -> RunnableLambda:
    """A Runnable that restores aliases in its input. Put it last, after the output parser."""
    return RunnableLambda(lambda value: restore_value(guard, value), name="piisafe_restore")


# ================================================================== callback


class PIISafeCallbackHandler(BaseCallbackHandler):
    """Checks every LLM prompt for raw PII.

    mode="raise" (default) aborts the run with UnsanitisedPIIError; mode="warn"
    only logs the entity types. Detection uses a private in-memory guard, so the
    check never adds aliases or audit rows to your session and never logs values.
    By default only structured PII (emails, IPs, cards, secrets …) is checked;
    check_names=True also runs name detection, which can flag product names.
    """

    raise_error = True  # let UnsanitisedPIIError propagate out of LangChain

    def __init__(
        self, guard: PIISafeGuard, mode: str = "raise", hook: str = "on_prompt", check_names: bool = False
    ) -> None:
        if mode not in ("raise", "warn"):
            raise ValueError("mode must be 'raise' or 'warn'")
        self.mode = mode
        self.hook = hook
        self._checker = PIISafeGuard(guard.policy, "callback-check", ephemeral=True, block_mode="redact",
                                     ner=None if check_names else "off")

    def _check(self, texts: Sequence[str]) -> None:
        found: list[str] = []
        for text in texts:
            r = self._checker.sanitize(text, self.hook)
            found += [f.entity_type for f in r.findings if f.action is not Action.ALLOW]
        if not found:
            return
        if self.mode == "raise":
            raise UnsanitisedPIIError(found)
        log.warning("unsanitised PII in LLM prompt: %s", ", ".join(sorted(set(found))))

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        self._check(prompts)

    def on_chat_model_start(
        self, serialized: dict[str, Any], messages: list[list[BaseMessage]], **kwargs: Any
    ) -> None:
        texts: list[str] = []
        for batch in messages:
            for m in batch:
                if isinstance(m.content, str):
                    texts.append(m.content)
                else:
                    texts += [p if isinstance(p, str) else str(p.get("text", ""))
                              for p in m.content if isinstance(p, (str, Mapping))]
        self._check(texts)
