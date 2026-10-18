"""Session-memory recogniser.

Once an entity has been seen in a session (e.g. "Kavishka" found by NER in
turn 1), any later bare mention is caught deterministically — even in text
where NER would miss it ("kavishka ok"). Built from the decrypted registry.
"""

from __future__ import annotations

import re

from piisafe import entities as E
from piisafe.models import Span

_MIN_LEN = 3
# Lower-case re-mentions of names are only trusted for longer names ('kavishka'),
# not short ones that collide with words ('mark', 'will').
_MIN_CASELESS_LEN = 6


class SessionMemoryDetector:
    def __init__(self) -> None:
        # casefold -> {(entity_type, exact_surface)}
        self._terms: dict[str, set[tuple[str, str]]] = {}
        self._regex: re.Pattern[str] | None = None
        self._dirty = False

    def __len__(self) -> int:
        return len(self._terms)

    def add(self, surface: str, entity_type: str) -> None:
        surface = surface.strip()
        if len(surface) < _MIN_LEN or entity_type not in E.MEMORABLE_TYPES:
            return
        key = surface.casefold()
        bucket = self._terms.setdefault(key, set())
        if (entity_type, surface) not in bucket:
            bucket.add((entity_type, surface))
            self._dirty = True

    def _compiled(self) -> re.Pattern[str] | None:
        if self._dirty:
            alts = sorted(self._terms, key=len, reverse=True)
            self._regex = (
                re.compile(
                    r"(?<![\w@.\-])(?:" + "|".join(re.escape(a) for a in alts) + r")(?![\w@\-])",
                    re.IGNORECASE,
                )
                if alts
                else None
            )
            self._dirty = False
        return self._regex

    def detect(self, text: str) -> list[Span]:
        regex = self._compiled()
        if regex is None:
            return []
        spans: list[Span] = []
        for m in regex.finditer(text):
            found = m.group(0)
            entity_type = None
            for etype, surface in sorted(self._terms.get(found.casefold(), ())):
                if etype == E.USERNAME:
                    if found == surface:
                        entity_type = etype
                        break
                elif found[0].isupper() or found == surface or len(found) >= _MIN_CASELESS_LEN:
                    entity_type = etype
                    break
            if entity_type is not None:
                spans.append(
                    Span(m.start(), m.end(), found, entity_type, 0.9, 2, "session_memory", 20)
                )
        return spans
