"""Detection cascade (Chain of Responsibility).

Tier 1 runs on everything. Characters it claims are masked out, so Tier 2 only
sees what Tier 1 missed (the "short-circuit" per span). Tier 2 is skipped
entirely when no capitalised word remains — the common case for structured logs.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from piisafe import entities as E
from piisafe.detection.memory import SessionMemoryDetector
from piisafe.detection.ner import NERDetector
from piisafe.detection.patterns import Tier1Detector, resolve_overlaps
from piisafe.models import Span
from piisafe.telemetry import LatencyRecorder

# Tier 2 only looks for capitalised words; lines without one (ISO timestamps,
# ALL_CAPS status codes, lowercase key=value logs) skip NER entirely.
_CAPITALISED = re.compile(r"[A-Z][a-z]")


def mask_spans(text: str, spans: Sequence[Span]) -> str:
    if not spans:
        return text
    chars = list(text)
    for s in spans:
        chars[s.start:s.end] = " " * s.length
    return "".join(chars)


class DetectionCascade:
    def __init__(
        self,
        tier1: Tier1Detector,
        ner: NERDetector | None,
        memory: SessionMemoryDetector | None,
        latency: LatencyRecorder | None = None,
    ) -> None:
        self.tier1 = tier1
        self.ner = ner
        self.memory = memory
        self.latency = latency or LatencyRecorder()

    def detect(self, text: str, forced: Sequence[Span] = ()) -> list[Span]:
        with self.latency.time("tier1"):
            spans = resolve_overlaps([*forced, *self.tier1.detect(text)])

        if self.memory is not None and len(self.memory):
            with self.latency.time("memory"):
                extra = [s for s in self.memory.detect(text) if not any(s.overlaps(o) for o in spans)]
                spans = resolve_overlaps([*spans, *extra])

        if self.ner is not None:
            masked = mask_spans(text, spans)
            if _CAPITALISED.search(masked):
                with self.latency.time("tier2"):
                    extra = [s for s in self.ner.detect(masked) if not any(s.overlaps(o) for o in spans)]
                spans = sorted([*spans, *extra], key=lambda s: s.start)
        spans = self._repeat_in_block(text, spans)
        return merge_adjacent_names(text, spans)

    def _repeat_in_block(self, text: str, spans: list[Span]) -> list[Span]:
        """Catch re-mentions of names first found in this same text.

        Session memory only knows names from earlier calls, so in a multi-line
        paste a later 'kavishka' would slip past the 'Kavishka' NER found above
        it. A throwaway memory built from this call's own findings closes that.
        """
        if self.memory is None:
            return spans
        local = SessionMemoryDetector()
        for s in spans:
            if s.entity_type in E.MEMORABLE_TYPES and s.detector != "session_memory":
                local.add(s.text, s.entity_type)
        if not len(local):
            return spans
        extra = [s for s in local.detect(text) if not any(s.overlaps(o) for o in spans)]
        if not extra:
            return spans
        return sorted([*spans, *extra], key=lambda s: s.start)


def merge_adjacent_names(text: str, spans: list[Span]) -> list[Span]:
    """'Kavishka' (session memory) + 'Perera' (NER) -> one PERSON 'Kavishka Perera'."""
    out: list[Span] = []
    for s in spans:
        prev = out[-1] if out else None
        if (
            prev is not None
            and prev.entity_type == s.entity_type == E.PERSON
            and 0 < s.start - prev.end <= 2
            and text[prev.end:s.start].strip(" \t") == ""
        ):
            out[-1] = Span(
                prev.start, s.end, text[prev.start:s.end], E.PERSON, max(prev.score, s.score),
                min(prev.tier, s.tier), f"{prev.detector}+{s.detector}", min(prev.priority, s.priority),
            )
        else:
            out.append(s)
    return out
