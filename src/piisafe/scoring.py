"""Privacy exposure score, 0-100.

S = sum(sensitivity(type) * confidence) over findings;
score = 100 * (1 - exp(-S / K)).  Saturating, so one credit card (~10) scores
~63 and a page full of PII approaches 100 without overflowing.
"""

from __future__ import annotations

import math
from collections.abc import Iterable

from piisafe import entities as E
from piisafe.models import Action, Finding

K = 10.0


def exposure(findings: Iterable[Finding], overrides: dict[str, float] | None = None) -> float:
    s = sum(E.sensitivity(f.entity_type, overrides) * f.confidence for f in findings)
    return round(100.0 * (1.0 - math.exp(-s / K)), 1)


def residual(findings: Iterable[Finding], overrides: dict[str, float] | None = None) -> float:
    """Exposure of what still leaves in clear text (action=allow)."""
    return exposure((f for f in findings if f.action is Action.ALLOW), overrides)
