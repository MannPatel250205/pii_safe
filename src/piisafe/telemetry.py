"""Per-stage latency recording (p50/p90/p99), cheap enough for the hot path.

OpenTelemetry export plugs in here later; the CLI only needs local percentiles.
"""

from __future__ import annotations

import random
import time
from collections.abc import Iterator
from contextlib import contextmanager

_RESERVOIR = 20_000


class LatencyRecorder:
    def __init__(self) -> None:
        self._samples: dict[str, list[float]] = {}
        self._counts: dict[str, int] = {}

    @contextmanager
    def time(self, stage: str) -> Iterator[None]:
        t0 = time.perf_counter()
        try:
            yield
        finally:
            self.add(stage, (time.perf_counter() - t0) * 1000.0)

    def add(self, stage: str, ms: float) -> None:
        n = self._counts.get(stage, 0) + 1
        self._counts[stage] = n
        bucket = self._samples.setdefault(stage, [])
        if len(bucket) < _RESERVOIR:
            bucket.append(ms)
        else:  # reservoir sampling keeps memory bounded on huge files
            j = random.randrange(n)
            if j < _RESERVOIR:
                bucket[j] = ms

    def summary(self) -> dict[str, dict[str, float]]:
        out: dict[str, dict[str, float]] = {}
        for stage, values in self._samples.items():
            v = sorted(values)
            out[stage] = {
                "calls": self._counts[stage],
                "p50_ms": _pct(v, 50),
                "p90_ms": _pct(v, 90),
                "p99_ms": _pct(v, 99),
                "max_ms": round(v[-1], 4) if v else 0.0,
            }
        return out


def _pct(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    k = (len(sorted_values) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(sorted_values) - 1)
    return round(sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo), 4)
