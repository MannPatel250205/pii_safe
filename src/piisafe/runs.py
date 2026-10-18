"""Recording file jobs and usage so the dashboard can show CLI and web activity alike."""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from piisafe.io.processor import RunStats
from piisafe.storage.base import Store


def record_run(
    store: Store,
    *,
    session_id: str,
    source: str,
    origin: str,
    hook: str,
    fmt: str | None,
    status: str,
    stats: RunStats | None,
    duration_s: float,
    actor: str | None = None,
    output_path: str | None = None,
    extra: dict[str, Any] | None = None,
    run_id: str | None = None,
) -> str:
    """Store one run row (aggregates only — never content) and bump the daily usage counter."""
    run_id = run_id or uuid.uuid4().hex[:16]
    report = {**(stats.to_dict() if stats else {}), **(extra or {})}
    store.insert_run(  # type: ignore[attr-defined]
        {
            "id": run_id,
            "ts": time.time(),
            "session_id": session_id,
            "source": Path(source).name if source not in ("<stdin>", "<text>") else source,
            "origin": origin,
            "actor": actor,
            "hook_type": hook,
            "format": fmt,
            "status": status,
            "records": stats.records if stats else 0,
            "findings": stats.total_findings if stats else 0,
            "max_risk": stats.max_risk if stats else 0.0,
            "duration_s": round(duration_s, 3),
            "output_path": output_path,
            "report": report,
        }
    )
    store.add_usage(origin, stats.records if stats else 0, stats.total_findings if stats else 0)  # type: ignore[attr-defined]
    return run_id
