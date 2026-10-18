"""Streaming file processors for text / JSONL / JSON / CSV.

One line (or record) = one turn, so co-occurrence works per log event.
Text is streamed, so multi-GB logs use constant memory.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from piisafe import scoring
from piisafe.exceptions import PolicyBlockError
from piisafe.guard import PIISafeGuard
from piisafe.models import Decision, Finding

FORMATS = ("text", "jsonl", "json", "csv")
_EXT = {".jsonl": "jsonl", ".ndjson": "jsonl", ".json": "json", ".csv": "csv"}


def detect_format(path: str | None, explicit: str = "auto") -> str:
    if explicit != "auto":
        return explicit
    if path and path != "-":
        return _EXT.get(Path(path).suffix.lower(), "text")
    return "text"


class BlockedAt(Exception):
    def __init__(self, line: int, error: PolicyBlockError) -> None:
        self.line = line
        self.error = error
        super().__init__(f"line {line}: {error}")


@dataclass
class RunStats:
    records: int = 0
    records_with_pii: int = 0
    dropped: int = 0
    by_type: Counter[str] = field(default_factory=Counter)
    by_action: Counter[str] = field(default_factory=Counter)
    by_tier: Counter[int] = field(default_factory=Counter)
    by_detector: Counter[str] = field(default_factory=Counter)
    by_decision: Counter[str] = field(default_factory=Counter)
    deferred: list[dict[str, Any]] = field(default_factory=list)
    max_risk: float = 0.0
    max_residual: float = 0.0
    risk_sum: float = 0.0
    dropped_lines: list[int] = field(default_factory=list)

    def add(self, findings: list[Finding], line: int, sensitivity: dict[str, float]) -> None:
        self.records += 1
        if not findings:
            return
        self.records_with_pii += 1
        risk = scoring.exposure(findings, sensitivity)
        self.risk_sum += risk
        self.max_risk = max(self.max_risk, risk)
        self.max_residual = max(self.max_residual, scoring.residual(findings, sensitivity))
        for f in findings:
            self.by_type[f.entity_type] += 1
            self.by_action[f.action.value] += 1
            self.by_tier[f.tier] += 1
            self.by_detector[f.detector] += 1
            if f.decision:
                self.by_decision[f.decision.value] += 1
            if f.decision is Decision.DEFERRED and len(self.deferred) < 500:
                self.deferred.append(
                    {"line": line, "alias": f.alias, "candidate": f.candidate_alias,
                     "score": round(f.resolution_score or 0, 3)}
                )

    @property
    def total_findings(self) -> int:
        return sum(self.by_type.values())

    @property
    def mean_risk(self) -> float:
        return round(self.risk_sum / self.records_with_pii, 1) if self.records_with_pii else 0.0

    def to_dict(self) -> dict[str, Any]:
        total = self.total_findings
        return {
            "records": self.records,
            "records_with_pii": self.records_with_pii,
            "dropped_records": self.dropped,
            "dropped_lines": self.dropped_lines[:1000],
            "findings": total,
            "by_entity_type": dict(self.by_type.most_common()),
            "by_action": dict(self.by_action.most_common()),
            "by_tier": {f"tier{k}": v for k, v in sorted(self.by_tier.items())},
            "tier1_hit_rate": round(self.by_tier.get(1, 0) / total, 3) if total else None,
            "by_detector": dict(self.by_detector.most_common()),
            "resolution": dict(self.by_decision.most_common()),
            "deferred": self.deferred,
            "risk": {
                "max_record_exposure": self.max_risk,
                "mean_record_exposure": self.mean_risk,
                "max_residual_exposure": self.max_residual,
            },
        }


class Processor:
    """Runs a guard over a stream in one of the supported formats.

    on_block: "fail" (raise BlockedAt) | "drop" (omit the record) | "redact"
    (the guard must then be built with block_mode="redact").
    """

    def __init__(
        self,
        guard: PIISafeGuard,
        hook: str = "on_prompt",
        policy_id: str | None = None,
        on_block: str = "fail",
        source: str | None = None,
        on_findings: Callable[[int, str, list[Finding]], None] | None = None,
        progress: Callable[[int], None] | None = None,
    ) -> None:
        self.guard = guard
        self.hook = hook
        self.policy_id = policy_id
        self.on_block = on_block
        self.source = source
        self.stats = RunStats()
        self._on_findings = on_findings
        self._progress = progress
        self._sens = guard.policy.sensitivity

    def run(self, fmt: str, src: TextIO, dst: TextIO | None) -> RunStats:
        handler = {
            "text": self._text,
            "jsonl": self._jsonl,
            "json": self._json,
            "csv": self._csv,
        }[fmt]
        # One lock + one flush for the whole file instead of per line.
        with self.guard.exclusive():
            handler(src, dst)
        return self.stats

    # ---------------------------------------------------------------- helpers

    def _record(self, line_no: int, raw: str, findings: list[Finding]) -> None:
        self.stats.add(findings, line_no, self._sens)
        if self._on_findings is not None and findings:
            self._on_findings(line_no, raw, findings)

    def _blocked(self, line_no: int, exc: PolicyBlockError) -> None:
        if self.on_block == "fail":
            raise BlockedAt(line_no, exc) from exc
        self.stats.records += 1
        self.stats.dropped += 1
        self.stats.dropped_lines.append(line_no)

    def _tick(self, n: int) -> None:
        if self._progress is not None:
            self._progress(n)

    # ---------------------------------------------------------------- formats

    def _text(self, src: TextIO, dst: TextIO | None) -> None:
        for line_no, raw in enumerate(src, 1):
            self._tick(len(raw))
            body = raw.rstrip("\r\n")
            ending = raw[len(body):]
            try:
                r = self.guard.sanitize(body, self.hook, policy_id=self.policy_id,
                                        source=self.source, line=line_no)
            except PolicyBlockError as exc:
                self._blocked(line_no, exc)
                continue
            self._record(line_no, body, r.findings)
            if dst is not None:
                dst.write(r.sanitised_text + ending)

    def _jsonl(self, src: TextIO, dst: TextIO | None) -> None:
        for line_no, raw in enumerate(src, 1):
            self._tick(len(raw))
            body = raw.rstrip("\r\n")
            ending = raw[len(body):] or "\n"
            if not body.strip():
                if dst is not None:
                    dst.write(raw)
                continue
            try:
                obj = json.loads(body)
            except json.JSONDecodeError:
                obj = None
            try:
                if obj is None or not isinstance(obj, (dict, list)):
                    r = self.guard.sanitize(body, self.hook, policy_id=self.policy_id,
                                            source=self.source, line=line_no)
                    out, findings = r.sanitised_text, r.findings
                else:
                    clean, findings = self.guard.sanitize_record(
                        obj, self.hook, policy_id=self.policy_id, source=self.source, line=line_no
                    )
                    out = json.dumps(clean, ensure_ascii=False)
            except PolicyBlockError as exc:
                self._blocked(line_no, exc)
                continue
            self._record(line_no, body, findings)
            if dst is not None:
                dst.write(out + ending)

    def _json(self, src: TextIO, dst: TextIO | None) -> None:
        text = src.read()
        self._tick(len(text))
        obj = json.loads(text)
        items: Iterable[Any] = obj if isinstance(obj, list) else [obj]
        out_items = []
        for idx, item in enumerate(items, 1):
            try:
                clean, findings = self.guard.sanitize_record(
                    item, self.hook, policy_id=self.policy_id, source=self.source, line=idx
                )
            except PolicyBlockError as exc:
                self._blocked(idx, exc)
                continue
            self._record(idx, json.dumps(item, ensure_ascii=False), findings)
            out_items.append(clean)
        if dst is not None:
            result = out_items if isinstance(obj, list) else (out_items[0] if out_items else None)
            json.dump(result, dst, ensure_ascii=False, indent=2)
            dst.write("\n")

    def _csv(self, src: TextIO, dst: TextIO | None) -> None:
        reader = csv.reader(src)
        writer = csv.writer(dst) if dst is not None else None
        header: list[str] | None = None
        for row in reader:
            line_no = reader.line_num
            if header is None:
                # Unique keys, so duplicate column names don't swallow values.
                header = [h if row.index(h) == i else f"{h}#{i}" for i, h in enumerate(row)]
                if writer is not None:
                    writer.writerow(row)
                continue
            buf = io.StringIO()
            csv.writer(buf).writerow(row)
            self._tick(len(buf.getvalue()))
            record = {(header[i] if i < len(header) else f"col{i}"): v for i, v in enumerate(row)}
            try:
                clean, findings = self.guard.sanitize_record(
                    record, self.hook, policy_id=self.policy_id, source=self.source, line=line_no
                )
            except PolicyBlockError as exc:
                self._blocked(line_no, exc)
                continue
            self._record(line_no, ",".join(row), findings)
            if writer is not None:
                writer.writerow(list(clean.values()))
