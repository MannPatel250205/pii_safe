"""Core data types shared across the SDK."""

from __future__ import annotations

import enum
from collections import Counter
from dataclasses import dataclass, field
from typing import Any


class Action(str, enum.Enum):
    ALLOW = "allow"
    PSEUDONYMISE = "pseudonymise"
    REDACT = "redact"
    MASK = "mask"
    BLOCK = "block"

    @classmethod
    def parse(cls, value: str) -> Action:
        v = str(value).strip().lower()
        if v in ("pseudonymize", "pseudonym", "alias"):
            v = "pseudonymise"
        return cls(v)


class Decision(str, enum.Enum):
    """Outcome of entity resolution for a pseudonymised span."""

    EXACT = "EXACT"  # canonical form already registered
    MERGE = "MERGE"  # fuzzy match accepted, existing alias reused
    NEW_ENTITY = "NEW_ENTITY"  # nothing similar, new alias
    DEFERRED = "DEFERRED"  # ambiguous: conservative split + flagged for review


class HookType(str, enum.Enum):
    ON_PROMPT = "on_prompt"
    ON_CONTEXT = "on_context"
    ON_TOOL_CALL = "on_tool_call"
    ON_MEMORY = "on_memory"
    EXPORT = "export"


@dataclass(slots=True)
class Span:
    """A detected PII occurrence in a piece of text."""

    start: int
    end: int
    text: str
    entity_type: str
    score: float
    tier: int
    detector: str
    priority: int = 50
    # Value used for resolution when it differs from the surface text
    # (e.g. the decoded email inside a base64 blob).
    value: str | None = None

    @property
    def length(self) -> int:
        return self.end - self.start

    @property
    def resolve_value(self) -> str:
        return self.value if self.value is not None else self.text

    def overlaps(self, other: Span) -> bool:
        return self.start < other.end and other.start < self.end


@dataclass(slots=True)
class Finding:
    """What happened to one span: detection, policy action and resolution."""

    entity_type: str
    start: int
    end: int
    action: Action
    replacement: str
    tier: int
    detector: str
    confidence: float
    policy: str | None
    value_hash: str
    alias: str | None = None
    decision: Decision | None = None
    resolution_score: float | None = None
    candidate_alias: str | None = None
    linked: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "start": self.start,
            "end": self.end,
            "action": self.action.value,
            "replacement": self.replacement,
            "alias": self.alias,
            "decision": self.decision.value if self.decision else None,
            "confidence": round(self.confidence, 3),
            "resolution_score": (
                round(self.resolution_score, 3) if self.resolution_score is not None else None
            ),
            "candidate_alias": self.candidate_alias,
            "tier": self.tier,
            "detector": self.detector,
            "policy": self.policy,
            "linked": list(self.linked),
        }


@dataclass(slots=True)
class SanitiseResult:
    sanitised_text: str
    findings: list[Finding]
    risk_score: float
    residual_risk: float
    audit_id: str
    hook_type: str
    session_id: str
    latency_ms: float = 0.0
    dropped: bool = False

    @property
    def entities_found(self) -> dict[str, int]:
        return dict(Counter(f.entity_type for f in self.findings))

    @property
    def deferred(self) -> list[Finding]:
        return [f for f in self.findings if f.decision is Decision.DEFERRED]

    def to_dict(self) -> dict[str, Any]:
        return {
            "sanitised_text": self.sanitised_text,
            "risk_score": self.risk_score,
            "residual_risk": self.residual_risk,
            "audit_id": self.audit_id,
            "hook_type": self.hook_type,
            "session_id": self.session_id,
            "entities_found": self.entities_found,
            "findings": [f.to_dict() for f in self.findings],
        }

    def __str__(self) -> str:
        return self.sanitised_text


@dataclass(slots=True)
class EntityRecord:
    """One resolved real-world entity inside a session.

    Holds plaintext only in memory; persisted encrypted (see storage + crypto).
    """

    alias: str
    entity_type: str
    canonical: str
    surface: str
    fingerprint: str
    variants: set[str] = field(default_factory=set)
    # Canonical forms of all variants ('kavishka', 'kavishka perera'); fuzzy
    # resolution compares against each of them.
    canon_variants: set[str] = field(default_factory=set)
    mentions: int = 0
    first_turn: int = 0
    last_turn: int = 0
    cooccur: set[str] = field(default_factory=set)
    linked: set[str] = field(default_factory=set)
    merged_into: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "canonical": self.canonical,
            "surface": self.surface,
            "variants": sorted(self.variants),
            "canon_variants": sorted(self.canon_variants),
            "first_turn": self.first_turn,
            "last_turn": self.last_turn,
            "cooccur": sorted(self.cooccur),
            "linked": sorted(self.linked),
        }

    @classmethod
    def from_payload(
        cls,
        alias: str,
        entity_type: str,
        fingerprint: str,
        mentions: int,
        merged_into: str | None,
        payload: dict[str, Any],
    ) -> EntityRecord:
        return cls(
            alias=alias,
            entity_type=entity_type,
            canonical=payload["canonical"],
            surface=payload["surface"],
            fingerprint=fingerprint,
            variants=set(payload.get("variants", [])),
            canon_variants=set(payload.get("canon_variants", [payload["canonical"]])),
            mentions=mentions,
            first_turn=payload.get("first_turn", 0),
            last_turn=payload.get("last_turn", 0),
            cooccur=set(payload.get("cooccur", [])),
            linked=set(payload.get("linked", [])),
            merged_into=merged_into,
        )
