"""Tier 3 — multi-signal deterministic entity resolution.

For a name-like value, every active entity of the same type is scored on:

    jw        Jaro-Winkler on aligned tokens            (prefix-weighted)
    edit      1 - Damerau-Levenshtein / max length
    typo      shape of the edit: transposition >> insertion
    phonetic  agreement of metaphone / soundex / NYSIIS codes
    cooccur   Jaccard of aliases seen alongside, this turn vs history
    recency   candidate is the most recently mentioned of its type
    pool      candidate is the only entity of its type in the session

Weighted sum -> MERGE (>= merge_threshold), DEFERRED (between) or NEW_ENTITY.

Two guards keep the scorer honest:

* short-name guard: if either name is shorter than ``min_fuzzy_length`` a fuzzy
  match can never MERGE (Raj/Raju, Raj/Ram carry too little evidence) — at most
  DEFERRED.
* token-subset rule: "Raj" vs a single known "Raj Mehta" merges; if several
  known people share that token, it's DEFERRED.

DEFERRED always splits (new alias) and is written to the audit log with the
candidate alias, so a reviewer can merge later (`piisafe sessions merge`).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from piisafe import entities as E
from piisafe.models import Decision, EntityRecord
from piisafe.registry import SessionRegistry
from piisafe.resolution.canonical import identity_tokens
from piisafe.resolution.similarity import (
    aligned_jaro_winkler,
    aligned_phonetic,
    edit_similarity,
    jaccard,
    typo_shape,
)

WEIGHTS = {
    "jw": 0.30,
    "edit": 0.20,
    "typo": 0.15,
    "phonetic": 0.15,
    "cooccur": 0.10,
    "recency": 0.05,
    "pool": 0.05,
}


@dataclass(slots=True)
class ResolutionConfig:
    merge_threshold: float = 0.80
    new_entity_threshold: float = 0.65
    min_fuzzy_length: int = 5
    link_identities: bool = True


@dataclass(slots=True)
class Resolution:
    decision: Decision
    record: EntityRecord | None = None
    score: float | None = None
    candidate: EntityRecord | None = None
    signals: dict[str, float] = field(default_factory=dict)


class EntityResolver:
    def __init__(self, config: ResolutionConfig | None = None) -> None:
        self.config = config or ResolutionConfig()

    def resolve(
        self,
        registry: SessionRegistry,
        entity_type: str,
        canonical: str,
        context_aliases: set[str],
    ) -> Resolution:
        exact = registry.lookup(entity_type, canonical)
        if exact is not None:
            return Resolution(Decision.EXACT, exact, 1.0)
        if entity_type not in E.FUZZY_TYPES:
            return Resolution(Decision.NEW_ENTITY)

        candidates = registry.active(entity_type)
        if not candidates:
            return Resolution(Decision.NEW_ENTITY)

        tokens = canonical.split()
        token_set = set(tokens)

        # Token-subset rule (first name vs full name), against every known variant.
        # Sharing the *first* name is a strong signal; sharing only a surname
        # ('Perera' vs 'Kavishka Perera') could be a relative -> at most DEFERRED.
        subset_hits: list[tuple[EntityRecord, bool]] = []
        for c in candidates:
            strong = weak = False
            for cv in c.canon_variants:
                cv_tokens = cv.split()
                if token_set < set(cv_tokens):
                    strong |= tokens[0] == cv_tokens[0]
                    weak = True
                elif token_set and set(cv_tokens) < token_set:
                    strong |= cv_tokens[0] == tokens[0]
                    weak = True
            if weak:
                subset_hits.append((c, strong))
        if len(subset_hits) == 1 and subset_hits[0][1]:
            return Resolution(Decision.MERGE, subset_hits[0][0], 0.92, signals={"subset": 1.0})
        if subset_hits:
            best = max((c for c, _ in subset_hits), key=lambda c: c.last_turn)
            signals = {"subset": 1.0, "ambiguous": float(len(subset_hits) > 1)}
            return Resolution(Decision.DEFERRED, None, 0.70, best, signals)

        last = registry.last_alias_of_type.get(entity_type)
        best_score, best_rec, best_signals, best_len = -1.0, None, {}, 0
        joined = canonical.replace(" ", "")
        for cand in candidates:
            context = {
                "cooccur": jaccard(context_aliases, cand.cooccur),
                "recency": 1.0 if cand.alias == last else 0.0,
                "pool": 1.0 if len(candidates) == 1 else 0.0,
            }
            for cv in cand.canon_variants:
                c_tokens = cv.split()
                c_joined = cv.replace(" ", "")
                signals = {
                    "jw": aligned_jaro_winkler(tokens, c_tokens),
                    "edit": edit_similarity(joined, c_joined),
                    "typo": typo_shape(joined, c_joined),
                    "phonetic": aligned_phonetic(tokens, c_tokens),
                    **context,
                }
                score = sum(WEIGHTS[k] * v for k, v in signals.items())
                if score > best_score:
                    best_score, best_rec, best_signals, best_len = score, cand, signals, len(c_joined)

        assert best_rec is not None
        cfg = self.config
        short = min(len(joined), best_len) < cfg.min_fuzzy_length
        best_signals = {k: round(v, 3) for k, v in best_signals.items()}
        if best_score >= cfg.merge_threshold and not short:
            return Resolution(Decision.MERGE, best_rec, best_score, signals=best_signals)
        if best_score >= cfg.new_entity_threshold:
            if short:
                best_signals["short_name_guard"] = 1.0
            return Resolution(Decision.DEFERRED, None, best_score, best_rec, best_signals)
        return Resolution(Decision.NEW_ENTITY, None, best_score, signals=best_signals)

    def link_identities(self, registry: SessionRegistry, rec: EntityRecord) -> list[EntityRecord]:
        """Link a PERSON to the EMAIL/USERNAME of the same human (metadata only).

        'Raj Mehta' <-> raj.mehta@corp.com, 'Raj' <-> raj.mehta@corp.com,
        'Raj Mehta' <-> rmehta. Only unambiguous links are recorded.
        """
        if not self.config.link_identities or rec.entity_type not in E.IDENTITY_TYPES:
            return []
        if rec.entity_type == E.PERSON:
            others: Iterable[EntityRecord] = [
                r for r in registry.active() if r.entity_type in (E.EMAIL_ADDRESS, E.USERNAME)
            ]
            matches = [o for o in others if _person_matches(rec, o)]
        else:
            persons = [r for r in registry.active(E.PERSON) if _person_matches(r, rec)]
            matches = persons
        if len(matches) != 1:
            return []
        registry.link(rec, matches[0])
        return matches


def _person_matches(person: EntityRecord, account: EntityRecord) -> bool:
    p_tokens = person.canonical.split()
    a_tokens = identity_tokens(account.entity_type, account.canonical)
    if not p_tokens or not a_tokens:
        return False
    if set(p_tokens) <= a_tokens:
        return True
    if len(p_tokens) >= 2:
        compact = account.canonical.split("@", 1)[0].replace(".", "").replace("_", "")
        first, last = p_tokens[0], p_tokens[-1]
        return compact in (first[0] + last, first + last[0], first + last, last + first[0])
    return False
