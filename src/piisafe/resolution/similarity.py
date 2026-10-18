"""String-level similarity signals for entity resolution."""

from __future__ import annotations

import jellyfish


def jaro_winkler(a: str, b: str) -> float:
    return jellyfish.jaro_winkler_similarity(a, b)


def align_tokens(ta: list[str], tb: list[str]) -> list[tuple[str, str]]:
    """Pair each token of the shorter list with its best JW match in the longer."""
    if not ta or not tb:
        return []
    short, long_ = (ta, tb) if len(ta) <= len(tb) else (tb, ta)
    return [(s, max(long_, key=lambda t: jaro_winkler(s, t))) for s in short]


def aligned_jaro_winkler(ta: list[str], tb: list[str]) -> float:
    """Mean best-match JW of the shorter token list against the longer."""
    pairs = align_tokens(ta, tb)
    return sum(jaro_winkler(s, t) for s, t in pairs) / len(pairs) if pairs else 0.0


def aligned_phonetic(ta: list[str], tb: list[str]) -> float:
    """Phonetic agreement per aligned token (joined strings over-penalise long names)."""
    pairs = align_tokens(ta, tb)
    return sum(phonetic_similarity(s, t) for s, t in pairs) / len(pairs) if pairs else 0.0


def edit_similarity(a: str, b: str) -> float:
    d = jellyfish.damerau_levenshtein_distance(a, b)
    return 1.0 - d / max(len(a), len(b), 1)


def typo_shape(a: str, b: str) -> float:
    """How much the difference looks like a keyboard typo rather than a different name.

    Adjacent transposition (Kavishka/Kavihska) is the classic typo -> 1.0.
    Insertion/deletion (Raj/Raju) looks like a nickname or another person -> 0.4.
    """
    if a == b:
        return 1.0
    if len(a) == len(b):
        diffs = [i for i in range(len(a)) if a[i] != b[i]]
        if (
            len(diffs) == 2
            and diffs[1] == diffs[0] + 1
            and a[diffs[0]] == b[diffs[1]]
            and a[diffs[1]] == b[diffs[0]]
        ):
            return 1.0
        if sorted(a) == sorted(b):
            return 0.8
        if len(diffs) == 1:
            return 0.7
        return 0.0
    if abs(len(a) - len(b)) == 1 and jellyfish.levenshtein_distance(a, b) == 1:
        return 0.4
    return 0.0


def phonetic_codes(s: str) -> tuple[str, str, str]:
    s = "".join(ch for ch in s if ch.isalpha()) or s
    return (jellyfish.metaphone(s), jellyfish.soundex(s), jellyfish.nysiis(s))


def phonetic_similarity(a: str, b: str) -> float:
    ca, cb = phonetic_codes(a), phonetic_codes(b)
    return sum(1 for x, y in zip(ca, cb, strict=True) if x and x == y) / len(ca)


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)
