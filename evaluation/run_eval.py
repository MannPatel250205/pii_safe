"""Detection precision / recall against hand-labelled datasets.

    python evaluation/run_eval.py                         # all datasets, default NER
    python evaluation/run_eval.py --ner heuristic -v      # without spaCy, list errors

A prediction counts as correct when its type matches a gold entity and the two
values overlap (one contains the other). Gold labels mark *what should be
protected*; product names and team names are labelled as not PII.

`heldout.jsonl` was written before the v0.1 precision fixes and never used for
tuning; keep it that way (add new tuning cases to dev.jsonl), or the numbers
stop meaning anything.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from piisafe import PIISafeGuard
from piisafe.normalize import normalize_text

HERE = Path(__file__).resolve().parent


def evaluate(path: Path, guard: PIISafeGuard) -> tuple[Counter, Counter, Counter, list[str]]:
    tp, fp, fn = Counter(), Counter(), Counter()
    errors: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        case = json.loads(raw)
        text = normalize_text(case["text"])
        gold = [(e["type"], e["value"]) for e in case["entities"]]
        pred = [
            (s.entity_type, text[s.start:s.end])
            for s in guard.cascade.detect(text)
            if not guard.policy.is_allowlisted(s.resolve_value, s.resolve_value)
        ]
        for p in pred:
            match = next((g for g in gold if g[0] == p[0] and (g[1] in p[1] or p[1] in g[1])), None)
            if match:
                tp[p[0]] += 1
                gold.remove(match)
            else:
                fp[p[0]] += 1
                errors.append(f"  FP {p[0]:<14} {p[1]!r:28} | {case['text']}")
        for g in gold:
            fn[g[0]] += 1
            errors.append(f"  FN {g[0]:<14} {g[1]!r:28} | {case['text']}")
    return tp, fp, fn, errors


def _row(name: str, tp: int, fp: int, fn: int) -> str:
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return f"  {name:<16} tp={tp:<3} fp={fp:<3} fn={fn:<3} precision={p:.2f} recall={r:.2f}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("datasets", nargs="*", type=Path)
    ap.add_argument("--ner", choices=("auto", "spacy", "heuristic", "off"))
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    guard = PIISafeGuard(ephemeral=True, ner=a.ner)
    print(f"NER backend: {guard.ner.backend if guard.ner else 'off'}")
    for path in a.datasets or sorted((HERE / "datasets").glob("*.jsonl")):
        tp, fp, fn, errors = evaluate(path, guard)
        print(f"\n{path.name}")
        for t in sorted(set(tp) | set(fp) | set(fn)):
            print(_row(t, tp[t], fp[t], fn[t]))
        structured = [t for t in set(tp) | set(fp) | set(fn) if t != "PERSON"]
        print(_row("STRUCTURED", sum(tp[t] for t in structured), sum(fp[t] for t in structured),
                   sum(fn[t] for t in structured)))
        print(_row("OVERALL", sum(tp.values()), sum(fp.values()), sum(fn.values())))
        if a.verbose and errors:
            print("\n".join(errors))


if __name__ == "__main__":
    main()
