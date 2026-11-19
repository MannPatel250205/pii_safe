"""Detection precision / recall against hand-labelled datasets.

    python evaluation/run_eval.py                         # all datasets, default NER
    python evaluation/run_eval.py --ner heuristic -v      # without spaCy, list errors
    python evaluation/run_eval.py --gate                  # exit 1 if below thresholds.json (CI)

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
import sys
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


def _scores(tp: int, fp: int, fn: int) -> tuple[float, float]:
    return (tp / (tp + fp) if tp + fp else 1.0), (tp / (tp + fn) if tp + fn else 1.0)


def _row(name: str, tp: int, fp: int, fn: int) -> str:
    p, r = _scores(tp, fp, fn)
    return f"  {name:<16} tp={tp:<3} fp={fp:<3} fn={fn:<3} precision={p:.2f} recall={r:.2f}"


def check_gate(backend: str, results: dict[str, dict[str, tuple[int, int, int]]], path: Path) -> list[str]:
    """Rows of *results* that fall below the floors in *path* for this NER backend."""
    floors = json.loads(path.read_text(encoding="utf-8")).get(backend)
    if floors is None:
        return [f"no thresholds for NER backend '{backend}' in {path.name}"]
    failures = []
    for dataset, rows in floors.items():
        if dataset not in results:
            continue
        for row, need in rows.items():
            p, r = _scores(*results[dataset].get(row, (0, 0, 0)))
            for metric, got in (("precision", p), ("recall", r)):
                if metric in need and got < need[metric] - 1e-9:
                    failures.append(f"{dataset} {row} {metric} {got:.3f} < {need[metric]}")
    return failures


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("datasets", nargs="*", type=Path)
    ap.add_argument("--ner", choices=("auto", "spacy", "gliner", "heuristic", "off"))
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--gate", nargs="?", const=HERE / "thresholds.json", type=Path,
                    help="fail (exit 1) if any score is below the floors in this file (default thresholds.json)")
    a = ap.parse_args()
    guard = PIISafeGuard(ephemeral=True, ner=a.ner)
    backend = guard.ner.backend if guard.ner else "off"
    print(f"NER backend: {backend}")
    results: dict[str, dict[str, tuple[int, int, int]]] = {}
    for path in a.datasets or sorted((HERE / "datasets").glob("*.jsonl")):
        tp, fp, fn, errors = evaluate(path, guard)
        print(f"\n{path.name}")
        rows = {t: (tp[t], fp[t], fn[t]) for t in sorted(set(tp) | set(fp) | set(fn))}
        structured = [t for t in rows if t != "PERSON"]
        rows["STRUCTURED"] = (sum(tp[t] for t in structured), sum(fp[t] for t in structured),
                              sum(fn[t] for t in structured))
        rows["OVERALL"] = (sum(tp.values()), sum(fp.values()), sum(fn.values()))
        for name, counts in rows.items():
            print(_row(name, *counts))
        results[path.name] = rows
        if a.verbose and errors:
            print("\n".join(errors))
    if a.gate:
        failures = check_gate(backend, results, a.gate)
        if failures:
            print("\nGATE FAILED:\n  " + "\n  ".join(failures))
            sys.exit(1)
        print(f"\ngate passed ({a.gate.name}, backend {backend})")


if __name__ == "__main__":
    main()
