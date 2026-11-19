"""Identity-resolution accuracy on labelled name pairs (Tier 3).

    python evaluation/run_resolution_eval.py           # current thresholds
    python evaluation/run_resolution_eval.py -v        # list every wrong call
    python evaluation/run_resolution_eval.py --sweep   # try other merge/new-entity thresholds
    python evaluation/run_resolution_eval.py --gate    # exit 1 if worse than thresholds.json (CI)

Each pair is run through the real pseudonymise step: name A is seen first, then
name B in a later turn. Two settings:

* isolated: A is the only other person in the session, so the "pool" and
  "recency" signals help;
* crowded: three unrelated people are mentioned between A and B, so they don't.

What counts:
* same-person pairs should MERGE (one alias). A split or a review-queue entry
  is safe but loses analytical value.
* different-person pairs must not MERGE. A wrong merge attributes one person's
  actions to another, which is the costly error. --gate fails if wrong merges
  rise, or same-person merging falls, past the baseline in thresholds.json.

The pairs were written by the author of the resolver; treat the numbers as a
regression check, not proof of real-world accuracy.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from piisafe import PIISafeGuard, Policy
from piisafe import entities as E
from piisafe.models import Action, Decision, Span
from piisafe.normalize import normalize_text
from piisafe.resolution import canonicalize

HERE = Path(__file__).resolve().parent
PAIRS = HERE / "datasets" / "resolution" / "pairs.jsonl"
DISTRACTORS = ("Hiroshi Watanabe", "Ingrid Solberg", "Tobias Engel")


@dataclass(frozen=True, slots=True)
class Outcome:
    kind: str
    same: bool
    merged: bool
    deferred: bool
    a: str
    b: str
    score: float | None


def _see(guard: PIISafeGuard, name: str):  # noqa: ANN202
    name = normalize_text(name)
    span = Span(0, len(name), name, E.PERSON, 0.9, 2, "eval")
    with guard.turn():
        return guard._apply(span, canonicalize(E.PERSON, name), Action.PSEUDONYMISE, None)


def run_pair(pair: dict, policy: Policy, crowded: bool) -> Outcome:
    guard = PIISafeGuard(policy, "res-eval", ephemeral=True, ner="off")
    try:
        first = _see(guard, pair["a"])
        if crowded:
            for d in DISTRACTORS:
                _see(guard, d)
        second = _see(guard, pair["b"])
    finally:
        guard.close()
    return Outcome(pair["kind"], pair["same"], second.alias == first.alias,
                   second.decision is Decision.DEFERRED, pair["a"], pair["b"], second.resolution_score)


def evaluate(pairs: list[dict], merge: float | None = None, new: float | None = None) -> dict[str, list[Outcome]]:
    policy = Policy.default()
    if merge is not None:
        policy.resolution.merge_threshold = merge
    if new is not None:
        policy.resolution.new_entity_threshold = new
    return {mode: [run_pair(p, policy, mode == "crowded") for p in pairs] for mode in ("isolated", "crowded")}


def summary(outcomes: list[Outcome]) -> dict[str, float | int]:
    same = [o for o in outcomes if o.same]
    diff = [o for o in outcomes if not o.same]
    merged = [o for o in outcomes if o.merged]
    return {
        "same_merged": sum(o.merged for o in same) / len(same),
        "same_deferred": sum(o.deferred for o in same) / len(same),
        "wrong_merges": sum(o.merged for o in diff),
        "diff_deferred": sum(o.deferred for o in diff) / len(diff),
        "merge_precision": (sum(o.same for o in merged) / len(merged)) if merged else 1.0,
    }


def _print(results: dict[str, list[Outcome]], verbose: bool) -> None:
    for mode, outs in results.items():
        s = summary(outs)
        print(f"\n{mode}: same-person merged {s['same_merged']:.0%} (to review {s['same_deferred']:.0%}) · "
              f"wrong merges {s['wrong_merges']} · different people sent to review {s['diff_deferred']:.0%} · "
              f"merge precision {s['merge_precision']:.2f}")
        by_kind: dict[str, Counter] = {}
        for o in outs:
            c = by_kind.setdefault(o.kind, Counter())
            c["n"] += 1
            c["ok"] += o.merged == o.same
        print("  " + " · ".join(f"{k} {c['ok']}/{c['n']}" for k, c in sorted(by_kind.items())))
        if verbose:
            for o in outs:
                if o.merged != o.same:
                    what = "WRONG MERGE" if o.merged else ("to review" if o.deferred else "split")
                    score = None if o.score is None else round(o.score, 3)
                    print(f"    {what:<11} {o.a!r} / {o.b!r}  score={score}")


def sweep(pairs: list[dict]) -> None:
    print("\nmerge  new   | isolated: merged wrong | crowded: merged wrong")
    best = None
    for m in [x / 100 for x in range(70, 92, 2)]:
        for n in [x / 100 for x in range(55, 80, 5)]:
            if n > m:
                continue
            r = evaluate(pairs, m, n)
            iso, crw = summary(r["isolated"]), summary(r["crowded"])
            mark = ""
            if iso["wrong_merges"] == crw["wrong_merges"] == 0:
                key = (iso["same_merged"] + crw["same_merged"], -abs(m - 0.80))
                if best is None or key > best[0]:
                    best = (key, m, n)
                mark = "  ok"
            print(f"{m:.2f}  {n:.2f}  | {iso['same_merged']:>15.0%} {iso['wrong_merges']:>5} |"
                  f" {crw['same_merged']:>14.0%} {crw['wrong_merges']:>5}{mark}")
    if best:
        print(f"\nhighest same-person merge rate with zero wrong merges: merge={best[1]:.2f} new={best[2]:.2f}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--gate", action="store_true", help="exit 1 if worse than the baseline in thresholds.json")
    a = ap.parse_args()
    pairs = [json.loads(line) for line in PAIRS.read_text(encoding="utf-8").splitlines() if line.strip()]
    cfg = Policy.default().resolution
    print(f"{len(pairs)} pairs ({sum(p['same'] for p in pairs)} same person) · "
          f"merge_threshold={cfg.merge_threshold} new_entity_threshold={cfg.new_entity_threshold}")
    results = evaluate(pairs)
    _print(results, a.verbose)
    if a.sweep:
        sweep(pairs)
    if a.gate:
        floors = json.loads((HERE / "thresholds.json").read_text(encoding="utf-8"))["resolution"]
        failures = []
        for mode, outs in results.items():
            s, need = summary(outs), floors[mode]
            if s["wrong_merges"] > need["max_wrong_merges"]:
                failures.append(f"{mode}: {s['wrong_merges']} wrong merges > {need['max_wrong_merges']}")
            if s["same_merged"] < need["min_same_merged"]:
                failures.append(f"{mode}: same-person merged {s['same_merged']:.2f} < {need['min_same_merged']}")
        if failures:
            print("\nGATE FAILED:\n  " + "\n  ".join(failures))
            sys.exit(1)
        print("\ngate passed (thresholds.json resolution baseline)")


if __name__ == "__main__":
    main()
