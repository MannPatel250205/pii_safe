"""Guards for the evaluation data itself, so the scores keep meaning something."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from piisafe.detection.wordlists import first_names

EVAL = Path(__file__).resolve().parents[2] / "evaluation"
sys.path.insert(0, str(EVAL))
import generate  # noqa: E402


def test_name_pools_split_on_the_first_name_list():
    # Half the generated names must be unknown to first_names.txt, or the list
    # alone could carry the PERSON score.
    assert all(n.lower() in first_names() for n in generate.FIRST_IN_LIST)
    assert not any(n.lower() in first_names() for n in generate.FIRST_NOT_IN_LIST)


def test_synthetic_dataset_is_current_and_labels_are_in_the_text():
    on_disk = (EVAL / "datasets" / "synthetic.jsonl").read_text(encoding="utf-8").splitlines()
    fresh = [json.dumps(r, ensure_ascii=False) for r in generate.generate(len(on_disk))]
    assert on_disk == fresh, "run: python evaluation/generate.py"
    for line in on_disk:
        row = json.loads(line)
        assert all(e["value"] in row["text"] for e in row["entities"])


def test_generated_ids_have_valid_check_digits():
    from piisafe.detection.patterns import iban_valid, luhn_valid, verhoeff_valid

    assert verhoeff_valid(generate.verhoeff_complete("23456789012"))
    assert luhn_valid(generate.luhn_complete("411111111111111"))
    assert iban_valid(generate.iban_complete("DE", "370400440532013000"))
