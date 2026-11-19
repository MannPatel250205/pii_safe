"""Person-name precision and recall rules (Tier 2), without depending on spaCy."""

from __future__ import annotations

import pytest

from piisafe.detection.ner import NERDetector, first_names, product_terms
from piisafe.models import Span


def names(guard, text: str) -> list[str]:
    return [text[f.start:f.end] for f in guard.sanitize(text).findings if f.entity_type == "PERSON"]


@pytest.mark.parametrize("text", [
    "Windows Defender updated signatures to version 1.403.2.0",
    "Build 20240312.4 deployed to Production by Jenkins pipeline",
    "Rule ET POLICY Suspicious User-Agent triggered 14 times",
    "Microsoft Teams meeting started by the Security Operations Center",
    "Alert: Possible Brute Force Attack detected on Domain Controller",
    "New York office VPN gateway CPU at 91 percent",
])
def test_products_and_places_are_not_people(heuristic_guard, text):
    assert names(heuristic_guard, text) == []


def test_honorific_beats_product_list(heuristic_guard):
    assert names(heuristic_guard, "call Mr. Jenkins about the invoice") == ["Jenkins"]


def test_possessive_is_stripped_so_aliases_match(heuristic_guard):
    a = heuristic_guard.on_prompt("Kenji Sato's account was locked").sanitised_text
    b = heuristic_guard.on_prompt("Kenji Sato logged in").sanitised_text
    assert a == "USER_001's account was locked" and b == "USER_001 logged in"


def test_names_joined_by_and_or_comma(heuristic_guard):
    assert names(heuristic_guard, "Meeting with John, Sarah and Ali about the breach") == ["John", "Sarah", "Ali"]
    assert names(heuristic_guard, "with John and Brute Force") == ["John"]


@pytest.mark.parametrize(("text", "expected"), [
    ("hi team, carlos garcia will take over the case", ["carlos garcia"]),
    ("ticket for maria lopez closed", ["maria lopez"]),
    ("priya sharma's laptop was quarantined", ["priya sharma"]),
    ("kevin reset the router", ["kevin"]),
    ("the kenji tanaka account", ["kenji"]),  # surname only taken in sentence-like context
])
def test_unseen_lowercase_names(heuristic_guard, text, expected):
    assert names(heuristic_guard, text) == expected


@pytest.mark.parametrize("text", [
    "the christian holiday calendar sync",   # faith word, not a name
    "jordan region failover test passed",    # place
    "please mark the ticket done",           # ambiguous given name
    "backup copied to /home/james/archive",  # path
    "host ws-james-01 rebooted",             # hostname
    "cron: maria.db vacuum done",            # file name
    "error in parse_james()",                # identifier
])
def test_lowercase_rule_leaves_non_names_alone(heuristic_guard, text):
    assert names(heuristic_guard, text) == []


def test_lists_load_and_ambiguous_names_are_excluded():
    assert {"carlos", "kenji", "priya"} <= first_names()
    assert not {"will", "mark", "jordan", "christian"} & first_names()
    assert {"jenkins", "defender", "tomcat"} <= product_terms()


def test_dropped_spacy_label_does_not_hide_rule_match():
    # spaCy tags 'Kenji Sato' as ORG; with PERSON-only output the rule's PERSON must survive.
    class FakeSpacy:
        def detect(self, text):
            yield Span(0, 10, "Kenji Sato", "ORGANIZATION", 0.6, 2, "ner:spacy", priority=33)

    ner = NERDetector("heuristic")
    ner._spacy = FakeSpacy()  # type: ignore[assignment]
    found = ner.detect("Kenji Sato's account was locked")
    assert [(s.text, s.entity_type) for s in found] == [("Kenji Sato", "PERSON")]


class _FakeGliner:
    """Stands in for gliner.GLiNER: same from_pretrained / predict_entities interface."""

    loaded: list[str] = []

    @classmethod
    def from_pretrained(cls, name):
        cls.loaded.append(name)
        return cls()

    def predict_entities(self, text, labels, threshold=0.5):
        assert labels == ["person"] and threshold >= 0.3
        i = text.find("Zuzana Novak")
        out = [{"start": i, "end": i + 12, "text": "Zuzana Novak", "label": "person", "score": 0.91}] if i >= 0 else []
        j = text.find("Jenkins")
        if j >= 0:  # a model false positive the product list must still remove
            out.append({"start": j, "end": j + 7, "text": "Jenkins", "label": "person", "score": 0.6})
        return out


@pytest.fixture
def fake_gliner(monkeypatch):
    import sys
    import types

    monkeypatch.setitem(sys.modules, "gliner", types.SimpleNamespace(GLiNER=_FakeGliner))
    _FakeGliner.loaded.clear()
    return _FakeGliner


def test_gliner_backend_adds_names_and_corroborates_weak_rules(fake_gliner):
    ner = NERDetector("gliner", "some/model")
    assert ner.backend == "gliner+heuristic" and fake_gliner.loaded == ["some/model"]
    found = ner.detect("wire flagged, holder Zuzana Novak; deploy by Jenkins")
    assert [(s.text, s.detector) for s in found] == [("Zuzana Novak", "ner:gliner")]


def test_gliner_mode_from_policy(fake_gliner):
    from piisafe import PIISafeGuard, Policy

    pol = Policy.from_dict({"settings": {"ner": "gliner", "gliner_model": "org/pii-model"}})
    g = PIISafeGuard(pol, ephemeral=True)
    assert g.on_prompt("approved for Zuzana Novak").sanitised_text == "approved for USER_001"
    assert fake_gliner.loaded == ["org/pii-model"]


def test_gliner_missing_fails_loudly(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "gliner", None)  # import raises ImportError
    with pytest.raises(ImportError):
        NERDetector("gliner")
