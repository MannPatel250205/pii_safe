"""Tier 2 — contextual entities (names, organisations, locations).

spaCy's small model is trained on news/web text and is unreliable on log lines
(it misses "Raj flagged ..." and labels "SUCCESS" as an ORG). So Tier 2 is the
union of:

* log-aware heuristic rules (capitalised name + action verb, cue word + name,
  honorifics) — always on, zero dependencies;
* spaCy ``en_core_web_sm`` when installed — adds recall on prose, filtered
  hard against log junk (ALL_CAPS tokens, underscores, digits).
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from piisafe import entities as E
from piisafe.detection.patterns import resolve_overlaps
from piisafe.models import Span

_NAME = r"[A-Z][a-z\u00e0-\u00f6\u00f8-\u00ff]+(?:[-'][A-Z]?[a-z\u00e0-\u00f6\u00f8-\u00ff]+)*"
_FULL = rf"{_NAME}(?:[ \t]+{_NAME}){{0,2}}"

_VERBS = (
    "accessed|logged|flagged|approved|rejected|failed|attempted|signed|requested|reported|"
    "uploaded|downloaded|deleted|created|modified|updated|sent|received|connected|"
    "disconnected|authenticated|opened|viewed|changed|reset|escalated|said|wrote|called|"
    "emailed|joined|left|submitted|reviewed|edited|exported|imported|ran|executed|"
    "initiated|triggered|granted|revoked|disabled|enabled|added|removed|transferred|"
    "paid|ordered|booked|visited|asked|replied|confirmed|denied|tried|used|accessing"
)
_CUES = (
    "by|to|from|with|cc|contact|assignee|owner|reviewer|approver|employee|analyst|"
    "manager|customer|patient|client|user|dear|hi|hello|thanks|regards|attn|name"
)
_HONORIFIC = r"Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Sir|Madam|Shri|Smt"

# Strong rules carry their own evidence (honorific, name + action verb).
# Weak rules (cue word, any capitalised pair) also fire on product and team
# names, so when spaCy is available they must be corroborated by a spaCy PERSON.
WEAK_RULES = frozenset({"cue_name", "capitalised_pair"})

_RULES: tuple[tuple[re.Pattern[str], float, str], ...] = (
    (re.compile(rf"\b(?:{_HONORIFIC})\.?[ \t]+({_FULL})"), 0.9, "honorific"),
    (
        re.compile(
            rf"\b({_FULL})[ \t]+(?:was[ \t]+|has[ \t]+been[ \t]+|had[ \t]+|is[ \t]+|has[ \t]+)?"
            rf"(?:{_VERBS})\b"
        ),
        0.75,
        "name_verb",
    ),
    (re.compile(rf"(?i:\b(?:{_CUES}))[ \t]*:?[ \t]+({_FULL})\b"), 0.65, "cue_name"),
    (re.compile(rf"\b({_NAME}(?:[ \t]+{_NAME}){{1,2}})\b"), 0.55, "capitalised_pair"),
)

# Capitalised words that are almost never names in logs / prose.
STOPWORDS = frozenset(
    w.lower()
    for w in """
    A An The This That These Those It Its He She They We I You Your Our My His Her Their
    And Or But If Then Else When While For To From By With Without Of On In At As Into
    Is Was Are Were Be Been Has Have Had Do Does Did Not No Yes Ok Okay All Any Some
    User Users Admin Administrator Root System Systems Server Servers Service Services
    Host Hosts Client Clients Account Accounts Session Sessions Request Requests
    Response Error Errors Warning Warn Info Debug Trace Fatal Critical Notice Alert
    Emergency Failed Failure Success Successful Succeeded Login Logon Logout Logoff
    Password Accepted Invalid Denied Connection Connected Disconnected Closed Opened
    Started Stopped Security Network Firewall Policy Rule Event Events Incident Alert
    Alerts Report Log Logs Access Accessed Auth Authentication Authorization Token Key
    Keys File Files Folder Database Table Query Update Updated Delete Deleted Create
    Created Insert Get Post Put Monday Tuesday Wednesday Thursday Friday Saturday Sunday
    January February March April May June July August September October November
    December Jan Feb Mar Apr Jun Jul Aug Sep Sept Oct Nov Dec Today Tomorrow Yesterday
    Mon Tue Wed Thu Fri Sat Sun Team Group Department Office Manager Analyst Engineer
    Support Desk Help Customer Ticket New Old Next Previous First Last Total Status
    State Source Destination Port Protocol Windows Linux Ubuntu Debian Microsoft Google
    Amazon Apple Azure Cloud Internet Web Hello Hi Dear Thanks Thank Regards Please Note
    Subject Re Fwd Attn Mr Mrs Ms Dr Prof Unknown None Null True False Default Local
    Remote Internal External Public Private Agent Bot Model Assistant Chat Message
    Messages Prompt Tool Tools Memory Context Approved Rejected Pending Completed
    Running Blocked Allowed Flagged Escalated Resolved Contact Someone Somebody Everyone
    Production Staging Development Dev Prod Test Testing Build Release Deploy Deployment
    Pipeline Job Jobs Task Tasks Scheduled Backup Restore Patch Upgrade Install Possible
    Suspicious Malicious Potential Attack Threat Detected Detection Domain Controller
    Cluster Node Nodes Pod Container Instance Gateway Proxy Router Switch Endpoint Agent
    Sensor Monitor Monitoring Dashboard Console Portal Center Centre Operations Admins
    Weekly Daily Monthly Hourly Nightly Annual Main Master Primary Secondary Blue Green
    Anyone Nobody Call Email Phone Card Payment Order Invoice
    """.split()  # noqa: SIM905 - readable word list
)


def _trim_stopwords(text: str, start: int) -> tuple[str, int] | None:
    """Strip leading/trailing stopword tokens ('User Raj' -> 'Raj')."""
    tokens = list(re.finditer(r"\S+", text))
    while tokens and tokens[0].group(0).lower() in STOPWORDS:
        tokens.pop(0)
    while tokens and tokens[-1].group(0).lower() in STOPWORDS:
        tokens.pop()
    if not tokens:
        return None
    s, e = tokens[0].start(), tokens[-1].end()
    return text[s:e], start + s


def _plausible_name(text: str) -> bool:
    if len(text) < 2 or any(c.isdigit() or c == "_" for c in text):
        return False
    if text.isupper() and len(text) > 3:
        return False
    return text[0].isupper()


class HeuristicNER:
    name = "heuristic"

    def detect(self, text: str) -> Iterator[Span]:
        for regex, score, rule in _RULES:
            for m in regex.finditer(text):
                trimmed = _trim_stopwords(m.group(1), m.start(1))
                if trimmed is None:
                    continue
                value, start = trimmed
                if not _plausible_name(value):
                    continue
                yield Span(
                    start, start + len(value), value, E.PERSON, score, 2, f"ner:{rule}",
                    priority=30 + int((1 - score) * 10),
                )


_SPACY_LABELS = {
    "PERSON": E.PERSON,
    "ORG": E.ORGANIZATION,
    "GPE": E.LOCATION,
    "LOC": E.LOCATION,
    "FAC": E.LOCATION,
}


class SpacyNER:
    name = "spacy"

    def __init__(self, model: str = "en_core_web_sm") -> None:
        import spacy  # noqa: PLC0415 - optional dependency

        self.model = model
        self._nlp = spacy.load(model, disable=["parser", "lemmatizer", "tagger", "attribute_ruler"])

    def detect(self, text: str) -> Iterator[Span]:
        for ent in self._nlp(text).ents:
            etype = _SPACY_LABELS.get(ent.label_)
            if etype is None:
                continue
            trimmed = _trim_stopwords(ent.text, ent.start_char)
            if trimmed is None:
                continue
            value, start = trimmed
            if not _plausible_name(value) or (value.isupper() and " " not in value):
                continue  # single ALL-CAPS tokens in logs are acronyms (SSN, MAC, SSH)
            score = 0.8 if etype == E.PERSON else 0.6
            yield Span(start, start + len(value), value, etype, score, 2, "ner:spacy", priority=33)


class NERDetector:
    """Tier 2 facade. ``mode``: auto | spacy | heuristic | off."""

    tier = 2

    def __init__(
        self,
        mode: str = "auto",
        model: str = "en_core_web_sm",
        enabled_types: set[str] | None = None,
        min_score: float = 0.5,
        ner_types: set[str] | None = None,
    ) -> None:
        self.mode = mode
        # Entity types NER may emit. Default PERSON only: on logs, spaCy's ORG /
        # LOC labels are mostly product and team names.
        self.ner_types = ner_types if ner_types is not None else {E.PERSON}
        self.min_score = min_score
        self.enabled_types = enabled_types
        self._heuristic = HeuristicNER() if mode != "off" else None
        self._spacy: SpacyNER | None = None
        self.spacy_error: str | None = None
        if mode in ("auto", "spacy"):
            try:
                self._spacy = SpacyNER(model)
            except Exception as exc:  # ImportError, OSError (model missing), ...
                if mode == "spacy":
                    raise
                self.spacy_error = f"{type(exc).__name__}: {exc}"

    @property
    def backend(self) -> str:
        if self._heuristic is None:
            return "off"
        return "spacy+heuristic" if self._spacy else "heuristic"

    def detect(self, masked_text: str) -> list[Span]:
        if self._heuristic is None:
            return []
        heuristic = list(self._heuristic.detect(masked_text))
        if self._spacy is not None:
            from_spacy = list(self._spacy.detect(masked_text))
            persons = [s for s in from_spacy if s.entity_type == E.PERSON]
            heuristic = [
                h for h in heuristic
                if h.detector.removeprefix("ner:") not in WEAK_RULES or any(h.overlaps(p) for p in persons)
            ]
            spans = heuristic + from_spacy
        else:
            spans = heuristic
        return [
            s
            for s in resolve_overlaps(spans)
            if s.score >= self.min_score
            and s.entity_type in self.ner_types
            and (self.enabled_types is None or s.entity_type in self.enabled_types)
        ]
