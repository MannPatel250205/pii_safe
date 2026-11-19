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
from functools import cache
from importlib import resources

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


@cache
def _word_list(name: str) -> frozenset[str]:
    """A bundled list from piisafe/data: whitespace-separated, '#' comments, case-insensitive."""
    text = resources.files("piisafe").joinpath(f"data/{name}").read_text("utf-8")
    return frozenset(
        w.casefold() for line in text.splitlines() if not line.lstrip().startswith("#") for w in line.split()
    )


def product_terms() -> frozenset[str]:
    return _word_list("product_terms.txt")


def first_names() -> frozenset[str]:
    """Given names, minus those that are also everyday words ('will', 'mark')."""
    return _word_list("first_names.txt") - _word_list("ambiguous_names.txt")


_VERB_SET = frozenset(_VERBS.split("|"))
# Words that can follow a lower-case 'first last' name in a sentence. A surname
# is only taken when one of these (or punctuation / end of text) comes next, so
# 'christian holiday calendar' does not turn 'holiday' into a surname.
_NAME_FOLLOWERS = _VERB_SET | frozenset((
    "will", "would", "has", "have", "had", "is", "was", "are", "were", "can", "could", "should",
    "may", "might", "must", "did", "does", "and", "or", "from", "to", "at", "in", "on", "for",
    "with", "via", "about", "who", "said",
))


def _strip_possessive(text: str) -> str:
    """'Kenji Sato's' -> 'Kenji Sato', 'James'' -> 'James', so the alias matches later bare mentions."""
    if len(text) > 2 and text.endswith(("'s", "’s")):
        return text[:-2]
    if len(text) > 2 and text.endswith(("s'", "s’")):
        return text[:-1]
    return text


def _is_product(text: str) -> bool:
    """True when every word is a product/infra term or a stopword ('Windows Defender', 'Brute Force')."""
    terms, words = product_terms(), text.split()
    if not any(w.casefold() in terms or all(p in terms for p in w.casefold().split("-")) for w in words):
        return False
    return all(
        w.casefold() in terms or w.casefold() in STOPWORDS
        or all(p in terms or p in STOPWORDS for p in w.casefold().split("-"))
        for w in words
    )


def is_known_first_name(token: str) -> bool:
    return token.casefold() in first_names()


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


_LIST_NEXT = re.compile(rf"[ \t]*(?:,|,?[ \t]+(?:and|or|&))[ \t]+({_NAME})\b")

# A lower-case word not glued to a path, host, email or key ('ws-james-01', 'user=james'),
# and a lower-case 'first [last]' name built from such words.
_LOWER_WORD = re.compile(r"(?<![\w@./\\=:-])[a-z]+")
_LOWER_NAME = re.compile(
    r"(?<![\w@./\\=:-])(?P<first>[a-z]{4,})"
    r"(?:[ \t]+(?P<last>[a-z]{3,})(?P<poss>['’]s)?(?![\w@/\\=-]|\.\w))?"
    r"(?![\w@/\\=-]|\.\w)"
)


class HeuristicNER:
    name = "heuristic"

    def detect(self, text: str) -> Iterator[Span]:
        found = list(self._rules(text))
        yield from found
        yield from self._listed_names(text, found)

    def _listed_names(self, text: str, found: list[Span]) -> Iterator[Span]:
        """'with John and Sarah': a name joined by and/or/&/comma to a strong match is a name too."""
        for s in found:
            if s.detector.removeprefix("ner:") in WEAK_RULES and s.detector != "ner:cue_name":
                continue
            end = s.end
            while m := _LIST_NEXT.match(text, end):
                value = m.group(1)
                if value.casefold() in STOPWORDS or _is_product(value) or not _plausible_name(value):
                    break
                yield Span(m.start(1), m.end(1), value, E.PERSON, s.score, 2, "ner:name_list", s.priority)
                end = m.end(1)

    def _rules(self, text: str) -> Iterator[Span]:
        for regex, score, rule in _RULES:
            for m in regex.finditer(text):
                trimmed = _trim_stopwords(m.group(1), m.start(1))
                if trimmed is None:
                    continue
                value, start = trimmed
                value = _strip_possessive(value)
                if not _plausible_name(value):
                    continue
                if rule == "capitalised_pair" and len(value.split()) < 2:
                    continue  # 'New York' trimmed to 'York': the pair was the only evidence
                if rule != "honorific" and _is_product(value):
                    continue  # 'Windows Defender', 'Jenkins', 'Brute Force'
                yield Span(
                    start, start + len(value), value, E.PERSON, score, 2, f"ner:{rule}",
                    priority=30 + int((1 - score) * 10),
                )

    def detect_lowercase(self, text: str) -> Iterator[Span]:
        """Unseen lower-case names ('carlos garcia will take over'): a known first name,
        plus the next word as its surname when the text reads like a sentence after it."""
        names, terms = first_names(), product_terms()
        pos = 0
        for w in _LOWER_WORD.finditer(text):
            if w.start() < pos:
                continue  # already part of the previous name
            m = _LOWER_NAME.match(text, w.start())
            if m is None or m.group("first") not in names:
                continue
            end = m.end("first")
            last = m.group("last")
            if (
                last and last not in STOPWORDS and last not in _NAME_FOLLOWERS and last not in terms
                and not last.endswith(("ed", "ing"))
                and (m.group("poss") or _sentence_follows(text, m.end()))
            ):
                end = m.end("last")
            pos = end
            yield Span(m.start(), end, text[m.start():end], E.PERSON, 0.6, 2, "ner:lower_first_name", priority=34)


def _sentence_follows(text: str, pos: int) -> bool:
    """End of text, punctuation, or a verb / auxiliary / preposition comes next."""
    rest = text[pos:].lstrip(" \t")
    if not rest or not rest[0].isalnum():
        return True
    word = re.match(r"[a-z]+", rest)
    return word is not None and (word.group(0) in _NAME_FOLLOWERS or word.group(0).endswith(("ed", "ing")))


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
            value = _strip_possessive(value)
            if not _plausible_name(value) or (value.isupper() and " " not in value):
                continue  # single ALL-CAPS tokens in logs are acronyms (SSN, MAC, SSH)
            if _is_product(value):
                continue
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

    def detect(self, masked_text: str, *, full: bool = True) -> list[Span]:
        """``full=False`` runs only the cheap lower-case name check (lines with no capitals)."""
        if self._heuristic is None:
            return []
        lower = list(self._heuristic.detect_lowercase(masked_text))
        if not full:
            spans = lower
        elif self._spacy is not None:
            heuristic = list(self._heuristic.detect(masked_text))
            from_spacy = list(self._spacy.detect(masked_text))
            persons = [s for s in from_spacy if s.entity_type == E.PERSON]
            # A weak rule needs corroboration: a spaCy PERSON, or a known first name.
            heuristic = [
                h for h in heuristic
                if h.detector.removeprefix("ner:") not in WEAK_RULES
                or any(h.overlaps(p) for p in persons)
                or is_known_first_name(h.text.split()[0])
            ]
            spans = heuristic + from_spacy + lower
        else:
            spans = list(self._heuristic.detect(masked_text)) + lower
        # Filter before resolving overlaps: a dropped spaCy ORG must not knock out
        # the PERSON a rule found on the same words ('Kenji Sato's account').
        return resolve_overlaps([
            s
            for s in spans
            if s.score >= self.min_score
            and s.entity_type in self.ner_types
            and (self.enabled_types is None or s.entity_type in self.enabled_types)
        ])
