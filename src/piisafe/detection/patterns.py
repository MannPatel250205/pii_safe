"""Tier 1 — deterministic pattern recognisers (regex + validators, no models).

Every recogniser is a regex with an optional cheap prefilter and an optional
validator (Luhn, ipaddress, IBAN mod-97, phonenumbers). Overlaps are settled by
priority (lower wins), then by length.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

from piisafe import entities as E
from piisafe.models import Span
from piisafe.normalize import MAX_DECODE_DEPTH, find_encoded_segments

try:  # optional but declared as a dependency
    import phonenumbers
except ImportError:  # pragma: no cover
    phonenumbers = None  # type: ignore[assignment]


@dataclass(frozen=True, slots=True)
class PatternRecognizer:
    name: str
    entity_type: str
    regex: re.Pattern[str]
    score: float
    priority: int
    group: int = 0
    validator: Callable[[str], bool] | None = None
    prefilter: Callable[[str], bool] | None = None

    def find(self, text: str) -> Iterator[Span]:
        if self.prefilter is not None and not self.prefilter(text):
            return
        for m in self.regex.finditer(text):
            start, end = m.span(self.group)
            if start < 0 or start == end:
                continue
            value = text[start:end]
            if self.validator is not None and not self.validator(value):
                continue
            yield Span(
                start, end, value, self.entity_type, self.score, 1, self.name, self.priority
            )


# ---------------------------------------------------------------- validators


def luhn_valid(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19 or digits[0] not in (2, 3, 4, 5, 6):
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def ipv6_valid(value: str) -> bool:
    if value.count(":") < 2 or not any(c.isalnum() for c in value):
        return False
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


def iban_valid(value: str) -> bool:
    s = value.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    try:
        num = int("".join(str(int(c, 36)) for c in rearranged))
    except ValueError:
        return False
    return num % 97 == 1


# ------------------------------------------------------------------ patterns

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_SECRET_KEYS = (
    r"api[_-]?key|apikey|x-api-key|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|"
    r"refresh[_-]?token|token|password|passwd|pass|pwd|private[_-]?key"
)
_USER_KEYS = r"user(?:name)?|login|account|acct|uid|usr|owner|actor|principal|sam_?account_?name"
_INTERNAL_TLDS = r"local|internal|corp|lan|intranet|ad|home|localdomain|priv"


def _has(chars: str) -> Callable[[str], bool]:
    return lambda text: any(c in text for c in chars)


def _digits_at_least(n: int) -> Callable[[str], bool]:
    return lambda text: sum(c.isdigit() for c in text) >= n


BUILTIN_RECOGNIZERS: tuple[PatternRecognizer, ...] = (
    PatternRecognizer(
        "jwt", E.SECRET,
        re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"),
        0.99, 1, prefilter=lambda t: "eyJ" in t,
    ),
    PatternRecognizer(
        "aws_access_key", E.SECRET,
        re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"), 0.99, 1,
    ),
    PatternRecognizer(
        "private_key_header", E.SECRET,
        re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"), 0.99, 1,
        prefilter=lambda t: "PRIVATE KEY" in t,
    ),
    PatternRecognizer(
        "url_password", E.SECRET,
        re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:([^\s@/]+)@"), 0.95, 2, group=1,
        prefilter=_has("@"),
    ),
    PatternRecognizer(
        "url_username", E.USERNAME,
        re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://([^\s:/@]+):[^\s@/]+@"), 0.9, 2, group=1,
        prefilter=_has("@"),
    ),
    PatternRecognizer(
        "bearer_token", E.SECRET,
        re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{8,}=*)"), 0.95, 2, group=1,
    ),
    PatternRecognizer(
        "kv_secret", E.SECRET,
        re.compile(
            rf"(?i)(?<![A-Za-z0-9])(?:{_SECRET_KEYS})[\"']?\s*[:=]\s*[\"']?([^\s\"',;&}}]{{4,}})"
        ),
        0.9, 3, group=1, prefilter=_has(":="),
    ),
    PatternRecognizer(
        "email", E.EMAIL_ADDRESS,
        re.compile(
            r"(?<![\w.+-])[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,63})@"
            r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w-])"
        ),
        0.99, 5, prefilter=_has("@"),
    ),
    PatternRecognizer(
        "ipv4", E.IP_ADDRESS,
        re.compile(rf"(?<![\d.]){_OCTET}(?:\.{_OCTET}){{3}}(?!\.?\d)"),
        0.97, 6, prefilter=_has("."),
    ),
    PatternRecognizer(
        "ipv6", E.IP_ADDRESS,
        re.compile(
            r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{0,4}|"
            r"(?:\d{1,3}\.){3}\d{1,3})(?![\w:])"
        ),
        0.95, 6, validator=ipv6_valid, prefilter=lambda t: t.count(":") >= 2,
    ),
    PatternRecognizer(
        "mac", E.MAC_ADDRESS,
        re.compile(r"(?<![\w:-])(?:[0-9A-Fa-f]{2}([:-]))(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![\w:-])"),
        0.95, 7,
    ),
    PatternRecognizer(
        "credit_card", E.CREDIT_CARD,
        re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])"),
        0.95, 8, validator=luhn_valid, prefilter=_digits_at_least(13),
    ),
    PatternRecognizer(
        "us_ssn", E.US_SSN,
        re.compile(r"(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])"),
        0.85, 9, prefilter=_has("-"),
    ),
    PatternRecognizer(
        "iban", E.IBAN_CODE,
        re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"),
        0.9, 9, validator=iban_valid,
    ),
    PatternRecognizer(
        "windows_account", E.USERNAME,
        re.compile(r"\b[A-Z][A-Z0-9-]{1,15}\\([A-Za-z0-9._-]{2,64})\b"), 0.9, 10, group=1,
        prefilter=_has("\\"),
    ),
    PatternRecognizer(
        "sshd_user", E.USERNAME,
        re.compile(r"(?i)\b(?:for (?:invalid user |illegal user )?|invalid user |illegal user )"
                   r"([A-Za-z0-9._-]{1,64}) from\b"),
        0.9, 10, group=1,
    ),
    PatternRecognizer(
        "kv_user", E.USERNAME,
        re.compile(
            rf"(?i)(?<![A-Za-z0-9_-])(?:{_USER_KEYS})[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9._\\-]{{2,64}})"
        ),
        0.85, 11, group=1, prefilter=_has(":="),
    ),
    PatternRecognizer(
        "internal_hostname", E.HOSTNAME,
        re.compile(
            rf"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{_INTERNAL_TLDS})\b(?![.-]\w)"
        ),
        0.8, 12, prefilter=_has("."),
    ),
)


def resolve_overlaps(spans: Iterable[Span]) -> list[Span]:
    """Keep the strongest non-overlapping spans: lower priority first, then longer."""
    accepted: list[Span] = []
    for s in sorted(spans, key=lambda s: (s.priority, -s.length, s.start)):
        if not any(s.overlaps(a) for a in accepted):
            accepted.append(s)
    accepted.sort(key=lambda s: s.start)
    return accepted


@dataclass(frozen=True, slots=True)
class CustomPattern:
    name: str
    entity_type: str
    regex: str
    score: float = 0.9
    group: int = 0


class Tier1Detector:
    tier = 1

    def __init__(
        self,
        enabled_types: set[str] | None = None,
        custom_patterns: Iterable[CustomPattern] = (),
        phone_regions: Iterable[str] = ("US",),
        decode_encoded: bool = True,
    ) -> None:
        self._recognizers = [
            r for r in BUILTIN_RECOGNIZERS if enabled_types is None or r.entity_type in enabled_types
        ]
        for cp in custom_patterns:
            self._recognizers.append(
                PatternRecognizer(
                    f"custom:{cp.name}", cp.entity_type, re.compile(cp.regex), cp.score, 4,
                    group=cp.group,
                )
            )
        self._phones = (
            phonenumbers is not None
            and (enabled_types is None or E.PHONE_NUMBER in enabled_types)
        )
        self._regions = [r.upper() for r in phone_regions] or ["US"]
        self._decode = decode_encoded
        if self._phones:  # load region metadata now, not on the first hot-path call
            for region in self._regions:
                list(phonenumbers.PhoneNumberMatcher("call 202-555-0143", region))

    def detect(self, text: str) -> list[Span]:
        return resolve_overlaps(self._detect(text, 0))

    def _detect(self, text: str, depth: int) -> list[Span]:
        spans: list[Span] = []
        for rec in self._recognizers:
            spans.extend(rec.find(text))
        if self._phones:
            spans.extend(self._find_phones(text))
        if self._decode and depth < MAX_DECODE_DEPTH:
            spans.extend(self._find_encoded(text, depth))
        return spans

    def _find_phones(self, text: str) -> Iterator[Span]:
        if sum(c.isdigit() for c in text) < 7:
            return
        seen: set[tuple[int, int]] = set()
        for region in self._regions:
            # POSSIBLE finds candidates; then require a valid number, or an
            # explicit +country prefix (test / reserved ranges are still phones).
            matcher = phonenumbers.PhoneNumberMatcher(
                text, region, leniency=phonenumbers.Leniency.POSSIBLE
            )
            for m in matcher:
                if (m.start, m.end) in seen:
                    continue
                if not (m.raw_string.startswith("+") or phonenumbers.is_valid_number(m.number)):
                    continue
                seen.add((m.start, m.end))
                e164 = phonenumbers.format_number(m.number, phonenumbers.PhoneNumberFormat.E164)
                yield Span(m.start, m.end, m.raw_string, E.PHONE_NUMBER, 0.85, 1, "phone", 13, e164)

    def _find_encoded(self, text: str, depth: int) -> Iterator[Span]:
        for seg in find_encoded_segments(text):
            inner = resolve_overlaps(self._detect(seg.decoded, depth + 1))
            if not inner:
                continue
            best = max(inner, key=lambda s: E.sensitivity(s.entity_type))
            yield Span(
                seg.start,
                seg.end,
                text[seg.start:seg.end],
                best.entity_type,
                best.score * 0.95,
                1,
                f"{seg.encoding}>{best.detector}",
                # Ties with a direct match on the same characters go to the direct match.
                best.priority + 1,
                best.resolve_value,
            )
