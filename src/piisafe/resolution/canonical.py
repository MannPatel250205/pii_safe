"""Type-aware canonicalisation (signal 1): format variants collapse to one key."""

from __future__ import annotations

import ipaddress
import re
import unicodedata

from piisafe import entities as E

try:
    import phonenumbers
except ImportError:  # pragma: no cover
    phonenumbers = None  # type: ignore[assignment]

_HONORIFICS = {"mr", "mrs", "ms", "miss", "mx", "dr", "prof", "sir", "madam", "shri", "smt"}
_NON_NAME = re.compile(r"[^\w\s'-]|[\d_]")


def _strip_accents(s: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))


def name_tokens(value: str) -> list[str]:
    s = _NON_NAME.sub(" ", _strip_accents(value).casefold())
    tokens = [t.strip("'-") for t in re.split(r"[\s-]+", s)]
    return [t for t in tokens if t and t not in _HONORIFICS]


def canonicalize(entity_type: str, value: str) -> str:
    v = value.strip()
    if entity_type == E.EMAIL_ADDRESS:
        return v.lower()
    if entity_type == E.IP_ADDRESS:
        try:
            return ipaddress.ip_address(v.split("%")[0]).compressed
        except ValueError:
            return v.lower()
    if entity_type == E.PHONE_NUMBER:
        if v.startswith("+") and phonenumbers is not None:
            try:
                return phonenumbers.format_number(
                    phonenumbers.parse(v, None), phonenumbers.PhoneNumberFormat.E164
                )
            except phonenumbers.NumberParseException:
                pass
        digits = re.sub(r"\D", "", v)
        return ("+" + digits) if v.startswith("+") else digits
    if entity_type in (E.CREDIT_CARD, E.US_SSN):
        return re.sub(r"\D", "", v)
    if entity_type == E.MAC_ADDRESS:
        return re.sub(r"[^0-9a-f]", "", v.lower())
    if entity_type == E.IBAN_CODE:
        return v.replace(" ", "").upper()
    if entity_type in (E.HOSTNAME,):
        return v.lower().rstrip(".")
    if entity_type == E.USERNAME:
        return v.split("\\")[-1].casefold()
    if entity_type in E.FUZZY_TYPES:
        return " ".join(name_tokens(v)) or v.casefold()
    return v


def identity_tokens(entity_type: str, canonical: str) -> set[str]:
    """Tokens used to link a PERSON to an EMAIL/USERNAME of the same human."""
    if entity_type == E.EMAIL_ADDRESS:
        canonical = canonical.split("@", 1)[0]
    parts = re.split(r"[._+\-\s\d]+", canonical.casefold())
    return {p for p in parts if len(p) >= 2}
