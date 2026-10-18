"""Replacement strategies for the non-alias actions."""

from __future__ import annotations

import re

from piisafe import entities as E


def redact(entity_type: str, fmt: str) -> str:
    return fmt.format(type=entity_type)


def mask(entity_type: str, value: str, ch: str = "*") -> str:
    if entity_type == E.EMAIL_ADDRESS and "@" in value:
        local, domain = value.split("@", 1)
        return f"{local[:1]}{ch * 3}@{domain}"
    if entity_type in (E.CREDIT_CARD, E.PHONE_NUMBER, E.US_SSN, E.IBAN_CODE):
        total = sum(c.isalnum() for c in value)
        keep_from = total - 4
        out, seen = [], 0
        for c in value:
            if c.isalnum():
                out.append(c if seen >= keep_from else ch)
                seen += 1
            else:
                out.append(c)
        return "".join(out)
    if entity_type == E.IP_ADDRESS and re.fullmatch(r"[\d.]+", value):
        parts = value.split(".")
        return ".".join(parts[:2] + [ch] * (len(parts) - 2))
    if entity_type == E.SECRET:
        return ch * 8
    return value[:1] + ch * min(max(len(value) - 1, 3), 8)
