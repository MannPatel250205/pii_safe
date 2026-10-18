"""Normalization pre-stage.

1. Unicode NFKC + removal of invisible characters, so homoglyph / zero-width
   tricks (``raj​@corp.com``) cannot hide PII from the regex tier.
2. Discovery of encoded segments (base64, hex, percent-encoding). Each segment
   is decoded (recursively, depth-capped) so the detectors can look inside it.
   Shannon entropy gates which tokens are worth trying to decode.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from urllib.parse import unquote

_INVISIBLE = re.compile("[­᠎​-‏‪-‮⁠-⁤﻿]")

_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_HEX_TOKEN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_PCT_TOKEN = re.compile(r"(?:[A-Za-z0-9._~+-]*%[0-9A-Fa-f]{2})+[A-Za-z0-9._~+-]*")

MAX_DECODE_DEPTH = 3
_MIN_B64_ENTROPY = 3.0


@dataclass(slots=True)
class EncodedSegment:
    start: int
    end: int
    decoded: str
    encoding: str


def normalize_text(text: str) -> str:
    if text.isascii():
        return text
    return _INVISIBLE.sub("", unicodedata.normalize("NFKC", text))


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _printable(s: str) -> bool:
    if not s:
        return False
    good = sum(1 for ch in s if ch.isprintable() or ch in "\t\r\n")
    return good / len(s) >= 0.95


def _try_b64(token: str) -> str | None:
    raw = token.rstrip("=")
    if len(raw) % 4 == 1:
        return None
    padded = raw + "=" * (-len(raw) % 4)
    try:
        urlsafe = "-" in raw or "_" in raw
        data = base64.urlsafe_b64decode(padded) if urlsafe else base64.b64decode(padded, validate=True)
        text = data.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return text if _printable(text) else None


def _try_hex(token: str) -> str | None:
    try:
        text = bytes.fromhex(token).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return text if _printable(text) else None


def find_encoded_segments(text: str) -> list[EncodedSegment]:
    """Return decodable segments of *text* (one level; callers recurse)."""
    out: list[EncodedSegment] = []
    if "%" in text:
        for m in _PCT_TOKEN.finditer(text):
            decoded = unquote(m.group(0))
            if decoded != m.group(0) and _printable(decoded):
                out.append(EncodedSegment(m.start(), m.end(), decoded, "percent"))
    for m in _HEX_TOKEN.finditer(text):
        hexed = _try_hex(m.group(0))
        if hexed:
            out.append(EncodedSegment(m.start(), m.end(), hexed, "hex"))
    for m in _B64_TOKEN.finditer(text):
        token = m.group(0)
        if shannon_entropy(token) < _MIN_B64_ENTROPY:
            continue
        if any(seg.start <= m.start() and m.end() <= seg.end for seg in out):
            continue
        b64 = _try_b64(token)
        if b64:
            out.append(EncodedSegment(m.start(), m.end(), b64, "base64"))
    return out
