from __future__ import annotations

import base64
import time

import pytest

from piisafe.detection.patterns import Tier1Detector, luhn_valid


@pytest.fixture(scope="module")
def t1() -> Tier1Detector:
    return Tier1Detector(phone_regions=["US", "IN"])


def types(t1: Tier1Detector, text: str) -> list[tuple[str, str]]:
    return [(s.entity_type, s.text) for s in t1.detect(text)]


@pytest.mark.parametrize(
    "text,etype,value",
    [
        ("mail raj.mehta@corp.com now", "EMAIL_ADDRESS", "raj.mehta@corp.com"),
        ("to: A.B+tag@sub.example.co.uk.", "EMAIL_ADDRESS", "A.B+tag@sub.example.co.uk"),
        ("from 192.168.1.45:443", "IP_ADDRESS", "192.168.1.45"),
        ("via 2001:db8::8a2e:370:7334 ok", "IP_ADDRESS", "2001:db8::8a2e:370:7334"),
        ("mac 00:1A:2B:3C:4D:5E", "MAC_ADDRESS", "00:1A:2B:3C:4D:5E"),
        ("card 4111 1111 1111 1111", "CREDIT_CARD", "4111 1111 1111 1111"),
        ("ssn 123-45-6789", "US_SSN", "123-45-6789"),
        ("iban GB82 WEST 1234 5698 7654 32", "IBAN_CODE", "GB82 WEST 1234 5698 7654 32"),
        ("call +1 415-555-0132", "PHONE_NUMBER", "+1 415-555-0132"),
        ("call +91 98765 43210", "PHONE_NUMBER", "+91 98765 43210"),
        ("key AKIAIOSFODNN7EXAMPLE", "SECRET", "AKIAIOSFODNN7EXAMPLE"),
        ("password=hunter2!", "SECRET", "hunter2!"),
        ("Authorization: Bearer abcdef123456789", "SECRET", "abcdef123456789"),
        ("Failed password for invalid user oracle from 10.0.0.1", "USERNAME", "oracle"),
        ("CORP\\jsmith logged on", "USERNAME", "jsmith"),
        ("sshd[811]: Invalid user deploy from 203.0.113.77 port 40122", "USERNAME", "deploy"),
        ("user=kperera action=login", "USERNAME", "kperera"),
        ("host ws-042.corp.local up", "HOSTNAME", "ws-042.corp.local"),
    ],
)
def test_positive(t1, text, etype, value):
    assert (etype, value) in types(t1, text)


@pytest.mark.parametrize(
    "text",
    [
        "version 1.2.3.4.5 released",
        "2024-03-12 09:00:12 heartbeat",
        "order 1234567890123 shipped",  # 13 digits, fails Luhn / prefix
        "999.1.1.1 is not an ip",
        "ratio 3:4:5 and time 10:20:30",
        "public site www.example.com is fine",
    ],
)
def test_negative(t1, text):
    assert types(t1, text) == []


def test_luhn():
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")
    assert not luhn_valid("0000000000000000")


def test_overlap_prefers_email_over_username(t1):
    assert types(t1, "user=raj.mehta@corp.com") == [("EMAIL_ADDRESS", "raj.mehta@corp.com")]


def test_encoded_email_is_found_and_resolves_to_inner_value(t1):
    blob = base64.b64encode(b"raj.mehta@corp.com").decode()
    spans = t1.detect(f"payload={blob}")
    assert len(spans) == 1
    assert spans[0].entity_type == "EMAIL_ADDRESS"
    assert spans[0].text == blob
    assert spans[0].resolve_value == "raj.mehta@corp.com"


def test_percent_encoded_email(t1):
    spans = t1.detect("GET /?email=bob%40corp.com&x=1")
    assert [(s.entity_type, s.resolve_value) for s in spans] == [("EMAIL_ADDRESS", "bob@corp.com")]


def test_custom_pattern():
    from piisafe.detection.patterns import CustomPattern

    t = Tier1Detector(custom_patterns=[CustomPattern("emp", "EMPLOYEE_ID", r"\bEMP-\d{5}\b")])
    assert [(s.entity_type, s.text) for s in t.detect("badge EMP-00421")] == [("EMPLOYEE_ID", "EMP-00421")]


def test_tier1_latency(t1):
    line = "2024-03-12 09:00 raj.mehta@corp.com accessed 192.168.1.45 — FAILED_LOGIN"
    for _ in range(50):
        t1.detect(line)
    samples = []
    for _ in range(500):
        t0 = time.perf_counter()
        t1.detect(line)
        samples.append(time.perf_counter() - t0)
    samples.sort()
    assert samples[len(samples) // 2] < 0.002  # median < 2 ms even on slow CI
