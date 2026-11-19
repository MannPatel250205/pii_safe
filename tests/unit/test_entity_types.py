"""National IDs, bank accounts, dates of birth, addresses and licences (Tier 1)."""

from __future__ import annotations

import pytest

from piisafe import PIISafeGuard
from piisafe.detection.patterns import birth_date_valid, verhoeff_valid


@pytest.fixture
def g():
    guard = PIISafeGuard(session_id="types", ephemeral=True, ner="off")
    yield guard
    guard.close()


def found(guard, text):
    return [(f.entity_type, text[f.start:f.end]) for f in guard.sanitize(text, "on_prompt").findings]


@pytest.mark.parametrize(("text", "etype", "value"), [
    ("aadhaar 2345 6789 0124 verified", "IN_AADHAAR", "2345 6789 0124"),
    ("uid=234567890124", "IN_AADHAAR", "234567890124"),
    ("PAN ABCPE1234F on file", "IN_PAN", "ABCPE1234F"),
    ("NI number AB 12 34 56 C", "UK_NINO", "AB 12 34 56 C"),
    ("nino=AB123456C", "UK_NINO", "AB123456C"),
    ("DOB: 1990-03-12", "DATE_OF_BIRTH", "1990-03-12"),
    ("date of birth 12/03/1990", "DATE_OF_BIRTH", "12/03/1990"),
    ("born on 3 March 1985", "DATE_OF_BIRTH", "3 March 1985"),
    ("birthday: March 3rd, 1985", "DATE_OF_BIRTH", "March 3rd, 1985"),
    ("passport no: K1234567", "PASSPORT_NUMBER", "K1234567"),
    ("Passport # 533380006", "PASSPORT_NUMBER", "533380006"),
    ("a/c no. 123456789012", "BANK_ACCOUNT", "123456789012"),
    ("bank account: 00123456", "BANK_ACCOUNT", "00123456"),
    ("acct # 4402-1187-33", "BANK_ACCOUNT", "4402-1187-33"),
    ("driver's license number MH1420110062821", "DRIVERS_LICENSE", "MH1420110062821"),
    ("DL: D1234-56789", "DRIVERS_LICENSE", "D1234-56789"),
    ("ships to 221B Baker Street, London", "STREET_ADDRESS", "221B Baker Street"),
    ("office at 1600 Pennsylvania Ave NW", "STREET_ADDRESS", "1600 Pennsylvania Ave NW"),
    ("flat at 42 MG Road", "STREET_ADDRESS", "42 MG Road"),
])
def test_detected(g, text, etype, value):
    assert (etype, value) in found(g, text)


@pytest.mark.parametrize("text", [
    "2024-03-12 09:00:01 login ok",          # timestamp without birth context
    "uptime since 12/03/2024",
    "born 2099-01-01",                       # future date
    "dob=31/02/1990",                        # not a real date
    "order 2345 6789 0123 shipped",          # 12 digits, bad Verhoeff check digit
    "id 2222 2222 2222",                     # all-same digits
    "build 20240312 deployed",
    "passport expired yesterday",            # keyword but no number
    "account locked after 5 attempts",
    "DL list updated",
    "ABCDE12345",                            # 4th PAN letter must be an entity code
    "GB123456A ticket",                      # GB is never an NI prefix
    "the 3 Load Balancer Way rollout",       # product words, not a street
    "release 2 on Main",
    "version 1.403.2.0 port 22",
])
def test_not_detected(g, text):
    assert found(g, text) == []


def test_validators():
    assert verhoeff_valid("234567890124") and not verhoeff_valid("234567890123")
    assert birth_date_valid("29/02/2000") and not birth_date_valid("29/02/2001")
    assert birth_date_valid("12/31/1990")  # US month-first


def test_same_id_formatted_differently_gets_one_alias():
    guard = PIISafeGuard(session_id="alias", ephemeral=True, ner="off")
    a = guard.sanitize("x aadhaar 2345 6789 0124", "on_memory_free").sanitised_text
    b = guard.sanitize("y uid=234567890124", "on_memory_free").sanitised_text
    assert a == "x aadhaar AADHAAR_001" and b == "y uid=AADHAAR_001"


def test_default_policy_redacts_ids_and_masks_on_export(g):
    assert g.sanitize("passport no: K1234567").sanitised_text == "passport no: [PASSPORT_NUMBER]"
    assert g.sanitize("DOB: 1990-03-12").sanitised_text == "DOB: DOB_001"
    assert g.sanitize("aadhaar 2345 6789 0124", "export").sanitised_text == "aadhaar [IN_AADHAAR]"
    from piisafe import actions
    assert actions.mask("IN_AADHAAR", "2345 6789 0124") == "**** **** 0124"


def test_field_hints_cover_new_types(g):
    clean, _ = g.sanitize_record({"date_of_birth": "1990-03-12", "address": "Flat 4, Rose Villa", "nino": "AB123456C"})
    assert clean == {"date_of_birth": "DOB_001", "address": "ADDR_001", "nino": "[UK_NINO]"}
