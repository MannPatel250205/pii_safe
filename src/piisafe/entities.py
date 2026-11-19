"""Entity type catalogue: canonical names, alias prefixes and sensitivity weights."""

from __future__ import annotations

import re

EMAIL_ADDRESS = "EMAIL_ADDRESS"
IP_ADDRESS = "IP_ADDRESS"
MAC_ADDRESS = "MAC_ADDRESS"
HOSTNAME = "HOSTNAME"
PHONE_NUMBER = "PHONE_NUMBER"
CREDIT_CARD = "CREDIT_CARD"
US_SSN = "US_SSN"
IBAN_CODE = "IBAN_CODE"
SECRET = "SECRET"
USERNAME = "USERNAME"
PERSON = "PERSON"
ORGANIZATION = "ORGANIZATION"
LOCATION = "LOCATION"
DATE_OF_BIRTH = "DATE_OF_BIRTH"
STREET_ADDRESS = "STREET_ADDRESS"
IN_AADHAAR = "IN_AADHAAR"
IN_PAN = "IN_PAN"
PASSPORT_NUMBER = "PASSPORT_NUMBER"
UK_NINO = "UK_NINO"
BANK_ACCOUNT = "BANK_ACCOUNT"
DRIVERS_LICENSE = "DRIVERS_LICENSE"

BUILTIN_TYPES = (
    EMAIL_ADDRESS,
    IP_ADDRESS,
    MAC_ADDRESS,
    HOSTNAME,
    PHONE_NUMBER,
    CREDIT_CARD,
    US_SSN,
    IBAN_CODE,
    SECRET,
    USERNAME,
    PERSON,
    ORGANIZATION,
    LOCATION,
    DATE_OF_BIRTH,
    STREET_ADDRESS,
    IN_AADHAAR,
    IN_PAN,
    PASSPORT_NUMBER,
    UK_NINO,
    BANK_ACCOUNT,
    DRIVERS_LICENSE,
)

# National / government identifiers: treated like US_SSN by the default policy.
GOVERNMENT_IDS = frozenset({US_SSN, IN_AADHAAR, IN_PAN, PASSPORT_NUMBER, UK_NINO, DRIVERS_LICENSE})

# Alias prefixes. Counters are kept per prefix, so several types may share one.
DEFAULT_ALIAS_PREFIX: dict[str, str] = {
    PERSON: "USER",
    USERNAME: "ACCT",
    EMAIL_ADDRESS: "MAIL",
    IP_ADDRESS: "HOST",
    HOSTNAME: "NODE",
    MAC_ADDRESS: "MAC",
    PHONE_NUMBER: "PHONE",
    CREDIT_CARD: "CARD",
    US_SSN: "SSN",
    IBAN_CODE: "IBAN",
    SECRET: "SECRET",
    ORGANIZATION: "ORG",
    LOCATION: "LOC",
    DATE_OF_BIRTH: "DOB",
    STREET_ADDRESS: "ADDR",
    IN_AADHAAR: "AADHAAR",
    IN_PAN: "PAN",
    PASSPORT_NUMBER: "PASSPORT",
    UK_NINO: "NINO",
    BANK_ACCOUNT: "BANKACCT",
    DRIVERS_LICENSE: "DL",
}

# Relative harm if the value leaks; used by the exposure scorer.
SENSITIVITY: dict[str, float] = {
    CREDIT_CARD: 10.0,
    US_SSN: 10.0,
    IN_AADHAAR: 10.0,
    PASSPORT_NUMBER: 9.0,
    UK_NINO: 9.0,
    IN_PAN: 8.0,
    BANK_ACCOUNT: 8.0,
    DRIVERS_LICENSE: 8.0,
    DATE_OF_BIRTH: 7.0,
    STREET_ADDRESS: 6.0,
    SECRET: 9.0,
    IBAN_CODE: 8.0,
    EMAIL_ADDRESS: 6.0,
    PHONE_NUMBER: 6.0,
    PERSON: 5.0,
    USERNAME: 4.0,
    IP_ADDRESS: 3.0,
    LOCATION: 2.0,
    HOSTNAME: 2.0,
    MAC_ADDRESS: 2.0,
    ORGANIZATION: 1.0,
}
DEFAULT_SENSITIVITY = 3.0

# Types whose surface forms vary (typos, nicknames) and get fuzzy entity resolution.
FUZZY_TYPES = frozenset({PERSON, ORGANIZATION, LOCATION})

# Types remembered by the session-memory recogniser so later mentions are caught
# even when NER misses them.
MEMORABLE_TYPES = frozenset({PERSON, ORGANIZATION, LOCATION, USERNAME})

# Types that can be linked to the same real-world identity.
IDENTITY_TYPES = frozenset({PERSON, EMAIL_ADDRESS, USERNAME})

ALIAS_RE = re.compile(r"\b([A-Z][A-Z0-9]*_\d{3,})\b")


def alias_prefix(entity_type: str, overrides: dict[str, str] | None = None) -> str:
    if overrides and entity_type in overrides:
        return overrides[entity_type]
    if entity_type in DEFAULT_ALIAS_PREFIX:
        return DEFAULT_ALIAS_PREFIX[entity_type]
    cleaned = re.sub(r"[^A-Z0-9]", "", entity_type.upper())
    return (cleaned or "ENTITY")[:8]


def sensitivity(entity_type: str, overrides: dict[str, float] | None = None) -> float:
    if overrides and entity_type in overrides:
        return overrides[entity_type]
    return SENSITIVITY.get(entity_type, DEFAULT_SENSITIVITY)
