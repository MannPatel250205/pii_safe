"""Generate evaluation/datasets/synthetic.jsonl: labelled log lines with known PII.

    python evaluation/generate.py            # rewrite the dataset (deterministic)
    python evaluation/generate.py -n 2000    # a bigger one

Every PII value is inserted by a template, so its type and value are known
exactly. About a third of the lines are PII-free decoys (timestamps, versions,
product names, build numbers) that probe for false positives.

What this set is good for: catching regressions across many formats and sources
(the CI recall gate in thresholds.json runs on it). What it is not: real-world
accuracy. The templates were written by the same people as the detectors, so
expect real logs to score lower. Half of the person names are deliberately NOT
in piisafe/data/first_names.txt, so the name list can't carry the score alone.
"""

from __future__ import annotations

import argparse
import json
import random
import string
from collections.abc import Callable
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "datasets" / "synthetic.jsonl"

# Half in the bundled first-name list, half not (checked by tests/unit/test_eval_data.py).
FIRST_IN_LIST = ["Priya", "Carlos", "Kenji", "Aisha", "Olga", "Kwame", "Sofia", "Arjun", "Mei", "Lucas"]
FIRST_NOT_IN_LIST = ["Wairimu", "Eero", "Siiri", "Tavita", "Oyelaran", "Ilse", "Bodhi", "Rangi", "Zuzana", "Ifeoma"]
SURNAMES = ["Sharma", "Garcia", "Sato", "Okafor", "Ivanova", "Mensah", "Rossi", "Nair", "Chen", "Silva",
            "Dlamini", "Virtanen", "Petrova", "Faleolo", "Adeyemi", "Jansen", "Kowalski", "Tane", "Novak", "Eze"]
STREETS = ["Baker Street", "MG Road", "Elm Avenue", "Harbour Lane", "Station Road", "Maple Drive",
           "Kingsway Boulevard", "Linden Court", "Nehru Marg", "Willow Close"]
PRODUCTS = ["Windows Defender", "Jenkins", "CrowdStrike Falcon", "Splunk", "Okta", "Load Balancer",
            "Microsoft Teams", "Palo Alto", "Grafana", "Apache Tomcat"]


# ------------------------------------------------------------ valid IDs


def luhn_complete(prefix: str) -> str:
    digits = [int(c) for c in prefix + "0"]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return prefix + str((10 - total % 10) % 10)


_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
      [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
      [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
      [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
      [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
      [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_complete(prefix: str) -> str:
    c = 0
    for i, d in enumerate(reversed([int(x) for x in prefix])):
        c = _D[c][_P[(i + 1) % 8][d]]
    return prefix + str(_INV[c])


def iban_complete(country: str, bban: str) -> str:
    num = int("".join(str(int(ch, 36)) for ch in bban + country + "00"))
    return f"{country}{98 - num % 97:02d}{bban}"


# ------------------------------------------------------------ value makers

Maker = Callable[[random.Random], tuple[str, str]]


def _name(r: random.Random) -> str:
    first = r.choice(FIRST_IN_LIST if r.random() < 0.5 else FIRST_NOT_IN_LIST)
    return f"{first} {r.choice(SURNAMES)}" if r.random() < 0.7 else first


def _aadhaar(r: random.Random) -> str:
    v = verhoeff_complete(str(r.randint(2, 9)) + "".join(r.choice(string.digits) for _ in range(10)))
    return f"{v[:4]} {v[4:8]} {v[8:]}" if r.random() < 0.6 else v


def _card(r: random.Random) -> str:
    v = luhn_complete(r.choice(["4111", "5500", "4012", "5105"]) + "".join(r.choice(string.digits) for _ in range(11)))
    return " ".join(v[i:i + 4] for i in range(0, 16, 4)) if r.random() < 0.5 else v


MAKERS: dict[str, Maker] = {
    "name": lambda r: (_name(r), "PERSON"),
    "lname": lambda r: (f"{r.choice(FIRST_IN_LIST)} {r.choice(SURNAMES)}".lower(), "PERSON"),
    "email": lambda r: (f"{r.choice(FIRST_IN_LIST + FIRST_NOT_IN_LIST).lower()}.{r.choice(SURNAMES).lower()}"
                        f"@{r.choice(['corp.example', 'bank.example', 'acme.io'])}", "EMAIL_ADDRESS"),
    "ip": lambda r: (".".join(str(x) for x in (r.choice([10, 172, 192, 203]), r.randint(0, 255),
                                               r.randint(0, 255), r.randint(1, 254))), "IP_ADDRESS"),
    "user": lambda r: (r.choice(FIRST_IN_LIST + FIRST_NOT_IN_LIST)[0].lower() + r.choice(SURNAMES).lower(),
                       "USERNAME"),
    "phone": lambda r: (r.choice([f"+44 20 7946 0{r.randint(100, 999)}",
                                  f"+91 98765 {r.randint(10000, 99999)}",
                                  f"+1 415-555-0{r.randint(100, 199)}"]), "PHONE_NUMBER"),
    "card": lambda r: (_card(r), "CREDIT_CARD"),
    "ssn": lambda r: (f"{r.randint(100, 665)}-{r.randint(10, 99)}-{r.randint(1000, 9999)}", "US_SSN"),
    "iban": lambda r: (iban_complete("DE", "".join(r.choice(string.digits) for _ in range(18))), "IBAN_CODE"),
    "mac": lambda r: (":".join(f"{r.randint(0, 255):02X}" for _ in range(6)), "MAC_ADDRESS"),
    "host": lambda r: (f"{r.choice(['ws', 'srv', 'db', 'dc'])}-{r.randint(1, 99):02d}."
                       f"{r.choice(['corp', 'local', 'internal'])}", "HOSTNAME"),
    "aadhaar": lambda r: (_aadhaar(r), "IN_AADHAAR"),
    "pan": lambda r: ("".join(r.choice(string.ascii_uppercase) for _ in range(3)) + r.choice("PCHF")
                      + r.choice(string.ascii_uppercase) + f"{r.randint(1000, 9999)}"
                      + r.choice(string.ascii_uppercase), "IN_PAN"),
    "passport": lambda r: (r.choice(string.ascii_uppercase) + f"{r.randint(1000000, 9999999)}", "PASSPORT_NUMBER"),
    "nino": lambda r: (r.choice(["AB", "CE", "JH", "PR", "WT"]) + f"{r.randint(100000, 999999)}" + r.choice("ABCD"),
                       "UK_NINO"),
    "dob": lambda r: (r.choice([f"{r.randint(1950, 2004)}-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}",
                                f"{r.randint(1, 28):02d}/{r.randint(1, 12):02d}/{r.randint(1950, 2004)}",
                                f"{r.randint(1, 28)} {r.choice(['March', 'July', 'October'])} "
                                f"{r.randint(1950, 2004)}"]),
                      "DATE_OF_BIRTH"),
    "addr": lambda r: (f"{r.randint(1, 999)}{r.choice(['', 'B'])} {r.choice(STREETS)}", "STREET_ADDRESS"),
    "bank": lambda r: (f"{r.randint(10000000, 99999999)}{r.randint(1000, 9999)}", "BANK_ACCOUNT"),
    "dl": lambda r: (f"{r.choice(['MH', 'KA', 'D'])}{r.randint(10, 99)}{r.randint(10000000000, 99999999999)}",
                     "DRIVERS_LICENSE"),
}

# Templates by source. {x} is a PII slot; [product], [n], [ts] are PII-free fillers.
TEMPLATES: dict[str, list[str]] = {
    "sshd": [
        "[ts] gw01 sshd[[n]]: Failed password for invalid user {user} from {ip} port [n] ssh2",
        "[ts] gw01 sshd[[n]]: Accepted publickey for {user} from {ip} port [n] ssh2",
        "[ts] bastion sshd[[n]]: Invalid user {user} from {ip}",
    ],
    "windows": [
        "EventID=4624 Logon Type 10 Account Name: {user} Source Network Address: {ip} Workstation: {host}",
        "EventID=4740 lockout account={user} caller={host}",
        "CORP\\{user} logged on to {host} (MAC {mac})",
    ],
    "web": [
        "{ip} - - [[ts]] \"GET /api/v1/orders?email={email} HTTP/1.1\" 200 [n]",
        "{ip} - - [[ts]] \"POST /login HTTP/1.1\" 401 [n] user={user}",
    ],
    "siem": [
        "ALERT [n]: {name} downloaded [n] files from {host} to {ip}",
        "Possible data exfiltration by {name} ({email}) to {ip}",
        "DLP match: card {card} sent by {email}",
        "DLP match: aadhaar {aadhaar} found in upload by {user}",
        "DLP match: SSN {ssn} in attachment from {email}",
        "Wire to IBAN {iban} flagged for {name}",
    ],
    "helpdesk": [
        "Ticket [n]: {name} reported a phishing email, call back on {phone}",
        "Ticket [n]: hi team, {lname} will take over the case",
        "Ticket [n]: KYC for {name}: PAN {pan}, DOB: {dob}",
        "Ticket [n]: update address for {name} to {addr}",
        "Ticket [n]: passport no: {passport} expires soon, holder {name}",
        "Ticket [n]: NI number {nino} mismatch for {email}",
        "Ticket [n]: refund to a/c no. {bank} for {name}",
        "Ticket [n]: driver's license number {dl} uploaded by {user}",
        "Ticket [n]: escalated to {name} and {name}",
        "Ticket [n]: {name}'s laptop was quarantined",
    ],
    "clean": [
        "[ts] [product] updated signatures to version [n].[n].[n]",
        "[ts] build [n] deployed to Production by [product] pipeline",
        "[ts] healthcheck ok node=web-[n] latency=[n]ms",
        "[ts] [product] license renewed for [n] seats",
        "[ts] backup job [n] completed in [n]s on 2024-03-12",
        "Possible Brute Force Attack detected on Domain Controller, [n] attempts",
        "[ts] cron: rotated [n] log files, freed [n] MB",
        "Release [n] notes: fixed [n] bugs in [product] integration",
        "[ts] account locked after [n] attempts, passport service restarted",
        "[ts] New York office VPN gateway CPU at [n] percent",
    ],
}


def render(template: str, r: random.Random) -> dict:
    text, entities = "", []
    i = 0
    while i < len(template):
        if template.startswith("[ts]", i):
            text += f"2024-03-{r.randint(10, 28)}T{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:00Z"
            i += 4
        elif template.startswith("[n]", i):
            text += str(r.randint(2, 9999))
            i += 3
        elif template.startswith("[product]", i):
            text += r.choice(PRODUCTS)
            i += 9
        elif template[i] == "{":
            j = template.index("}", i)
            value, etype = MAKERS[template[i + 1:j]](r)
            entities.append({"type": etype, "value": value})
            text += value
            i = j + 1
        else:
            text += template[i]
            i += 1
    return {"text": text, "entities": entities}


def generate(n: int, seed: int = 2026) -> list[dict]:
    r = random.Random(seed)
    sources = [s for s in TEMPLATES if s != "clean"]
    rows = []
    for k in range(n):
        source = "clean" if k % 3 == 2 else sources[k % len(sources)]
        row = render(r.choice(TEMPLATES[source]), r)
        row["source"] = source
        rows.append(row)
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=1200)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("-o", "--output", type=Path, default=OUT)
    a = ap.parse_args()
    rows = generate(a.n, a.seed)
    a.output.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    print(f"wrote {len(rows)} lines to {a.output}")


if __name__ == "__main__":
    main()
