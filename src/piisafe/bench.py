"""Synthetic security-log generator + latency / detection benchmark.

No Faker dependency: a small seeded generator is enough to exercise every tier
and gives reproducible numbers (`piisafe bench --seed 7`).
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any

from piisafe.guard import PIISafeGuard

_FIRST = ["Raj", "Kavishka", "Priya", "Michael", "Aisha", "Wei", "Carlos", "Fatima", "Olga", "Kenji"]
_LAST = ["Mehta", "Perera", "Sharma", "Johnson", "Khan", "Chen", "Garcia", "Ali", "Ivanova", "Sato"]
_TYPOS = {"Kavishka": "Kavihska", "Michael": "Micheal", "Priya": "Pirya"}
_DOMAINS = ["corp.com", "example.org", "acme.io"]
_VERBS = ["accessed", "logged into", "flagged", "approved", "uploaded", "requested"]
_RESULTS = ["SUCCESS", "FAILED_LOGIN", "DENIED", "TIMEOUT"]


@dataclass(frozen=True)
class Person:
    first: str
    last: str

    @property
    def email(self) -> str:
        return f"{self.first.lower()}.{self.last.lower()}@{_DOMAINS[sum(map(ord, self.last)) % len(_DOMAINS)]}"


def generate(n: int, seed: int = 7) -> list[str]:
    rnd = random.Random(seed)
    people = [Person(f, last) for f, last in zip(_FIRST, _LAST, strict=True)]
    ips = [f"10.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}" for _ in range(8)]
    lines = []
    for i in range(n):
        p = rnd.choice(people)
        ip = rnd.choice(ips)
        ts = f"2024-03-12T{9 + i // 3600 % 12:02d}:{i // 60 % 60:02d}:{i % 60:02d}Z"
        kind = rnd.random()
        if kind < 0.35:
            lines.append(f"{ts} sshd[{rnd.randint(1000, 9999)}]: Failed password for "
                         f"{p.first.lower()}{p.last[0].lower()} from {ip} port 22 ssh2")
        elif kind < 0.6:
            lines.append(f"{ts} auth user={p.email} src_ip={ip} result={rnd.choice(_RESULTS)}")
        elif kind < 0.8:
            name = _TYPOS.get(p.first, p.first) if rnd.random() < 0.2 else p.first
            lines.append(f"{ts} {name} {rnd.choice(_VERBS)} {ip} - ticket INC-{rnd.randint(100, 999)}")
        elif kind < 0.9:
            lines.append(f"{ts} contact {p.first} {p.last} at +1 415-555-{rnd.randint(100, 199):04d}")
        else:
            lines.append(f"{ts} healthcheck ok latency={rnd.randint(1, 90)}ms node=web-{rnd.randint(1, 9)}")
    return lines


def run(n: int = 1000, seed: int = 7, ner: str | None = None) -> dict[str, Any]:
    lines = generate(n, seed)
    raw_t0 = time.perf_counter()
    for line in lines:  # pass-through baseline
        _ = line.encode()
    baseline_ms = (time.perf_counter() - raw_t0) * 1000

    t0 = time.perf_counter()
    guard = PIISafeGuard(session_id=f"bench-{seed}", ephemeral=True, ner=ner)
    init_ms = (time.perf_counter() - t0) * 1000
    tiers: dict[int, int] = {}
    decisions: dict[str, int] = {}
    leaked = 0
    t1 = time.perf_counter()
    outputs = []
    for line in lines:
        r = guard.sanitize(line)
        outputs.append(r.sanitised_text)
        for f in r.findings:
            tiers[f.tier] = tiers.get(f.tier, 0) + 1
            if f.decision:
                decisions[f.decision.value] = decisions.get(f.decision.value, 0) + 1
    total_ms = (time.perf_counter() - t1) * 1000
    # Leak check: no known email / full name should survive.
    people = [Person(f, last) for f, last in zip(_FIRST, _LAST, strict=True)]
    needles = [p.email for p in people] + [f"{p.first} {p.last}" for p in people]
    for out in outputs:
        leaked += sum(1 for s in needles if s in out)
    found = sum(tiers.values())
    return {
        "lines": n,
        "ner_backend": guard.ner.backend if guard.ner else "off",
        "init_ms": round(init_ms, 1),
        "total_ms": round(total_ms, 1),
        "throughput_lines_per_s": round(n / (total_ms / 1000), 1) if total_ms else None,
        "baseline_ms": round(baseline_ms, 3),
        "latency": guard.latency.summary(),
        "findings": found,
        "tier1_hit_rate": round(tiers.get(1, 0) / found, 3) if found else None,
        "by_tier": {f"tier{k}": v for k, v in sorted(tiers.items())},
        "resolution": decisions,
        "known_pii_leaked": leaked,
        "sample": list(zip(lines[:5], outputs[:5], strict=True)),
    }
