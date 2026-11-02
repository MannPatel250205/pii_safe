# Mentor sign-off — Stage 0B

**Status:** ☐ sent ☐ signed off · **Sent on:** Day ___ · **Reply by:** Day 9 (plan's cut-off)

Per the work plan: send by Day 6 at the latest; if there is no reply by Day 9, proceed on the
written assumptions below and note it here.

- **Signed off by:** ___________________ **Date:** ___________
- **Conditions or changes requested:**

---

## What we are asking you to sign off

Three things, in order of how expensive they are to change later.

### 1. The frozen contract — `docs/CONTRACT.md`

The hook signatures, alias format, registry schema, policy schema and audit schema. After this
gate, changing any of them needs both partners to agree, so this is the cheap moment to object.

### 2. Three deliberate divergences from the original proposal

| Proposal said | We built | Why |
|---|---|---|
| Registry stores **SHA-256 only**, "raw PII never stored" | Keyed **HMAC** fingerprints + payload encrypted with a per-session key | The proposal also requires `reidentify()`. You cannot reverse a hash, so the two requirements contradict each other. Encryption satisfies both, and a plain SHA-256 of an IP or a common first name is brute-forceable in seconds anyway. |
| **Double Metaphone** for name matching | metaphone + soundex + NYSIIS, voted per token | `jellyfish` has no Double Metaphone, and DM does not match Kavishka/Kavihska — the project's own worked example. |
| **Presidio** as the fallback for `DEFERRED` | Not used | `DEFERRED` is a *resolution* question ("are these two the same person?"), not a *detection* one. A second detector does not answer it; the human review queue does. |

Full reasoning in `docs/DESIGN.md §5`. **Divergence 1 is the one we most want challenged** — it
is the project's core security claim, and we would rather be corrected now than in Week 11.

### 3. Scope

The plan's v1 scope is intact. Not in v1: image/audio PII, NER fine-tuning, non-English,
HSM/Vault key management, full adversarial hardening of the normalisation stage.

## Where the project stands

Stage 0B's exit test is met: CI is green — ruff clean, strict mypy clean across 44 modules,
97 tests passing (17 skipped are Postgres/AWS, covered by a separate CI job with a real Postgres).

One thing to flag honestly: the repo is **well ahead of the Stage 0B milestone**. The plan expects
a design doc and an empty pytest skeleton at this point; what exists is a largely working SDK —
the three-tier cascade, registry, policy engine, CLI, audit log, framework adapters and a
dashboard. Stages 1–8 are therefore closer to *harden, test and document* than *build from
scratch*. We would like your view on whether to re-cut the remaining stages against reality or
keep the plan's structure and let the schedule run ahead.

## Attached

- `docs/CONTRACT.md` — the frozen contract (one page)
- `docs/DESIGN.md` — full design, measured accuracy, limitations, roadmap
- `docs/handoffs/stage-0b-mann-to-raj.md` — this stage's handoff note
