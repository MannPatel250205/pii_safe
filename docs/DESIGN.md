# PII-Safe: design and roadmap

This document explains how PII-Safe works, why it is built this way, how accurate it is today, and what comes next. Read it before changing the code. For installation and CLI usage, see the [README](../README.md).

---

## 1. The problem in one paragraph

AI agents forward raw operational data (logs, tickets, tool parameters) to cloud LLMs. Redacting everything to `[REDACTED]` protects privacy but breaks the agent's reasoning: it can no longer tell whether two log lines involve the same person. PII-Safe replaces each real-world entity with a **stable, typed alias**:
- `raj.mehta@corp.com` → `MAIL_001`
- `Raj` → `USER_001`
- `192.168.1.45` → `HOST_001`

Aliases stay consistent across a whole session, even through typos ("Kavihska") and format variants ("RAJ.MEHTA@CORP.COM"). The originals are kept encrypted, so an authorised person can restore them later.

---

## 2. The pipeline at a glance

Every entry point (CLI `sanitize`, `on_prompt`, `on_tool_call`, …) runs the same pipeline on each piece of text:

```
 input text
    │
    ▼
 ┌──────────────────────────┐
 │ 1. Normalise             │  NFKC, strip zero-width chars; find base64 / hex / %-encoded tokens
 └────────────┬─────────────┘
              ▼
 ┌──────────────────────────┐
 │ 2. Detect (cascade)      │  Tier 1 regex+validators ─► session memory ─► Tier 2 names
 │    → list of Spans       │  (each tier only sees characters earlier tiers did not claim)
 └────────────┬─────────────┘
              ▼
 ┌──────────────────────────┐
 │ 3. Allowlist             │  drop 127.0.0.1, root, … (policy.allowlist)
 └────────────┬─────────────┘
              ▼
 ┌──────────────────────────┐
 │ 4. Policy                │  (entity type, hook, policy_id) → allow | pseudonymise | redact | mask | block
 └────────────┬─────────────┘    block → PolicyBlockError *before* anything is stored
              ▼
 ┌──────────────────────────┐
 │ 5. Resolve (Tier 3)      │  pseudonymise only: EXACT / MERGE / DEFERRED / NEW_ENTITY
 └────────────┬─────────────┘
              ▼
 ┌──────────────────────────┐
 │ 6. Registry + audit      │  alias assigned; encrypted payload; keyed-hash audit row
 └────────────┬─────────────┘
              ▼
 sanitised text + SanitiseResult (findings, risk score, audit id)
```

### Walkthrough: one log line

Input, in session `INC-001`, where earlier lines already contained `raj.mehta@corp.com` and "Raj":

```
2024-03-12 09:07 Raju accessed 192.168.1.67 — SUCCESS
```

1. **Normalise:** the line is plain ASCII, so it passes through unchanged.
2. **Tier 1:** the `ipv4` recogniser matches `192.168.1.67` (score 0.97). That span is now masked.
3. **Session memory:** no previously seen name matches.
4. **Tier 2:** a capitalised word remains, so NER runs. The `name_verb` rule matches "Raju accessed" → PERSON `Raju`.
5. **Policy:** the hook is `on_prompt`, so the `internal_analysis` policy applies. Both entities are pseudonymised.
6. **Resolve:** types with exact identities are resolved first.
   - The IP is new → `HOST_002`.
   - "raju" is then scored against the known person "raj". Jaro-Winkler 0.94, phonetics agree, typo shape = insertion (0.4); the combined score is 0.74.
   - Because "raj" is shorter than 5 letters, the short-name guard forbids a merge. The decision is **DEFERRED**: a new alias `USER_002`, with candidate `USER_001` written to the audit log.
7. **Output:** `2024-03-12 09:07 USER_002 accessed HOST_002 — SUCCESS`.

---

## 3. Components

### 3.1 Façade: `guard.py` (`PIISafeGuard`)

`PIISafeGuard` is the only object users touch. It owns:
- the policy;
- the detection cascade;
- the session registry;
- the resolver;
- the store;
- the hook registry.

| Method | Purpose |
|---|---|
| `sanitize(text, hook)` | The core pipeline |
| `sanitize_record(obj, hook)` | JSON-like data; field names act as type hints |
| `on_prompt`, `on_context`, `on_tool_call`, `on_memory`, `on_export` | The hook entry points |
| `restore`, `reidentify`, `merge` | Re-identification and review |
| `turn()` | Context manager: groups calls into one *turn* (one log line, one record, one RAG injection). Co-occurrence is measured per turn. |

**Hooks (`hooks.py`)** are an observer registry: name → handler. Adding `on_tool_result` takes one `guard.hooks.register(...)` call, with no change to the pipeline.

### 3.2 Normalisation: `normalize.py`

**Unicode.** NFKC normalisation plus removal of zero-width and bidi characters. This stops `raj​.mehta@corp.com` from slipping past the regex tier. The fast path skips ASCII text entirely.

**Encoded tokens.** Tokens that look like base64 (and pass a Shannon-entropy check), hex, or percent-encoding are decoded. The decoded text is scanned again, recursively, up to 3 levels deep. If PII is found inside:
- the whole encoded token becomes the span;
- the inner value is used for resolution.

So `cmFqLm1laHRhQGNvcnAuY29t` gets the **same** alias as `raj.mehta@corp.com`.

### 3.3 Detection: `detection/`

Every detector returns `Span(start, end, text, entity_type, score, tier, detector, priority, value)`.

**Overlaps.** `resolve_overlaps` keeps the strongest non-overlapping spans: lowest `priority` first, then the longest. Priorities encode trust:
- secrets (1–3);
- email (5);
- IP (6) … usernames (10–11);
- encoded spans: inner priority + 1;
- session memory (20);
- NER (30+).

**Tier 1, `patterns.py`.** Regex recognisers, each optionally with a cheap prefilter (e.g. "contains `@`") and a validator:

| Type | Detection | Validation |
|---|---|---|
| EMAIL_ADDRESS | RFC-ish regex | — |
| IP_ADDRESS | IPv4 regex; IPv6 candidates | `ipaddress` module |
| MAC_ADDRESS | 6 hex pairs with a consistent separator | — |
| CREDIT_CARD | 13–19 digits | Luhn + issuer prefix (2–6) |
| US_SSN | dashed form | excludes the invalid 000 / 666 / 9xx blocks |
| IBAN_CODE | country + check digits | mod-97 |
| PHONE_NUMBER | Google `phonenumbers` matcher over `settings.phone_regions` | valid number, or explicit `+country` |
| SECRET | JWT, AWS keys, `Bearer …`, `password=…` / `token: …`, URL passwords, PEM headers | — |
| USERNAME | sshd formats (`for X from`, `Invalid user X from`), `DOMAIN\user`, `user=` / `login:` keys, URL user | — |
| HOSTNAME | FQDNs on internal TLDs (`.local`, `.corp`, `.internal`, `.lan`, …) | — |
| IN_AADHAAR | 12 digits, first 2–9, optional 4-4-4 grouping | Verhoeff check digit; all-same digits rejected |
| IN_PAN | `AAAPA9999A` | 4th letter must be a valid holder-type code |
| UK_NINO | two letters, six digits, A–D | never-issued prefixes (BG, GB, NK, KN, NT, TN, ZZ) excluded |
| PASSPORT_NUMBER | 6–9 alphanumerics after `passport (no / number / #)` | at least 4 digits |
| DRIVERS_LICENSE | after `driver's / driving licence` or `DL no / DL:` | at least 4 digits |
| BANK_ACCOUNT | 6–18 digits after `a/c no`, `account number`, `bank account` | — |
| DATE_OF_BIRTH | a date after `DOB`, `date of birth`, `born (on)`, `birthday` | a real date, 1900–today |
| STREET_ADDRESS | house number + 1–4 capitalised words + a street suffix | the words can't all be product terms |
| custom | regexes from `policy.custom_patterns`, e.g. `EMP-\d+` | — |

Keyword-backed types (passport, licence, bank account, date of birth) have priority 7, so they beat checksum-only matches (card, Aadhaar: 8) on the same digits. Phone matches right after `version`, `v`, `build`, `release` or `rev` are dropped (`version 149.962.2887`).

**Session memory, `memory.py`.** Every name-like value (PERSON, USERNAME, …) that the session has seen is compiled into a single regex. Later mentions are caught deterministically, including lowercase ones for names of 6+ letters ("kavishka").

**Tier 2, `ner.py`.** The full rules and spaCy run only if a capitalised word (`[A-Z][a-z]`) survives masking. That skips ISO timestamps and ALL-CAPS status codes, about 60% of lines in the benchmark. Every line still gets the cheap lowercase check below (a word-set lookup).
- **Strong rules:** an honorific (`Dr. Alice Brown`), or a name followed by an action verb (`Raju accessed`, `Kavihska approved`).
- **Weak rules:** a cue word followed by a name (`assigned to Priya Sharma`), or any capitalised pair. When spaCy is installed, a weak match must be **corroborated** by a spaCy PERSON or by a known first name. A capitalised pair must still be two words after stopwords are trimmed ("New York" → "York" is dropped).
- **Name lists:** "John, Sarah and Ali": a name joined by `and` / `or` / `&` / a comma to a match is a name too.
- **Possessives:** "Kenji Sato's" is detected as "Kenji Sato", so it gets the same alias as later bare mentions.
- **Lowercase names:** a lowercase known first name is a PERSON ("kevin reset the router"). The next word is taken as the surname only if the text after it reads like a sentence: a verb, `will`, `has`, a preposition, punctuation or the end ("carlos garcia will take over"). Words glued to paths, hosts, emails or keys (`/home/james`, `ws-james-01`, `user=james`) are skipped.
- **spaCy `en_core_web_sm` (optional):** junk filters reject ALL-CAPS single tokens, underscores and digits.
- **Output types:** `settings.ner_types` (default `[PERSON]`). On logs, spaCy's ORG and LOC labels are mostly product and team names.
- **Stopwords:** a list of words common in ops and logs that are never names.

**Name and product lists, `data/`.** Plain-text, whitespace-separated, case-insensitive, `#` for comments. Extend them for your environment.
- `product_terms.txt`: vendor, product and ops words. A candidate made only of these words (and stopwords) is not a person ("Windows Defender", "Brute Force"), unless an honorific says otherwise ("Mr. Jenkins").
- `first_names.txt`: about 980 given names from eight regions. They corroborate weak rules and drive lowercase detection.
- `ambiguous_names.txt`: given names that are also everyday words, places or faiths (`will`, `mark`, `jordan`, `christian`). They still count when capitalised in a name context, but never in lowercase.

**Cascade, `cascade.py`.** The order is Tier 1 → mask → session memory → mask → Tier 2. Afterwards, adjacent PERSON spans are merged: "Kavishka" (from memory) + "Perera" (from NER) → "Kavishka Perera".

### 3.4 Policy engine: `policy.py`

The policy is YAML, validated when it loads. All errors are reported together.

**Rule lookup.** The engine picks the named policies that match the hook (or the one named by `policy_id`). Within them, the first rule matching the entity type wins; `'*'` matches any type. If nothing matches, it falls back to the policy's own `default_action`, then to the global `default_action`. Results are cached per (type, hook, policy_id).

**Actions:**

| Action | Effect |
|---|---|
| `allow` | Leave the value as it is |
| `pseudonymise` | Replace with an alias via Tier 3 |
| `redact` | Replace with `[EMAIL_ADDRESS]` (format configurable) |
| `mask` | Partial: `r***@corp.com`, `**** **** **** 1111`, `192.168.*.*` |
| `block` | Raise `PolicyBlockError` before anything is written to the registry. The CLI can `fail`, `drop` or `redact` instead. |

**Other policy sections:**

| Section | Purpose |
|---|---|
| `allowlist` | Values that are never PII |
| `custom_patterns` | Organisation-specific identifiers |
| `field_hints` | Field name → type, for structured input |
| `resolution` | Thresholds for Tier 3 |
| `aliases` | Alias prefixes |
| `sensitivity` | Weights for the risk score |

### 3.5 Entity resolution (Tier 3): `resolution/`

**Canonicalisation, `canonical.py`.** Each type has its own normalisation:
- emails: lowercase;
- IPs: `ipaddress` compressed form;
- phones: E.164;
- cards: digits only;
- names: casefold, strip accents and honorifics, then tokenise.

An exact canonical match is an **EXACT** hit.

**Fuzzy matching.** Only PERSON, ORGANIZATION and LOCATION get fuzzy matching. Usernames and emails never fuzzy-merge, because `rmehta` vs `rmheta` in a security log may well be a different account.

**Scoring, `resolver.py`.** Each new name is compared with every *variant* of every known entity of the same type:

| Signal | Weight | Meaning |
|---|---|---|
| Jaro-Winkler (per aligned token) | 0.30 | Prefix-weighted string similarity |
| Edit similarity | 0.20 | 1 − Damerau-Levenshtein / length |
| Typo shape | 0.15 | Adjacent transposition 1.0 · other anagram 0.8 · substitution 0.7 · insertion 0.4 |
| Phonetic agreement | 0.15 | Share of metaphone / soundex / NYSIIS codes that agree, per token |
| Co-occurrence | 0.10 | Jaccard of aliases seen in the same turn vs. the candidate's history |
| Recency | 0.05 | The candidate is the most recently mentioned entity of its type |
| Pool | 0.05 | The candidate is the only entity of its type in the session |

| Combined score | Decision |
|---|---|
| ≥ `merge_threshold` (0.80) | MERGE |
| ≥ `new_entity_threshold` (0.65) | DEFERRED |
| otherwise | NEW_ENTITY |

**Guards that override the score:**
- **Short-name guard:** a name shorter than `min_fuzzy_length` (5) can never fuzzy-MERGE. "Raj"/"Raju" and "Raj"/"Ram" carry too little evidence.
- **Token-subset rule:** "Raj" vs a single known "Raj Mehta" is a MERGE when the shared token is the **first** name. A surname alone ("Perera") is only DEFERRED, since it could be a relative. If several known people share the token, it is DEFERRED.

**DEFERRED means a safe split.** The entity gets its own alias and is flagged in the audit log together with the candidate alias. A reviewer can accept the merge with `piisafe sessions merge`; future mentions then map to the target alias.

**Identity links.** PERSON ↔ EMAIL/USERNAME pairs are linked when this is unambiguous: `Raj Mehta` ↔ `raj.mehta@corp.com` ↔ `rmehta`. Links are metadata in the registry and never change aliases.

### 3.6 Session registry: `registry.py`

- **In memory:** `EntityRecord` holds alias, type, canonical form, surface variants, canonical variants, mentions, turns, co-occurring aliases, links and `merged_into`.
- **Lookup:** by keyed fingerprint of (type, canonical form).
- **Alias counters:** kept per *prefix* (`USER`, `HOST`, …), so several types can share one prefix. The format is `PREFIX_NNN`.
- **Writes:** only records that changed are written back, encrypted, when the registry is flushed.

### 3.7 Security model: `crypto.py`

```
master key   (~/.piisafe/master.key, 0600, or $PIISAFE_MASTER_KEY)
  └─ session key = HMAC-SHA256(master, session_id)     ← shareable for ONE session
       ├─ Fernet (AES-128-CBC + HMAC) encrypts entity payloads
       └─ fingerprint key → HMAC fingerprints in DB and audit log
```

- **No plaintext PII on disk.** A test greps the database file to check this.
- **Keyed hashes.** Fingerprints differ per session, so the same person can't be linked across sessions without the key. A plain SHA-256 of an IPv4 address is reversible: there are only 2³² of them.
- **Wrong keys are rejected.** Each session stores a key-check value.
- **Re-identification is audited.** `restore`, `reidentify`, `merge`, and session key export each write an `events` row.

### 3.8 Storage and audit: `storage/`

`Store` is a protocol; `SQLiteStore` is the v1 implementation.

| Table | Contents |
|---|---|
| `sessions` | id, key check, turn counter |
| `entities` | alias, type, fingerprint, **encrypted payload**, mentions, merged_into |
| `fingerprints` | (type, fingerprint) → alias; one row per variant |
| `counters` | per-prefix alias counters |
| `audit` | one row per finding: hook, policy, source:line, type, value hash, alias, action, decision, scores, candidate, tier, detector |
| `events` | restore / reidentify / merge / key export / delete |

SQLite runs in WAL mode. Audit rows are buffered and written in batches of 1,000.

### 3.9 I/O and CLI: `io/processor.py`, `cli.py`

**Formats.** The processors stream `text`, `jsonl` and `csv` with constant memory; `json` is loaded whole.
- One line or record = one turn.
- JSONL lines that fail to parse are treated as text.
- CSV columns become field hints.
- Line endings are preserved byte for byte.

**CLI behaviour:**
- Output is written atomically (temp file, then rename). A blocked or failed run leaves nothing behind.
- `scan` uses an in-memory session, so dry runs never touch real sessions.

### 3.10 Web service and dashboard: `server/`

`piisafe serve` starts a FastAPI app (`server/app.py`) that wraps `PIISafeGuard`, and serves a no-build single-page dashboard from `server/static/`.

**Concurrency (`server/pool.py`).**
- One long-lived guard per session (LRU-cached, 32 by default), each behind its own lock. This is what keeps aliases correct when requests arrive in parallel; a test fires 20 concurrent requests at one session.
- Each guard owns a SQLite connection; WAL mode plus busy timeouts handle the rest.
- Writes are always committed immediately. An uncommitted UPDATE once held a lock that blocked every other connection; that bug was found and fixed with these tests.

**Auth (`server/auth.py`).**
- API keys `psk_…`, 256-bit random. Only their SHA-256 is stored.
- Roles:
  - `analyst`: sanitise, scan, dashboards, audit, review.
  - `admin`: also re-identification, session deletion, policy edits and key management.
- The first start creates a bootstrap admin key and prints it once. The last admin key cannot be revoked.

**Dashboard data.** These tables hold aggregates only, never content:

| Table | Contents |
|---|---|
| `runs` | One row per file job, from the CLI or the web |
| `usage_daily` | Request and record counters |
| `reviews` | Reviewer decisions on DEFERRED pairs |
| `api_keys` | Key hashes, roles, last use |

The overview charts are computed from `audit`, `runs` and `usage_daily`.

**Frontend (`server/static/`).**
- Vanilla ES modules, with no CDN or build step, so it works on air-gapped customer networks.
- Every value is inserted with text nodes, never `innerHTML`. A strict CSP (`script-src 'self'`) backs that up.
- Charts are single-series SVG with hover and keyboard tooltips, and every chart has a table view.
- Colours come from tokens with explicit light and dark values. Status is always shown as icon + label, never colour alone.
- The layout works down to phone width.

**Uploads and outputs.** Uploads stream to `<state>/uploads/` and are deleted after processing. Sanitised outputs are kept in `<state>/outputs/` for download, and are deleted with their session.

### 3.11 Risk score: `scoring.py`

`exposure = 100 · (1 − e^(−Σ sensitivity·confidence / 10))`. The score saturates: one credit card ≈ 63, a page full of PII → ~100.

`residual_risk` applies the same formula to whatever is left in clear text (`allow`).

---

## 4. How accurate is it? (measured, v0.1)

### Detection

Measured with `python evaluation/run_eval.py`.
- `dev.jsonl` has 44 labelled lines, 16 of them PII-free.
- `heldout.jsonl` has 27 lines, 12 PII-free. It was written before the v0.1 precision fixes and never used for tuning.

| | Dev precision | Dev recall | Held-out precision | Held-out recall |
|---|---|---|---|---|
| Structured types (email, IP, MAC, card, SSN, IBAN, phone, secrets, usernames, hostnames) | 1.00 | 1.00 | 1.00 | 1.00 |
| PERSON, spaCy + rules | 1.00 | 1.00 | 1.00 | 1.00 |
| PERSON, rules only (no spaCy) | 1.00 | 1.00 | 0.89 | 1.00 |

Before the name lists were connected (2026-11-19), PERSON scored 0.77 / 0.83 dev and 0.73 / 1.00 held-out with spaCy, and 0.62 / 0.83 dev and 0.47 / 1.00 held-out without it.

**How to read this:**
- **Structured PII is reliable.** That covers most of the PII in security logs; Tier 1 caught 83% of all findings in the benchmark.
- **Names are still the weak spot,** but much less so. The product list, possessives, name lists and lowercase detection fixed every dev-set error. **The dev score is optimistic:** those fixes were built from the dev errors. The held-out set was not used for tuning, but it has only 8 names. Known gaps: a lowercase surname is dropped when no sentence follows ("the kenji tanaka account" → only "kenji"), and lowercase names missing from `first_names.txt` are still missed.
- **A false positive costs utility, not privacy.** "Jenkins" becomes `USER_004`: over-protection. A false negative is a leak.
- **The sets are small and labelled by the author.** Treat these numbers as a smoke test, not a benchmark. Section 7 explains how to get trustworthy numbers.

### Entity resolution

**Identity resolution** (`evaluation/run_resolution_eval.py`, 65 labelled name pairs, 33 of them the same person):

| Setting | Same person merged | Same person sent to review | Different people wrongly merged |
|---|---|---|---|
| Isolated (only the two names in the session) | 58% | 33% | 3 of 32 |
| Crowded (three other people in between) | 24% | 58% | 0 of 32 |

The 3 wrong merges are real-name pairs one letter apart (Frances/Francis, Marina/Marian, Kiran/Karan). A threshold sweep found no setting that removes them and still auto-merges typos: zero wrong merges needs `merge_threshold` 0.88 or higher, where only case, accent and first-name/full-name matches merge. Nicknames (Bob/Robert) are never merged.

Examples from the unit tests (`tests/unit/test_resolution.py`):

| Case | Outcome |
|---|---|
| Kavishka→Kavihska, Michael→Micheal, Jonathan→Jonathon | MERGE |
| Raj→Raju, Michael→Michelle, "Priya" with two known Priyas, surname alone | DEFERRED |
| Raj→Ram, Alice→Alicia, Alice→Bob | NEW_ENTITY |

### Performance

`piisafe bench -n 2000`: synthetic security logs, spaCy installed, one CPU core.

| Stage | p50 | p99 |
|---|---|---|
| Tier 1 | 0.53 ms | 0.69 ms |
| Tier 2 (runs on ~38% of lines) | 3.5 ms | 11 ms |
| Resolution | 0.03 ms | 0.10 ms |
| Whole line | 0.6 ms | 5 ms |

- **Throughput:** about 450–500 lines/s.
- **Startup:** about 0.6 s, mostly loading spaCy.
- **Leak check:** 0 of the known names or emails appeared in the output.

---

## 5. Where this differs from the original proposal

| Proposal | Implemented | Reason |
|---|---|---|
| SHA-256 of originals | Keyed HMAC per session | Plain hashes of IPs and names can be brute-forced. |
| "Raw PII never stored" *and* `reidentify()` | Payloads encrypted with a session key | The two requirements contradicted each other; encryption satisfies both. |
| Double Metaphone | metaphone + soundex + NYSIIS vote, per token | `jellyfish` lacks Double Metaphone, and DM doesn't match Kavishka/Kavihska anyway. |
| spaCy small as the name detector | Log-aware rules + spaCy, with corroboration | spaCy small misses "Raj flagged…" and labels "SUCCESS" as an ORG. |
| Presidio fallback for DEFERRED | Not used | DEFERRED is a resolution question; a human review (`sessions merge`) answers it better than a second detector. |
| — | Short-name and surname guards | Prevent false merges. |
| — | Session-memory recogniser | Catches later mentions that NER misses. |
| — | Field hints, decoding of encoded tokens, Unicode normalisation | Structured logs and evasion. |

---

## 6. Known limitations

- English only.
- Free-text names: see section 4. Lowercase names that were never seen before are missed.
- No detection of dates of birth, street addresses, passport numbers or national IDs other than US SSN (custom patterns can add them).
- `json` input is loaded into memory.
- Resolution thresholds are hand-set, not learned from data.
- Sessions live in one local SQLite file, so there is no multi-user concurrency.
- Keys live in a local file; there is no KMS or HSM yet.

---

## 7. Moving forward

The SDK is the product core, and everything below wraps it rather than forking it. The phases are ordered so that each one ships something usable and the riskiest unknowns come first.

### Phase 1: make accuracy trustworthy (next)

Accuracy is the product. A privacy tool that leaks, or that destroys the logs, won't be adopted.

1. **A real labelled dataset.** Partly done on 2026-11-19: `evaluation/generate.py` builds a 1,200-line labelled set across five sources, and `run_eval.py --gate` fails CI below `evaluation/thresholds.json`. Still needed: 1–2k *real* lines labelled by two people, with disagreements resolved and a frozen held-out split.
2. **Better name precision:** done on 2026-11-19. There's a first-name list that corroborates weak rules and finds lowercase names, a product/vendor list as a negative signal, and possessive handling. See §3.3.
3. **Better name recall:** `ner: gliner` (`GlinerNER` in `ner.py`) plugs a GLiNER model into the same slot spaCy uses: extra recall plus corroboration for weak rules. Tested only against a stand-in model; not yet measured on the datasets.
4. **Measure resolution.** Done: `evaluation/run_resolution_eval.py` reports merge rates and wrong merges, sweeps thresholds, and gates CI on the baseline. The finding is in §4: string similarity alone can't separate close real names from typos, so better resolution needs new evidence (for example co-occurring emails or usernames), not new thresholds.
5. **More entity types:** done (see the Tier 1 table in §3.3).

### Phase 2: agent integrations (the proposal's v1 scope)

**Done:** `piisafe/integrations/`:
- `guard.as_runnable()` / `restore_runnable()` (LangChain Runnables) and `guard.as_callback()`, a `BaseCallbackHandler` guard rail that rejects prompts still holding raw PII;
- `guard.as_langgraph_node()`, which replaces messages in state by id;
- `piisafe mcp`, an MCP server exposing `sanitize`, `scan` and `score_exposure`, plus `restore` only with `--allow-restore`.

Still to do:
- `on_tool_result` and `on_outbound` hooks.
- Automatic `restore` on tool calls, so tools receive real values while the LLM only sees aliases. This needs a policy flag per tool.
- OpenTelemetry spans from `telemetry.py`.
- A Docker image and `docker-compose` with Ollama for end-to-end demos.

### Phase 3: backend service

**Done in v0.1:** `piisafe serve` provides FastAPI, API keys with roles, per-session locking, and a Dockerfile (built and smoke-tested by the `docker` CI job). See §3.10.

**Done since:** `PostgresStore` (advisory locks across hosts) and managed master keys wrapped by AWS KMS or Vault Transit (`keyproviders.py`, `piisafe master-key migrate`). The Docker compose file runs the dashboard with Postgres.

Still to do for a hosted, multi-customer product:
- Redis for hot session caches.
- Multi-tenancy: tenant → policies → sessions. API keys, quotas, rate limits.
- Per-tenant master keys, and GCP KMS / Azure Key Vault providers.
- Versioned policies stored in the database (`Policy.from_dict` already validates them).
- Deployment options:
  - in-process SDK (lowest latency);
  - a sidecar or HTTP proxy in front of the LLM provider (no code changes for customers).

### Phase 4: dashboard

**Done in v0.1:** overview, sanitise (text and file), review queue, sessions, audit, policy editor, re-identification, activity log, and API keys. See §3.10.

Next:
- SSO (OIDC/SAML) instead of pasted API keys.
- Per-tenant views.
- Exposure trends per data source.
- Re-identification by request and approval, instead of direct admin access.
- Scheduled reports.

The original Phase 4 plan, for reference:

- **Review queue** for DEFERRED decisions: accept a merge or keep the split. This is the `sessions merge` flow plus `audit --deferred`.
- **Policy editor** with live validation and a preview against sample logs (the `scan` flow).
- **Exposure analytics:** risk score over time, by source, by entity type, top leaking sources.
- **Re-identification requests** with approval and a full audit trail.
- **Session browser:** aliases, links and mention counts (no raw values without approval).

### Phase 5: later

- Embedding-based resolution as an extra signal.
- Multi-language NER.
- OPA/Rego policies.
- A streaming-token API (sanitising LLM output as it streams).
- Differential-privacy aggregate reports.

### Seams that already exist for this

| Need | Already in place |
|---|---|
| Swap storage | `storage/base.py` `Store` protocol |
| Keys from a KMS | `PIISafeGuard(session_key=...)`, `create_keys=False` |
| Policies from an API | `Policy.from_dict()` with full validation |
| New hooks | `guard.hooks.register(name, handler)` |
| New detectors | Add a `PatternRecognizer`, or implement a detector returning `Span`s |
| API responses | `SanitiseResult.to_dict()`, `Finding.to_dict()` |
| Regression gates | `evaluation/run_eval.py`, `piisafe bench --json`, `piisafe scan --fail-over` |

---

## 8. Contributor guide: common changes

**Add a structured recogniser.**
1. Add a `PatternRecognizer` to `BUILTIN_RECOGNIZERS` in `detection/patterns.py`, with a validator if possible.
2. Add positive *and* negative cases to `tests/unit/test_tier1.py`.
3. Add labelled lines to `evaluation/datasets/dev.jsonl`.

**Add an entity type.**
1. Add the constant, alias prefix and sensitivity to `entities.py`.
2. Add canonicalisation in `resolution/canonical.py`.
3. Add a default rule in `policies/default.yaml`.

**Add a hook.**
1. Register it in `PIISafeGuard.__init__`.
2. Add a public method.
3. Add it to `KNOWN_HOOKS` in `policy.py`.

**Add a storage backend.** Implement the `Store` protocol and pass `store=` to `PIISafeGuard`.

**Change resolution weights or thresholds.**
1. Run `pytest tests/unit/test_resolution.py`.
2. Explain the change with data from the resolution evaluation (Phase 1.4), not with a single example.

**Before any detection change**, run `python evaluation/run_eval.py -v` and compare the numbers. Never tune on `heldout.jsonl`.

---

## 9. Repository layout

```
src/piisafe/
  guard.py  hooks.py  policy.py  registry.py  crypto.py  normalize.py
  actions.py  scoring.py  telemetry.py  entities.py  models.py  config.py
  keyproviders.py (local / env / AWS KMS / Vault Transit)
  detection/   patterns.py (Tier 1) · memory.py · ner.py (Tier 2) · cascade.py
  resolution/  canonical.py · similarity.py · resolver.py (Tier 3)
  storage/     base.py (protocol) · sql.py · sqlite.py · postgres.py
  server/      app.py (FastAPI) · auth.py · pool.py · static/ (dashboard)
  integrations/ langchain.py · langgraph.py · mcp.py
  io/          processor.py (text / jsonl / json / csv)
  policies/    default.yaml
  cli.py  bench.py  __main__.py
tests/         unit, CLI, server, backend and integration tests (pytest)
evaluation/    run_eval.py + labelled datasets (dev, heldout)
examples/      security.log · events.jsonl · customers.csv
docs/          DESIGN.md (this file)
```
