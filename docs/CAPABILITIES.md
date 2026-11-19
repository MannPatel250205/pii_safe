# PII-Safe v0.1: capabilities, limitations and roadmap

A single summary of what PII-Safe does today, where it falls short, and what comes next.
For how things work internally, see [DESIGN.md](DESIGN.md). For setup and usage, see the [README](../README.md).

Status as of **2026-11-19**, version **0.1.0**.

---

## 1. What it supports today

### Detection

| Area | Supported |
|---|---|
| **Structured PII** (regex + validators) | Email, IPv4/IPv6, MAC address, credit card (Luhn + issuer check), US SSN, IBAN (mod-97), phone numbers (via Google `phonenumbers`), internal hostnames (`.local`, `.corp`, `.internal`, `.lan` …) |
| **Secrets** | JWTs, AWS keys, `Bearer …` tokens, `password=` / `token:` pairs, passwords in URLs, PEM headers |
| **Usernames** | sshd formats (`for X from`, `Invalid user X`), `DOMAIN\user`, `user=` / `login:` keys, URL users |
| **Person names** | Log-aware rules (honorifics, name + action verb, cue words, "X and Y" lists), possessives, unseen lowercase names from a ~980-name first-name list, a product/vendor deny-list, and optional spaCy `en_core_web_sm` corroboration |
| **Session memory** | Names seen earlier in a session are caught again later, including lowercase forms of names with 6+ letters |
| **Custom identifiers** | Your own regexes in the policy (e.g. `EMP-\d+` → `EMP_001`) |
| **Evasion handling** | Unicode normalisation; looks inside base64, hex and %-encoded tokens |
| **Structured input** | Field-name hints in JSON/CSV (`src_ip`, `userEmail` …) protect a value even if it looks unusual |

### Pseudonymisation and entity resolution

- **Stable, typed aliases:** the same value gets the same alias across a whole session (`192.168.1.45` → `HOST_001` everywhere).
- **Typo merging:** `Kavishka` / `Kavihska` and `Michael` / `Micheal` merge into one alias.
- **Safe splitting:** short or ambiguous names (`Raj` / `Raju`, two different `Priya`s) stay separate and go to a human **review queue**.
- **Identity linking:** `Raj Mehta` is linked to `raj.mehta@corp.com` in the registry.

### Policy engine

- Five actions per entity type and per hook: `allow`, `pseudonymise`, `redact`, `mask`, `block`.
- Hooks: `on_prompt`, `on_context`, `on_memory`, `on_tool_call`.
- An allowlist (values and patterns), alias prefix overrides and per-type on/off switches.
- Validation from the CLI (`piisafe policy validate`) or from the dashboard editor. Unknown keys are rejected with a "did you mean" hint, so a typo such as `hook_types` can't silently fall back to a default.
- Custom hook names (e.g. `on_ticket`) work in the SDK, API, CLI and dashboard.
- One active policy for every interface: the CLI uses `-p FILE`, then `./piisafe.yaml`, then the policy saved from the dashboard, then the built-in default.

### Security

- Original values are **encrypted** with a per-session key. Aliases are derived with a keyed HMAC, not plain hashes.
- **Master key providers:** local file, environment variable, **AWS KMS**, **HashiCorp Vault Transit**. Migrate between them with `piisafe master-key migrate`.
- Every restore, re-identification, merge and key export is written to the **audit log**.
- API keys are stored as hashes only, with two roles: `analyst` and `admin`.
- The dashboard sets a strict CSP and renders log text as text, so injected HTML is inert.
- One lock per session (Postgres advisory locks across hosts), so two requests never get the same alias.

### Interfaces

| Interface | What you get |
|---|---|
| **CLI** | `sanitize`, `scan` (CI gate with `--fail-over`), `restore`, `reidentify`, `sessions`, `audit`, `policy`, `bench`, `serve`, `mcp`, `keys`, `master-key`, `doctor` |
| **Input formats** | `text`, `jsonl`, `csv` (streamed) and `json` (whole document) |
| **Python SDK** | `PIISafeGuard` |
| **REST API** | FastAPI: sanitise text or a file, scan, restore, re-identify, reviews, policy, API keys, stats, sessions, audit; OpenAPI docs at `/api/docs` |
| **Dashboard** | Overview and risk analytics, sanitise, review queue, sessions, audit log, policy editor, re-identification, activity log, API keys |
| **LangChain** | Sanitise and restore Runnables, plus a callback guard rail that rejects prompts still holding raw PII |
| **LangGraph** | A sanitise node that replaces messages in state |
| **MCP server** | `sanitize`, `scan` and `score_exposure` tools; `restore` only with `--allow-restore` |
| **Storage** | SQLite (default) or PostgreSQL |
| **Deployment** | Local install, a Dockerfile, and `docker-compose.yml` with Postgres |

### Measured quality (v0.1)

| | Precision | Recall |
|---|---|---|
| Structured PII | 1.00 | 1.00 |
| Person names, spaCy + rules (held-out set) | 1.00 | 1.00 |
| Person names, rules only (held-out set) | 0.89 | 1.00 |

- **Before the name lists were connected** (2026-11-19), names scored 0.73 (spaCy) and 0.47 (rules only) precision on the same held-out set. That set has only 8 names, so the gain is real, but the exact figures are not reliable.
- **Performance:** about 0.7 ms per line at p50 and 7 ms at p99, or about 450 lines/s on one core with spaCy.
- **Leak check:** in the benchmark, none of the known names or emails appeared in the output.

---

## 2. Known limitations

### Accuracy

- **Small evaluation set.** The figures come from 71 hand-labelled lines written by the author. Treat them as a smoke test, not a benchmark.
- **Names are the weak spot.**
  - Missed: lowercase names that aren't in `first_names.txt`, and a lowercase surname that isn't followed by a sentence-like word (`the kenji tanaka account` protects only `kenji`). A miss is a **leak**.
  - Over-flagged: Title-Case product names missing from `product_terms.txt`. Add your own tools there. This costs usefulness, not privacy.
- **Resolution thresholds are hand-set**, not learned from data. Merge accuracy has not been measured at scale.
- **English only.**

### Coverage

- No built-in detection for dates of birth, street addresses, passport numbers, or national IDs other than US SSN (Aadhaar, PAN, NI …), bank account numbers or driver's licences. Custom patterns can cover some of these.
- Phone numbers written without a `+country` prefix are found only for the regions listed in `settings.phone_regions` (default: US, IN, GB).
- `json` (whole-document) input is loaded fully into memory. `text`, `jsonl` and `csv` stream.

### Agent workflows

- Tools called by an agent receive **aliases, not real values**. There is no automatic per-tool restore yet.
- The `on_tool_result` and `on_outbound` hooks are not implemented.

### Operations and deployment

- The dashboard signs in with pasted API keys. **No SSO** (OIDC/SAML).
- No multi-tenancy, quotas or rate limits.
- Managed keys cover AWS KMS and Vault only; GCP KMS and Azure Key Vault are not supported.
- **CI is set up but has not run yet.** `.github/workflows/ci.yml` builds the Docker image, starts the compose stack and smoke-tests it, runs the PostgreSQL tests against a Postgres service, and installs every extra so the server, agent-framework and AWS tests run. Until the repository is pushed and that workflow passes, treat the Docker files and the Postgres backend as untested.
- Locally, the **PostgreSQL tests** run only when `PIISAFE_TEST_DATABASE_URL` is set. Otherwise they are skipped.
- **Memory:** the full test suite with spaCy needs about 2 GB of free RAM. On small VMs without swap, the OOM killer can stop the test run and the editor that started it.

---

## 3. What can be done in the future

### Phase 1: make accuracy trustworthy (next)

1. **A real labelled dataset:**
   - 1–2k lines from sshd/auth logs, Windows events, web access logs, SIEM alerts and helpdesk tickets;
   - labelled by two people;
   - a frozen held-out split;
   - a CI gate that fails if recall drops.
2. **Better name precision:** done on 2026-11-19 (first-name list, product deny-list, possessives, lowercase names).
3. **Better name recall:** an optional transformer NER backend (e.g. GLiNER or a small fine-tuned BERT) behind the existing `NERDetector` interface.
4. **Measured resolution:** a labelled set of same-person / different-person pairs, with thresholds fitted to the data.
5. **More entity types:** date of birth in context, street addresses, passport / Aadhaar / PAN / NI numbers, bank accounts and driver's licences, each with positive and negative tests.

### Phase 2: agent integrations

- `on_tool_result` and `on_outbound` hooks.
- **Automatic restore on tool calls,** controlled by a policy flag per tool, so tools get real values while the LLM only sees aliases.
- OpenTelemetry spans.
- An end-to-end demo stack (Docker compose with Ollama).

### Phase 3: backend service

- Redis for hot session caches.
- Multi-tenancy (tenant → policies → sessions), quotas and rate limits.
- Per-tenant master keys, plus GCP KMS and Azure Key Vault providers.
- Versioned policies stored in the database.
- A sidecar or HTTP-proxy deployment in front of the LLM provider, so customers need no code changes.

### Phase 4: dashboard

- SSO (OIDC/SAML).
- Per-tenant views.
- Exposure trends per data source.
- Re-identification by **request and approval** instead of direct admin access.
- Scheduled reports.

### Phase 5: later

- Embedding-based entity resolution.
- Multi-language NER.
- OPA/Rego policies.
- Sanitising LLM output as it streams.
- Differential-privacy aggregate reports.

### Quick wins: done on 2026-11-19

- CI installs `.[dev,server,agents,postgres,aws]`, with a separate job for spaCy.
- A Postgres service in CI, so the Postgres tests run.
- A Docker job in CI that builds the image and smoke-tests the compose stack.
- Restore keeps phone numbers as originally written.

---

## 4. Extension points already in place

| Need | Existing seam |
|---|---|
| A new storage backend | The `Store` protocol in `storage/base.py` |
| Keys from another KMS | The `ManagedKeyProvider` protocol in `keyproviders.py` |
| Policies from an API or database | `Policy.from_dict()` with full validation |
| New hooks | `guard.hooks.register(name, handler)` |
| New detectors | A `PatternRecognizer`, or any detector that returns `Span`s |
| Regression gates | `evaluation/run_eval.py`, `piisafe bench --json`, `piisafe scan --fail-over` |
