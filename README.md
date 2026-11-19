# PII-Safe

Privacy guard for agentic AI workflows. PII-Safe finds PII in logs, prompts, RAG chunks and tool calls and swaps each value for a **stable, typed alias**. The LLM can still work out *who did what* without ever learning who anyone is.

```
2024-03-12 09:00 raj.mehta@corp.com accessed 192.168.1.45 — FAILED_LOGIN      2024-03-12 09:00 MAIL_001 accessed HOST_001 — FAILED_LOGIN
2024-03-12 09:05 Raj flagged by the security system                    ──►    2024-03-12 09:05 USER_001 flagged by the security system
2024-03-12 09:07 Raju accessed 192.168.1.67 — SUCCESS                         2024-03-12 09:07 USER_002 accessed HOST_002 — SUCCESS
2024-03-12 09:12 Kavishka logged in from 192.168.1.45                         2024-03-12 09:12 USER_003 logged in from HOST_001
2024-03-12 09:14 Kavihska approved the request          (typo)                2024-03-12 09:14 USER_003 approved the request
```

- `Raj` and `Raju` stay separate, and the pair is flagged for human review.
- The `Kavihska` typo merges into `USER_003`.
- The same IP gets the same alias (`HOST_001`) wherever it appears.
- Real values can be restored later with the session key. Every restore is audited.

## What's included

| Part | What you get |
|---|---|
| **Core SDK + CLI** | Detection (regex + validators, name rules, optional spaCy), entity resolution, policies per hook, encrypted alias registry, audit log. |
| **Agent integrations** | LangChain (sanitise Runnable, restore Runnable, guard-rail callback), LangGraph (sanitise node), MCP server (`piisafe mcp`). |
| **Backend** | FastAPI REST API, SQLite or **PostgreSQL**, API keys with roles, and **managed master keys** in AWS KMS or HashiCorp Vault. |
| **Dashboard** | Overview and risk analytics, a review queue for ambiguous name matches, a policy editor, sessions, the audit log, re-identification and API keys. |

## Contents

1. [Setup](#1-setup)
2. [Configuration: what goes where](#2-configuration-what-goes-where)
3. [Third-party services (Postgres, AWS KMS, Vault)](#3-third-party-services)
4. [How to use it](#4-how-to-use-it): CLI · dashboard · REST API · SDK · LangChain · LangGraph · MCP
5. [Keeping PII safe: checklist](#5-keeping-pii-safe-checklist)
6. [Policy](#6-policy)
7. [How it works](#7-how-it-works) and [security model](#8-security-model)
8. [Development](#9-development), [accuracy](#10-accuracy-v01-measured) and [limitations](#11-known-limitations-v01)

---

## 1. Setup

### Requirements

- Python **3.10+**
- Optional: PostgreSQL 13+ for shared, multi-host state
- Optional: an AWS KMS key or a HashiCorp Vault Transit key for managed master keys
- Optional: Docker with Compose v2.24+ for the container setup
- RAM: the core is light. spaCy and the test suite need noticeably more, so on small VMs keep 2 GB free or add swap.

### Local install

```bash
git clone <your-repo-url> piisafe && cd piisafe
python3 -m venv .venv && . .venv/bin/activate

pip install -e .                          # core SDK + CLI
pip install -e ".[server]"                # + dashboard and REST API
pip install -e ".[agents]"                # + LangChain, LangGraph and MCP integrations
pip install -e ".[ner]" && python -m spacy download en_core_web_sm   # + better name recall

piisafe init                              # writes ./piisafe.yaml (picked up automatically)
piisafe doctor                            # checks the install, NER backend, key permissions and DB
```

Install only the extras you need. Several can be combined, for example `pip install -e ".[server,postgres,aws,agents]"`.

| Extra | Installs | Needed for |
|---|---|---|
| `server` | FastAPI, uvicorn | `piisafe serve` (dashboard + REST API) |
| `postgres` | psycopg 3 | `PIISAFE_DATABASE_URL=postgresql://…` |
| `aws` | boto3 | `PIISAFE_KEY_PROVIDER=aws-kms` |
| `langchain` | langchain-core | `piisafe.integrations.langchain` |
| `langgraph` | langgraph | `piisafe.integrations.langgraph` |
| `mcp` | MCP Python SDK (v1 or v2) | `piisafe mcp` |
| `agents` | all three integrations above | |
| `ner` | spaCy | Tier-2 name detection with a statistical model |
| `dev` | pytest, ruff, mypy, httpx | running the test suite |

Without spaCy, name detection falls back to the built-in log-aware rules. Vault needs no extra package.

### Docker (dashboard + PostgreSQL)

```bash
cp .env.example .env && chmod 600 .env    # set POSTGRES_PASSWORD at minimum
docker compose up -d
docker compose logs piisafe               # copy the one-time admin API key printed on first start
```

Open <http://localhost:8765>. The image includes the `server`, `ner`, `postgres`, `aws` and `mcp` extras. The port is bound to localhost only; put an HTTPS reverse proxy in front before exposing it. *The `docker` CI job builds and smoke-tests this stack; it has not had its first run yet.*

---

## 2. Configuration: what goes where

All secrets and connection settings are **environment variables**. Nothing secret goes in `piisafe.yaml`, which you can commit. The full annotated list is in [`.env.example`](.env.example).

```bash
cp .env.example .env && chmod 600 .env    # .env is git-ignored
set -a && . ./.env && set +a              # load it for the CLI / SDK (docker compose reads it automatically)
```

| Variable | Default | Set it when |
|---|---|---|
| `PIISAFE_HOME` | `~/.piisafe` | You want the SQLite DB, local master key and outputs elsewhere. |
| `PIISAFE_DATABASE_URL` | SQLite in `PIISAFE_HOME` | You use PostgreSQL: `postgresql://user:pass@host:5432/db`. |
| `PIISAFE_KEY_PROVIDER` | `env` if `PIISAFE_MASTER_KEY` is set, else `local` | You use `aws-kms` or `vault-transit`. |
| `PIISAFE_MASTER_KEY` | none | Provider `env`: the master key itself, injected by your secrets manager. |
| `PIISAFE_KMS_KEY_ID`, `AWS_REGION`, AWS credentials | none | Provider `aws-kms`. |
| `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_CACERT`, `PIISAFE_VAULT_KEY`, `PIISAFE_VAULT_MOUNT` | mount `transit`, key `piisafe` | Provider `vault-transit`. |
| `POSTGRES_PASSWORD` | none | Only for `docker compose`, which creates the bundled Postgres. |

Every variable also has a CLI flag (`--state-dir`, `--database-url`, `--key-provider`) and an SDK argument (`state_dir=`, `database_url=`, `key_provider=`).

**PII-Safe does not call any LLM, so it needs no LLM API key.** `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` and similar belong to *your* agent code and are read by those SDKs directly.

**Dashboard / REST API keys** (`psk_…`) are not set in `.env`. They are created by PII-Safe (see [Dashboard](#dashboard)), and only a hash of each key is stored.

---

## 3. Third-party services

Each of these is optional. Start with the defaults, then add them when you deploy to more than one host.

### PostgreSQL (shared state for several replicas / hosts)

```sql
-- as a Postgres superuser
CREATE USER piisafe WITH PASSWORD 'a-long-random-password';
CREATE DATABASE piisafe OWNER piisafe;
```

```bash
pip install -e ".[postgres]"
export PIISAFE_DATABASE_URL='postgresql://piisafe:a-long-random-password@db.internal:5432/piisafe'
piisafe doctor            # creates the schema on first use; the password is masked in all output
```

Every API replica, CLI host and MCP server that points at the same database shares sessions, aliases, the review queue and the audit log. Per-session locking uses Postgres advisory locks, so it holds across hosts. In production, use `?sslmode=require` and a managed secret for the password.

### Managed master key: AWS KMS

PII-Safe generates the master key, has KMS **wrap** (encrypt) it, and stores only the wrapped blob in the database. The plaintext key never touches disk, and a database dump on its own is useless.

1. **Create a key:** AWS Console → KMS → *Create key* → Symmetric, *Encrypt and decrypt*. Note the key ARN or create an alias such as `alias/piisafe`.
2. **Grant the PII-Safe role** (instance profile, ECS task role or IRSA) this permission:
   ```json
   { "Effect": "Allow",
     "Action": ["kms:Encrypt", "kms:Decrypt"],
     "Resource": "arn:aws:kms:eu-west-1:123456789012:key/…",
     "Condition": { "StringEquals": { "kms:EncryptionContext:application": "piisafe" } } }
   ```
3. **Configure** (a database is required, because that is where the wrapped key lives):
   ```bash
   pip install -e ".[aws,postgres]"
   export PIISAFE_KEY_PROVIDER=aws-kms
   export PIISAFE_KMS_KEY_ID=alias/piisafe
   export AWS_REGION=eu-west-1          # credentials: role (preferred), AWS_PROFILE, or access keys
   piisafe master-key status
   ```

### Managed master key: HashiCorp Vault Transit

```bash
vault secrets enable transit
vault write -f transit/keys/piisafe
vault policy write piisafe - <<'EOF'
path "transit/encrypt/piisafe" { capabilities = ["update"] }
path "transit/decrypt/piisafe" { capabilities = ["update"] }
EOF
vault token create -policy=piisafe        # use AppRole / Kubernetes auth in production

export PIISAFE_KEY_PROVIDER=vault-transit
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=…                      # optional: VAULT_NAMESPACE, VAULT_CACERT, PIISAFE_VAULT_KEY, PIISAFE_VAULT_MOUNT
piisafe master-key status
```

### Moving an existing local key into KMS / Vault

Existing sessions stay readable, because the *same* key is wrapped:

```bash
piisafe master-key migrate --from local --to aws-kms     # or --to vault-transit; --from env for $PIISAFE_MASTER_KEY
# then set PIISAFE_KEY_PROVIDER=aws-kms everywhere PII-Safe runs, check `piisafe master-key status`,
# and securely delete ~/.piisafe/master.key (or the old $PIISAFE_MASTER_KEY secret)
```

---

## 4. How to use it

### CLI

```bash
piisafe sanitize examples/security.log -o clean.log -s INC-001
piisafe sanitize examples/events.jsonl -o clean.jsonl -s INC-001   # same session = same aliases
cat clean.log | your-llm-tool > answer.txt                          # the LLM only ever sees aliases
piisafe restore answer.txt -s INC-001                               # aliases -> real values (audited)
piisafe scan examples/security.log --fail-over 50                   # CI / pre-commit gate (exit 4)
```

| Command | What it does |
|---|---|
| `sanitize IN [-o OUT] [-s SESSION]` | Writes a sanitised copy. Text, JSONL, JSON and CSV are detected by extension; `-` means stdin/stdout. Output is written atomically. |
| `scan IN [--fail-over 50] [--fail-on-pii]` | Dry run. Lists findings (values masked) and the exposure score. Exits 4 on threshold. |
| `restore IN -s SESSION` | Replaces aliases in, for example, an LLM answer with the original values. |
| `reidentify USER_001 … -s SESSION` | Shows the value behind an alias, plus its variants and linked identities. |
| `sessions list \| show \| key \| merge \| delete` | Manages sessions. `merge` accepts a flagged pair after review. `key` exports the session key. |
| `audit [-s S] [--deferred] [--events]` | Queries the audit log, or the re-identification / merge events. |
| `policy validate FILE` / `policy show` | Validates a policy, or prints the entity × hook action matrix. |
| `serve` | Runs the dashboard and REST API. |
| `mcp` | Runs the MCP server. |
| `keys create \| list \| revoke` | Manages dashboard / API keys. |
| `master-key status \| migrate` | Shows the master key source, or moves the key into KMS / Vault. |
| `bench [-n 1000]` | Latency per tier (p50/p90/p99), tier-1 hit rate, leak check on synthetic logs. |
| `doctor` | Checks the installation, NER backend, key permissions and DB location. |

Useful flags:
- `--hook on_prompt|on_context|on_tool_call|on_memory|export` selects which policy applies.
- `--policy-id NAME` forces a named policy set.
- `--on-block fail|drop|redact` controls what happens when a `block` rule fires.
- `--ephemeral` keeps everything in memory, so nothing is persisted and nothing can be restored.
- `--report run.json` writes a machine-readable summary.

Exit codes: `0` ok · `1` error · `2` usage · `3` blocked by policy · `4` risk threshold exceeded.

### Dashboard

```bash
piisafe serve                                  # http://localhost:8765
```

1. On first start, a one-time **admin key** is printed. Store it in your password manager; it is never shown again.
2. Open the dashboard and paste the key to sign in.
3. Create keys for people and agents under **API keys**, or from the CLI:
   `piisafe keys create soc-team --role analyst`. `analyst` can sanitise, scan and review. `admin` can also re-identify, edit policy, delete sessions and manage keys.

| Page | What it is for |
|---|---|
| **Overview** | Risk analytics: records processed, PII found, identities protected, pending reviews and peak exposure. Findings per day, by type, by action and by resolution decision. Recent runs. |
| **Sanitize** | Paste text, or upload `.log`/`.txt`/`.jsonl`/`.json`/`.csv` files up to 50 MB. Shows highlighted aliases, findings and exposure; the sanitised file can be downloaded. "Scan only" is a dry run. |
| **Review queue** | Ambiguous name matches. Choose "Same person — merge" or "Different". Admins can reveal both values; this is logged. |
| **Sessions** | Every session with identities by type, file runs and the alias registry. Values are never shown here. Admins can delete a session. |
| **Audit log** | Every finding, filterable by session, decision and type. Values are stored as keyed hashes only. |
| **Policy** | The entity × hook action matrix. Admins can edit, validate and apply the YAML; it applies to new requests immediately. |
| **Re-identify** *(admin)* | Restore aliases in an LLM's answer, or look up individual aliases. Every use is logged. |
| **Activity log** *(admin)* | Re-identifications, merges, deletions, policy changes and key events. |
| **API keys** *(admin)* | Create and revoke `analyst` or `admin` keys. |

The CLI, the dashboard and the MCP server share the same state (state directory or `PIISAFE_DATABASE_URL`), so all runs appear on the dashboard.

### REST API

Interactive docs: `http://localhost:8765/api/docs`. Authenticate with `Authorization: Bearer psk_…`.

```bash
export PIISAFE_API_KEY=psk_…               # an analyst key; keep it out of shell history and code

curl -s localhost:8765/api/sanitize -H "Authorization: Bearer $PIISAFE_API_KEY" \
     -H 'Content-Type: application/json' \
     -d '{"text": "raj.mehta@corp.com accessed 192.168.1.45", "session_id": "INC-001"}'
# {"sanitised_text": "MAIL_001 accessed HOST_001", "risk_score": 58.7, "findings": [...], ...}
```

| Endpoint | Role | Purpose |
|---|---|---|
| `POST /api/sanitize` | analyst | `{text, session_id?, hook?, policy_id?, on_block?}` → sanitised text + findings |
| `POST /api/sanitize/file` | analyst | Multipart file upload; the sanitised output is downloadable |
| `POST /api/scan` | analyst | Dry run, with masked previews |
| `GET/POST /api/reviews` | analyst | Review queue: list pending matches, decide `merge` or `keep` |
| `GET /api/stats`, `/api/runs`, `/api/sessions`, `/api/audit` | analyst | Analytics and history |
| `GET /api/policy`, `POST /api/policy/validate` | analyst | Read or validate policy |
| `PUT /api/policy` | admin | Apply a new policy |
| `POST /api/restore`, `POST /api/reidentify` | admin | Aliases → real values (audited) |
| `GET/POST/DELETE /api/keys`, `GET /api/events` | admin | Key management, activity log |

A `block` rule returns HTTP **409** with the entity types and the matching policy, never the value.

### Python SDK

```python
from piisafe import PIISafeGuard, PolicyBlockError

with PIISafeGuard(policy="piisafe.yaml", session_id="INC-001") as guard:
    r = guard.on_prompt("raj.mehta@corp.com accessed 192.168.1.45")
    r.sanitised_text        # 'MAIL_001 accessed HOST_001'
    r.risk_score            # exposure of the input, 0-100
    r.findings              # per span: type, action, alias, decision, tier, detector …

    guard.on_context(["chunk 1 …", "chunk 2 …"])               # RAG chunks, one turn
    guard.on_tool_call("block_ip", {"src_ip": "192.168.1.45"})  # field names act as hints
    try:
        guard.on_memory("note", "mail raj@corp.com")
    except PolicyBlockError as e:
        ...                                                     # e.entity_types, e.policy_name
    guard.restore("USER_001 approved it")                       # audited
```

`PIISafeGuard(...)` also accepts `database_url=`, `key_provider=`, `state_dir=` and `ephemeral=True`.

### LangChain

`pip install -e ".[langchain]"`

```python
from langchain_anthropic import ChatAnthropic          # any chat model works
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from piisafe import PIISafeGuard
from piisafe.integrations.langchain import restore_runnable

guard = PIISafeGuard(session_id="INC-001")
prompt = ChatPromptTemplate.from_messages([("system", "You are a SOC analyst."), ("human", "{question}")])

chain = (
    guard.as_runnable()          # 1. sanitise the input: str, dict, messages, prompt values, Documents
    | prompt
    | ChatAnthropic(model="claude-sonnet-5-5")
    | StrOutputParser()
    | restore_runnable(guard)    # 3. optional: real values back, for an authorised end user only
)
answer = chain.invoke(
    {"question": "Why was raj.mehta@corp.com locked out of 192.168.1.45?"},
    config={"callbacks": [guard.as_callback()]},   # 2. guard rail: abort if raw PII reaches the LLM
)
```

- **`guard.as_runnable(hook="on_prompt")`** (= `sanitize_runnable(guard)`): sanitises strings, dicts, lists, messages (including multi-part content), prompt values and `Document`s. Message ids and document metadata are kept.
- **`guard.as_callback(mode="raise"|"warn", check_names=False)`** (= `PIISafeCallbackHandler`): LangChain callbacks cannot modify inputs, so this one *verifies* every LLM prompt. It raises `UnsanitisedPIIError`, or logs a warning in `warn` mode, if structured PII got through. It uses a private in-memory checker, so it never touches your session or logs values. `check_names=True` also checks names, which can flag product names.
- **`restore_runnable(guard)`**: puts real values back. Leave it out unless the output goes straight to someone allowed to see them.
- For retrievers: `retriever | guard.as_runnable("on_context")`.

### LangGraph

`pip install -e ".[langgraph]"`

```python
from langgraph.graph import END, START, MessagesState, StateGraph

graph = StateGraph(MessagesState)
graph.add_node("pii_guard", guard.as_langgraph_node())     # sanitises state["messages"]
graph.add_node("agent", call_model)
graph.add_edge(START, "pii_guard")
graph.add_edge("pii_guard", "agent")
graph.add_edge("agent", END)
app = graph.compile()
```

The node returns the messages with the **same ids**, so the `add_messages` reducer *replaces* the originals. Raw text is not kept in the graph state or the checkpointer. Use `guard.as_langgraph_node(keys=("messages", "ticket"))` for other state keys. The node is idempotent, so you can also put it before every model call in a loop.

### MCP server (Claude Desktop, Claude Code, Cursor, …)

`pip install -e ".[mcp]"`

```bash
piisafe mcp                                       # stdio: what desktop clients launch
piisafe mcp --transport streamable-http           # HTTP: http://127.0.0.1:8766/mcp
```

| Tool | Returns | Stores |
|---|---|---|
| `sanitize(text, session_id="mcp-default", hook="on_prompt")` | Aliased text, risk score, entity counts, number needing review | Yes (session) |
| `scan(text, hook)` | Entity types, positions, **masked** previews | No |
| `score_exposure(text, hook)` | 0–100 score, counts per type, types that would stay in clear | No |
| `restore(text, session_id)` | Real values. **Only exists with `--allow-restore`**; audited | No |

Tool results never contain detected values. The model only ever gets aliases.

**Claude Code:**

```bash
claude mcp add piisafe -- /path/to/piisafe/.venv/bin/piisafe mcp
```

**Claude Desktop / Cursor** (`claude_desktop_config.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "piisafe": {
      "command": "/path/to/piisafe/.venv/bin/piisafe",
      "args": ["mcp"],
      "env": { "PIISAFE_HOME": "/home/you/.piisafe" }
    }
  }
}
```

Add `PIISAFE_DATABASE_URL` / `PIISAFE_KEY_PROVIDER` to `env` to share state with a central deployment. Point the client at your MCP server with an absolute path to the venv's `piisafe`. The streamable-http transport has no authentication of its own, so keep it on localhost or behind an authenticating proxy.

---

## 5. Keeping PII safe: checklist

- [ ] **Secrets only in env / a secrets manager.** `.env` is git-ignored and should be `chmod 600`. Never put keys in `piisafe.yaml`, code or notebooks.
- [ ] **Back up the master key**, or use KMS / Vault. Without it, no session can be restored, by design.
- [ ] **Production:** use a managed key provider (`aws-kms` / `vault-transit`) and PostgreSQL with TLS, and delete any old local `master.key`.
- [ ] **Network:** the dashboard and MCP HTTP bind to `127.0.0.1`. Expose them only behind an HTTPS reverse proxy.
- [ ] **Least privilege:** give agents and most people `analyst` keys. Keep `admin` for re-identification and policy. Revoke unused keys (`piisafe keys list`).
- [ ] **Restore last, rarely.** Only `restore` output that goes to a person allowed to see it. Don't enable MCP `--allow-restore` unless you must.
- [ ] **Gate in CI:** `piisafe scan <file> --fail-on-pii` or `--fail-over 50` before logs or fixtures are committed or shared.
- [ ] **Review the queue** regularly. Ambiguous names get separate aliases until someone decides.
- [ ] **Don't commit state:** `~/.piisafe/`, `*.db` and `master.key` are git-ignored. Keep it that way.
- [ ] **Session per investigation.** Sharing one session's key reveals that session only.

---

## 6. Policy

Generate one with `piisafe init`. The default policy documents itself. Key sections:

| Section | What it controls |
|---|---|
| `policies` | Rules per hook (`on_prompt`, `on_context`, `on_tool_call`, `on_memory`, `export`). First match wins; `'*'` matches any entity type. Actions: `allow`, `pseudonymise`, `redact`, `mask`, `block`. |
| `allowlist` | Values that are never treated as PII, such as `127.0.0.1` or `root`. |
| `custom_patterns` | Your own identifiers, for example `EMP-12345`. |
| `field_hints` | For JSON/CSV, the field name implies the type: `src_ip`, `userEmail`. |
| `resolution` | The merge / defer thresholds. |

Check a policy with `piisafe policy validate piisafe.yaml` and `piisafe policy show`. In the dashboard, the **Policy** page edits it live.

The CLI picks its policy in this order: `-p FILE`, then `./piisafe.yaml`, then the policy saved from the dashboard (stored in the database), then the built-in default. `piisafe policy show` prints which one is in use.

---

## 7. How it works

```
text ─► normalise (NFKC, strip zero-width, decode base64/hex/%-encoding ≤3 levels)
     ─► Tier 1  regex + validators (Luhn, ipaddress, IBAN mod-97, phonenumbers)    ~0.5 ms
     ─► memory  names already seen in this session (catches what NER misses)       ~0.01 ms
     ─► Tier 2  log-aware name rules + spaCy (only if a capitalised word remains) ~3.5 ms
     ─► allowlist ─► policy (entity × hook → allow/pseudonymise/redact/mask/block)
     ─► Tier 3  entity resolution → EXACT / MERGE / DEFERRED / NEW_ENTITY
     ─► registry (encrypted) + audit log (keyed hashes only)
```

Tier 3 scores each known entity on several signals:
- Jaro-Winkler and Damerau-Levenshtein similarity;
- *typo shape* (transposition vs. insertion);
- phonetic agreement per token (metaphone, soundex, NYSIIS);
- co-occurrence, recency and pool size.

Two guards keep it conservative:
- **Short names** (fewer than 5 letters) never fuzzy-merge.
- **A surname alone** (for example "Perera") never merges into a full name.

Ambiguous cases become **DEFERRED**: the name gets its own alias and lands in the review queue.

[docs/DESIGN.md](docs/DESIGN.md) explains every component, the security model, measured accuracy and the roadmap.

## 8. Security model

- **No plaintext PII at rest.** Registry payloads are Fernet-encrypted (AES-128-CBC + HMAC) with a per-session key.
- **Keyed hashes only.** Fingerprints and audit hashes are HMAC-SHA256, not plain SHA-256, which is brute-forceable for IPs and first names.
- **Key hierarchy:** master key (local file mode 0600, `$PIISAFE_MASTER_KEY`, or wrapped by AWS KMS / Vault) → session key = HMAC(master, session_id).
  - Sharing one session's key re-identifies that session only.
  - A wrong key is rejected.
- **Every re-identification is logged:** `restore`, `reidentify`, `merge` and key export all write to the events log.
- **API keys** are stored as hashes only. Two roles: `analyst` and `admin`.
- **Dashboard:** strict CSP, and all log text is rendered as text, so `<script>` inside a log line is inert.
- **Concurrency:** one lock per session (advisory locks on Postgres), so concurrent requests and replicas never hand out the same alias twice.
- **No secrets in output:** database passwords are masked as `***`, and scans and MCP results show masked previews only.

## 9. Development

```bash
pip install -e ".[dev,server,agents]"
pytest                                    # unit, CLI, server and integration tests
PIISAFE_TEST_DATABASE_URL=postgresql://… pytest tests/integration/test_backends.py tests/integration/test_server.py   # + Postgres tests
python evaluation/run_eval.py -v          # detection precision / recall
ruff check src tests
piisafe bench -n 2000
```

Tests for an integration whose framework is not installed are skipped. On small VMs, set aside about 2 GB of free RAM (or add swap) for the full suite with spaCy.

## 10. Accuracy (v0.1, measured)

`python evaluation/run_eval.py` runs against hand-labelled lines, including PII-free lines that probe for false positives:

| | Precision | Recall |
|---|---|---|
| Structured PII (email, IP, card, SSN, IBAN, phone, secrets, usernames, national IDs …) | 1.00 | 1.00 |
| Person names, with spaCy (held-out set) | 1.00 | 1.00 |
| Person names, rules only (held-out set) | 0.89 | 1.00 |

Structured PII is reliable. Names improved a lot once the first-name and product lists were connected. Extend `src/piisafe/data/product_terms.txt` with your own tool names to avoid aliasing them. The hand-labelled datasets are small (71 lines, 8 held-out names), so treat these figures as a smoke test. A generated 1,200-line set across five log sources scores 1.00 precision and 0.97 / 0.92 recall (structured / names, rules only), and CI fails if scores drop below `evaluation/thresholds.json`. See [DESIGN.md §4](docs/DESIGN.md#4-how-accurate-is-it-measured-v01).

## 11. Known limitations (v0.1)

- English only.
- Passport, licence, bank-account and date-of-birth numbers are found only next to a keyword (`passport no:`, `DOB:`).
- Name detection in free text is rule-based plus spaCy-small (or an optional GLiNER model, not yet benchmarked). Lowercase names are found only if they are in the bundled first-name list, and Title-Case product names missing from the product list can still be aliased.
- `json` (whole-document) input is loaded into memory. `text`, `jsonl` and `csv` stream.
- Phone detection depends on `settings.phone_regions` for numbers written without a `+country` prefix.
- The dashboard signs in with pasted API keys. SSO (OIDC/SAML) is not implemented yet.
- Tools called by an agent receive aliases, not real values. Automatic per-tool restore is on the roadmap.
- The Docker image and compose file are only covered by the `docker` CI job, which has not had its first run yet.
