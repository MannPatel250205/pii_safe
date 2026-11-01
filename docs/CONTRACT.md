# PII-Safe: frozen contract (Stage 0B)

**Owner:** Mann · **Frozen at:** Stage 0B sign-off · **Status:** draft, awaiting mentor sign-off

This is the one-page contract the rest of the project builds against. Everything here is
**frozen**: changing any signature or schema below needs both Mann and Raj to agree, as the risk
table in the work plan requires. The reasoning behind these choices, and the places where they
deviate from the original proposal, live in [DESIGN.md](DESIGN.md) — this page is just the
agreed surface.

---

## 1. Public API — `PIISafeGuard`

Five hooks. Four are the agent-loop hooks from the plan; `on_export` is the outbound hook the
CLI and server already use.

```python
guard.on_prompt(text: str, policy_id: str | None = None) -> SanitiseResult
guard.on_context(docs: Sequence[str], policy_id: str | None = None) -> list[SanitiseResult]
guard.on_tool_call(tool_name: str, params: Mapping[str, Any], policy_id: str | None = None) -> dict[str, Any]
guard.on_memory(key: str, value: Any, policy_id: str | None = None) -> Any
guard.on_export(text: str, policy_id: str | None = None) -> SanitiseResult
guard.reidentify(alias: str) -> dict[str, Any]
```

Hooks dispatch through `HookRegistry` (`hooks.py`), so a v2 hook such as `on_tool_result` is one
`register()` call and **no** change to this contract's existing entries.

`SanitiseResult` (`models.py`):

| Field | Type | Meaning |
|---|---|---|
| `sanitised_text` | `str` | text with every non-`allow` finding replaced |
| `findings` | `list[Finding]` | one per detected span |
| `risk_score` | `float` | 0–100, exposure before sanitisation |
| `residual_risk` | `float` | 0–100, exposure still present after |
| `audit_id` | `str` | groups every audit row from this call |
| `hook_type` | `str` | which hook produced it |
| `session_id` | `str` | registry scope |
| `latency_ms` | `float` | measured, not estimated |
| `dropped` | `bool` | input refused whole (block + `--on-block drop`) |

`Finding` carries `entity_type, start, end, action, replacement, tier, detector, confidence,
policy, value_hash, alias, decision, resolution_score, candidate_alias, linked`.

> **Note vs. the plan:** the plan listed `SanitiseResult(sanitised_text, risk_score,
> entities_found, audit_id)`. `entities_found` is named `findings` and the shape is wider. Raj's
> Stage 0A API file is the origin; this is the version that shipped.

---

## 2. Alias format — `TYPE_NNN`

`{PREFIX}_{counter:03d}`, counters kept **per prefix per session**, so `USER_001`, `HOST_003`,
`MAIL_002`. Recognised again by `ALIAS_RE = \b([A-Z][A-Z0-9]*_\d{3,})\b` — three digits is the
minimum, not the maximum, so a session may run past `USER_999`.

Default prefixes (`entities.DEFAULT_ALIAS_PREFIX`, overridable per policy under `aliases:`):

| Type | Prefix | Type | Prefix | Type | Prefix |
|---|---|---|---|---|---|
| `PERSON` | `USER` | `IP_ADDRESS` | `HOST` | `CREDIT_CARD` | `CARD` |
| `USERNAME` | `ACCT` | `HOSTNAME` | `NODE` | `US_SSN` | `SSN` |
| `EMAIL_ADDRESS` | `MAIL` | `MAC_ADDRESS` | `MAC` | `IBAN_CODE` | `IBAN` |
| `ORGANIZATION` | `ORG` | `PHONE_NUMBER` | `PHONE` | `SECRET` | `SECRET` |
| `LOCATION` | `LOC` | | | | |

An unknown type falls back to the first 8 alphanumerics of its name, or `ENTITY`.

---

## 3. Session Entity Registry

Keyed by `(session_id, entity_type, fingerprint)`, where
`fingerprint = HMAC(session_key, f"{entity_type}\x1f{canonical}")`.

`EntityRecord`: `alias, entity_type, canonical, surface, fingerprint, variants,
canon_variants, mentions, first_turn, last_turn, cooccur, linked, merged_into`.

Storage rules — these are the security claims the project makes, so they do not bend:

1. **Nothing identifying is stored in the clear.** The record payload is encrypted with the
   session key before it reaches the store; lookups go through keyed fingerprints only.
2. **Keyed HMAC, not bare SHA-256.** A plain hash of an IP or a common name is brute-forceable
   in seconds; the per-session key removes that. (This is a deliberate change from the proposal's
   "SHA-256 only" — see [DESIGN.md §5](DESIGN.md).)
3. **Sessions are isolated.** The same name in two sessions gets two registries, two keys and
   unrelated aliases. A wrong key raises `KeyMismatchError`, never silent garbage.
4. **Merges are soft.** `merge()` sets `merged_into`; nothing is deleted, so an audit trail of
   the merge survives.

---

## 4. Policy YAML schema

Top-level keys: `version`, `default_action`, `settings`, `resolution`, `aliases`, `allowlist`,
`custom_patterns`, `entities`, `field_hints`, `policies`.

Actions: `allow | pseudonymise | redact | mask | block`. (`mask` is a fifth action beyond the
plan's four — partial reveal, e.g. `****-****-****-1111`.) `block` raises `PolicyBlockError`.

A named policy set:

```yaml
policies:
  - name: tool_guard        # <- this is the policy_id callers pass
    hook_type: on_tool_call # or a list, or '*' for any hook
    rules:
      - entity_type: SECRET           # one type, a list, or '*'
        action: block
      - entity_type: [CREDIT_CARD, US_SSN]
        action: redact
```

Resolution order in `action_for(entity_type, hook_type, policy_id)`:

1. `policy_id` given → only that named set is considered; unknown id raises `PolicyError`.
2. No `policy_id` → every set whose `hook_type` matches, in file order.
3. First matching rule wins; then the set's own `default_action`; then the file's
   `default_action`. Results are cached per `(entity_type, hook_type, policy_id)`.

---

## 5. Audit log schema

One row per detected span, in the `audit` table (SQLite or Postgres, same DDL):

`audit_id, ts, session_id, hook_type, policy, source, line, entity_type, value_hash, alias,
action, decision, confidence, resolution_score, candidate_alias, tier, detector`

- `value_hash` is a **keyed HMAC**, never the raw value — the audit log is safe to ship off-box.
- `hook_type` is always filled, so every row is attributable to a hook.
- `decision` is `MERGE | NEW_ENTITY | DEFERRED`; `DEFERRED` rows are indexed
  (`audit_session ON audit(session_id, decision)`) so review queues are cheap.
- `audit_id` groups all rows from one hook call and matches `SanitiseResult.audit_id`.

---

## 6. What changing this costs

| Change | Needs |
|---|---|
| New hook, new entity type, new alias prefix, new policy key | Owner's judgement — additive, no agreement needed |
| Renaming or re-typing anything in §1–§5 | Both partners agree in writing; note it in the stage handoff |
| Weakening §3's storage rules | Not allowed in v1 — they are the project's core claim |
