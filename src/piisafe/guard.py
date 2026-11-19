"""PIISafeGuard — the single public entry point (Façade).

    guard = PIISafeGuard(policy="piisafe.yaml", session_id="INC-001")
    guard.on_prompt("raj.mehta@corp.com accessed 192.168.1.45").sanitised_text
    # -> 'MAIL_001 accessed HOST_001'

Every hook runs the same pipeline:

    normalize -> Tier 1 (regex) -> session memory -> Tier 2 (NER)
              -> allowlist -> policy -> Tier 3 resolution -> registry -> audit
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from piisafe import actions, scoring
from piisafe import entities as E
from piisafe.config import default_state_dir
from piisafe.crypto import KeyManager, SessionCrypto
from piisafe.detection import DetectionCascade, NERDetector, SessionMemoryDetector, Tier1Detector
from piisafe.exceptions import PolicyBlockError
from piisafe.hooks import HookRegistry
from piisafe.models import Action, Decision, Finding, SanitiseResult, Span
from piisafe.normalize import normalize_text
from piisafe.policy import Policy
from piisafe.registry import SessionRegistry
from piisafe.resolution import EntityResolver, canonicalize
from piisafe.storage import SQLiteStore, Store, open_store
from piisafe.telemetry import LatencyRecorder

_AUDIT_FLUSH_EVERY = 1000
_NER_CACHE: dict[tuple[str, str, float, frozenset[str], frozenset[str]], NERDetector] = {}


def _ner_for(policy: Policy, mode: str) -> NERDetector | None:
    if mode == "off":
        return None
    enabled = frozenset(policy.enabled_types())
    st = policy.settings
    key = (mode, st.spacy_model, st.min_ner_score, enabled, frozenset(st.ner_types))
    if key not in _NER_CACHE:
        _NER_CACHE[key] = NERDetector(mode, st.spacy_model, set(enabled), st.min_ner_score, set(st.ner_types))
    return _NER_CACHE[key]


class PIISafeGuard:
    def __init__(
        self,
        policy: str | Path | Policy | None = None,
        session_id: str | None = None,
        *,
        state_dir: str | Path | None = None,
        ephemeral: bool = False,
        session_key: str | None = None,
        store: Store | None = None,
        database_url: str | None = None,
        key_provider: str | None = None,
        ner: str | None = None,
        block_mode: str = "raise",
        create_keys: bool = True,
    ) -> None:
        """
        Args:
            policy: Policy object, path to a YAML policy, or None for the built-in default.
            session_id: Aliases are consistent within a session. Random if omitted.
            state_dir: Where the registry DB and master key live (default ~/.piisafe).
            ephemeral: Keep everything in memory; nothing is written to disk.
            session_key: Use this session key instead of deriving it from the master key.
            store: Custom storage backend (implements piisafe.storage.Store).
            database_url: e.g. postgresql://user:pw@host/db (default: $PIISAFE_DATABASE_URL,
                else SQLite in state_dir).
            key_provider: where the master key comes from (default: $PIISAFE_KEY_PROVIDER, else
                local file). See piisafe.keyproviders — e.g. "aws-kms", "vault-transit".
            ner: Override settings.ner (auto | spacy | heuristic | off).
            block_mode: "raise" -> PolicyBlockError; "redact" -> treat block as redact.
            create_keys: Generate a master key if none exists (False for read-only use).
        """
        if isinstance(policy, Policy):
            self.policy = policy
        elif policy is not None:
            self.policy = Policy.load(policy)
        else:
            self.policy = Policy.default()
        if block_mode not in ("raise", "redact"):
            raise ValueError("block_mode must be 'raise' or 'redact'")
        self.block_mode = block_mode
        self.session_id = session_id or f"session-{uuid.uuid4().hex[:12]}"

        if ephemeral:
            self.state_dir: Path | None = None
            self.store: Store = store or SQLiteStore(":memory:")
        else:
            self.state_dir = Path(state_dir).expanduser() if state_dir else default_state_dir()
            self.store = store or open_store(database_url, self.state_dir)
        self.keys = KeyManager(
            self.state_dir,
            create=create_keys and session_key is None,
            provider="local" if ephemeral else key_provider,
            store=self.store,
        )
        self.crypto = SessionCrypto(session_key or self.keys.session_key(self.session_id))
        self.registry = SessionRegistry(self.session_id, self.store, self.crypto, self.policy.aliases)

        st = self.policy.settings
        self.latency = LatencyRecorder()
        self.memory = SessionMemoryDetector()
        for rec in self.registry.records.values():
            for v in rec.variants:
                self.memory.add(v, rec.entity_type)
        self.ner = _ner_for(self.policy, ner or st.ner)
        self.cascade = DetectionCascade(
            Tier1Detector(
                self.policy.enabled_types(),
                self.policy.custom_patterns,
                st.phone_regions,
                st.decode_encoded,
            ),
            self.ner,
            self.memory,
            self.latency,
        )
        self.resolver = EntityResolver(self.policy.resolution)

        self._audit: list[dict[str, Any]] = []
        self._excl_depth = 0
        self._turn_depth = 0
        self._turn_aliases: set[str] = set()

        self.hooks = HookRegistry()
        self.hooks.register("on_prompt", self._hook_text("on_prompt"))
        self.hooks.register("on_context", self._handle_context)
        self.hooks.register("on_tool_call", self._handle_tool_call)
        self.hooks.register("on_memory", self._handle_memory)
        self.hooks.register("export", self._hook_text("export"))

    # =========================================================== public hooks

    def on_prompt(self, text: str, policy_id: str | None = None) -> SanitiseResult:
        """User message entering the agent."""
        return self.hooks.dispatch("on_prompt", text, policy_id=policy_id)

    def on_context(self, docs: Sequence[str], policy_id: str | None = None) -> list[SanitiseResult]:
        """RAG chunks before they are injected into the context window (one turn)."""
        return self.hooks.dispatch("on_context", docs, policy_id=policy_id)

    def on_tool_call(
        self, tool_name: str, params: Mapping[str, Any], policy_id: str | None = None
    ) -> dict[str, Any]:
        """Tool parameters before the tool executes. Returns sanitised params."""
        return self.hooks.dispatch("on_tool_call", tool_name, params, policy_id=policy_id)

    def on_memory(self, key: str, value: Any, policy_id: str | None = None) -> Any:
        """A value about to be written to agent memory. Returns the sanitised value."""
        return self.hooks.dispatch("on_memory", key, value, policy_id=policy_id)

    def on_export(self, text: str, policy_id: str | None = None) -> SanitiseResult:
        """Data leaving the organisation (reports, tickets, external APIs)."""
        return self.hooks.dispatch("export", text, policy_id=policy_id)

    # ============================================================= integrations

    def as_runnable(self, hook: str = "on_prompt") -> Any:
        """LangChain Runnable that sanitises its input (piisafe.integrations.langchain)."""
        from piisafe.integrations.langchain import sanitize_runnable

        return sanitize_runnable(self, hook)

    def as_callback(self, mode: str = "raise", check_names: bool = False) -> Any:
        """LangChain callback handler that rejects LLM prompts still containing raw PII."""
        from piisafe.integrations.langchain import PIISafeCallbackHandler

        return PIISafeCallbackHandler(self, mode, check_names=check_names)

    def as_langgraph_node(self, keys: Sequence[str] = ("messages",), hook: str = "on_prompt") -> Any:
        """LangGraph node that sanitises the given state keys (piisafe.integrations.langgraph)."""
        from piisafe.integrations.langgraph import sanitize_node

        return sanitize_node(self, keys, hook)

    def _hook_text(self, hook: str):  # noqa: ANN202
        def handler(text: str, policy_id: str | None = None) -> SanitiseResult:
            return self.sanitize(text, hook, policy_id=policy_id)

        return handler

    def _handle_context(self, docs: Sequence[str], policy_id: str | None = None) -> list[SanitiseResult]:
        with self.turn():
            return [self.sanitize(d, "on_context", policy_id=policy_id) for d in docs]

    def _handle_tool_call(
        self, tool_name: str, params: Mapping[str, Any], policy_id: str | None = None
    ) -> dict[str, Any]:
        out, _ = self.sanitize_record(dict(params), "on_tool_call", policy_id=policy_id, source=f"tool:{tool_name}")
        return out

    def _handle_memory(self, key: str, value: Any, policy_id: str | None = None) -> Any:
        out, _ = self.sanitize_record({key: value}, "on_memory", policy_id=policy_id, source=f"memory:{key}")
        return out[key]

    # ============================================================== pipeline

    @contextmanager
    def exclusive(self) -> Iterator[None]:
        """Hold this session exclusively (across threads, processes and DB hosts).

        On entry the registry is reloaded if another writer changed the session;
        on exit everything is flushed. Re-entrant. Every public call uses it, so
        the CLI, the web server and several replicas can share one session
        without ever allocating the same alias twice. Wrap a batch of calls in
        it yourself to pay the lock/flush cost once (the file processor does).
        """
        if self._excl_depth:
            self._excl_depth += 1
            try:
                yield
            finally:
                self._excl_depth -= 1
            return
        with self.store.session_lock(self.session_id):
            self._excl_depth = 1
            try:
                if self.store.session_version(self.session_id) != self.registry.version:
                    self.registry.load()
                    for rec in self.registry.records.values():
                        for v in rec.variants:
                            self.memory.add(v, rec.entity_type)
                yield
            finally:
                try:
                    self._write_pending()
                finally:
                    self._excl_depth = 0

    @contextmanager
    def turn(self) -> Iterator[None]:
        """Group several calls into one turn (shared co-occurrence context)."""
        with self.exclusive():
            if self._turn_depth == 0:
                self.registry.next_turn()
                self._turn_aliases = set()
            self._turn_depth += 1
            try:
                yield
            finally:
                self._turn_depth -= 1

    def sanitize(
        self,
        text: str,
        hook_type: str = "on_prompt",
        *,
        policy_id: str | None = None,
        field_hint: str | None = None,
        source: str | None = None,
        line: int | None = None,
    ) -> SanitiseResult:
        t0 = time.perf_counter()
        audit_id = uuid.uuid4().hex
        with self.turn():
            text = normalize_text(text)
            spans = self.cascade.detect(text)
            if field_hint:
                spans = self._apply_field_hint(text, spans, field_hint)

            planned: list[tuple[Span, str, Action, str | None]] = []
            for s in spans:
                canonical = canonicalize(s.entity_type, s.resolve_value)
                if self.policy.is_allowlisted(s.resolve_value, canonical):
                    continue
                action, pname = self.policy.action_for(s.entity_type, hook_type, policy_id)
                planned.append((s, canonical, action, pname))

            blocked = [p for p in planned if p[2] is Action.BLOCK]
            if blocked and self.block_mode == "raise":
                for s, canonical, action, pname in blocked:
                    self._audit_row(audit_id, hook_type, source, line, Finding(
                        s.entity_type, s.start, s.end, action, "", s.tier, s.detector, s.score,
                        pname, self.registry.fingerprint(s.entity_type, canonical),
                    ))
                raise PolicyBlockError([p[0].entity_type for p in blocked], hook_type, blocked[0][3])

            # Resolve exact-match types first so names get co-occurrence context.
            order = sorted(range(len(planned)), key=lambda i: planned[i][0].entity_type in E.FUZZY_TYPES)
            findings: list[Finding | None] = [None] * len(planned)
            with self.latency.time("resolve"):
                for i in order:
                    findings[i] = self._apply(*planned[i])

            done = [f for f in findings if f is not None]
            out = text
            for f in sorted(done, key=lambda f: f.start, reverse=True):
                out = out[:f.start] + f.replacement + out[f.end:]
            for f in done:
                self._audit_row(audit_id, hook_type, source, line, f)

        sens = self.policy.sensitivity
        elapsed = (time.perf_counter() - t0) * 1000
        self.latency.add("total", elapsed)
        return SanitiseResult(
            sanitised_text=out,
            findings=done,
            risk_score=scoring.exposure(done, sens),
            residual_risk=scoring.residual(done, sens),
            audit_id=audit_id,
            hook_type=hook_type,
            session_id=self.session_id,
            latency_ms=round(elapsed, 3),
        )

    def sanitize_record(
        self,
        obj: Any,
        hook_type: str = "on_prompt",
        *,
        policy_id: str | None = None,
        source: str | None = None,
        line: int | None = None,
    ) -> tuple[Any, list[Finding]]:
        """Sanitise a JSON-like structure. Field names act as entity hints."""
        collected: list[Finding] = []
        with self.turn():
            out = self._walk(obj, None, hook_type, policy_id, source, line, collected)
        return out, collected

    def _walk(
        self, obj: Any, key: str | None, hook: str, policy_id: str | None,
        source: str | None, line: int | None, acc: list[Finding],
    ) -> Any:
        if isinstance(obj, Mapping):
            return {k: self._walk(v, str(k), hook, policy_id, source, line, acc) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._walk(v, key, hook, policy_id, source, line, acc) for v in obj]
        hint = self.policy.hint_for_field(key) if key else None
        if isinstance(obj, str):
            r = self.sanitize(obj, hook, policy_id=policy_id, field_hint=hint, source=source, line=line)
            acc.extend(r.findings)
            return r.sanitised_text
        if hint and isinstance(obj, (int, float)) and not isinstance(obj, bool):
            r = self.sanitize(str(obj), hook, policy_id=policy_id, field_hint=hint, source=source, line=line)
            acc.extend(r.findings)
            return r.sanitised_text if r.findings else obj
        return obj

    def _apply_field_hint(self, text: str, spans: list[Span], hint: str) -> list[Span]:
        stripped = text.strip()
        if not stripped or hint in self.policy.disabled_entities:
            return spans
        lead = len(text) - len(text.lstrip())
        end = lead + len(stripped)
        if any(s.entity_type == hint for s in spans):
            return spans
        if any(s.start <= lead and s.end >= end for s in spans):
            return spans
        return [Span(lead, end, stripped, hint, 0.9, 1, "field_hint", 0)]

    def _apply(self, span: Span, canonical: str, action: Action, pname: str | None) -> Finding:
        fp = self.registry.fingerprint(span.entity_type, canonical)
        base: dict[str, Any] = dict(
            entity_type=span.entity_type, start=span.start, end=span.end, tier=span.tier,
            detector=span.detector, confidence=span.score, policy=pname, value_hash=fp,
        )
        if action is Action.ALLOW:
            return Finding(action=action, replacement=span.text, **base)
        # BLOCK only reaches here with block_mode="redact": recorded as block, redacted.
        if action in (Action.REDACT, Action.BLOCK):
            return Finding(
                action=action,
                replacement=actions.redact(span.entity_type, self.policy.settings.redaction_format),
                **base,
            )
        if action is Action.MASK:
            return Finding(
                action=action,
                replacement=actions.mask(span.entity_type, span.text, self.policy.settings.mask_char),
                **base,
            )

        # pseudonymise
        res = self.resolver.resolve(self.registry, span.entity_type, canonical, self._turn_aliases)
        # Phones resolve on their E.164 form but are restored as written ('+44 20 7946 0958').
        surface = (span.text if span.detector == "phone" else span.resolve_value).strip()
        if res.record is not None:
            rec = res.record
            self.registry.add_variant(rec, canonical, surface)
        else:
            rec = self.registry.create(span.entity_type, canonical, surface)
        self.registry.observe(rec, self._turn_aliases)
        self._turn_aliases.add(rec.alias)
        if res.decision is not Decision.EXACT:
            self.resolver.link_identities(self.registry, rec)
        self.memory.add(surface, span.entity_type)
        return Finding(
            action=action,
            replacement=rec.alias,
            alias=rec.alias,
            decision=res.decision,
            resolution_score=res.score,
            candidate_alias=res.candidate.alias if res.candidate else None,
            linked=tuple(sorted(rec.linked)),
            **base,
        )

    # ============================================================== re-identification

    def reidentify(self, alias: str) -> dict[str, Any]:
        """Return the original value behind *alias*. Every call is logged."""
        with self.exclusive():
            rec = self.registry.get(alias)
        self.store.log_event(self.session_id, "reidentify", {"alias": alias})
        return {
            "alias": rec.alias,
            "entity_type": rec.entity_type,
            "value": rec.surface,
            "variants": sorted(rec.variants),
            "mentions": rec.mentions,
            "linked": sorted(rec.linked),
        }

    def restore(self, text: str) -> str:
        """Replace aliases in *text* (e.g. an LLM answer) with the original values."""
        count = 0

        def sub(m: Any) -> str:
            nonlocal count
            alias = m.group(1)
            if alias not in self.registry.records:
                return alias
            count += 1
            return self.registry.get(alias).surface

        with self.exclusive():
            out = E.ALIAS_RE.sub(sub, text)
        self.store.log_event(self.session_id, "restore", {"aliases_restored": count})
        return out

    def merge(self, src_alias: str, dst_alias: str) -> None:
        """Accept a DEFERRED pair: future mentions of *src* map to *dst*."""
        with self.exclusive():
            self.registry.merge(src_alias, dst_alias)
        self.store.log_event(self.session_id, "merge", {"src": src_alias, "dst": dst_alias})

    def session_key(self) -> str:
        return self.keys.session_key(self.session_id)

    # ============================================================== persistence

    def _audit_row(
        self, audit_id: str, hook: str, source: str | None, line: int | None, f: Finding
    ) -> None:
        self._audit.append(
            {
                "audit_id": audit_id,
                "ts": time.time(),
                "session_id": self.session_id,
                "hook_type": hook,
                "policy": f.policy,
                "source": source,
                "line": line,
                "entity_type": f.entity_type,
                "value_hash": f.value_hash,
                "alias": f.alias,
                "action": f.action.value,
                "decision": f.decision.value if f.decision else None,
                "confidence": round(f.confidence, 4),
                "resolution_score": round(f.resolution_score, 4) if f.resolution_score is not None else None,
                "candidate_alias": f.candidate_alias,
                "tier": f.tier,
                "detector": f.detector,
            }
        )
        if len(self._audit) >= _AUDIT_FLUSH_EVERY:
            self._write_pending()

    def _write_pending(self) -> None:
        """Persist registry changes and buffered audit rows. Caller holds exclusive()."""
        self.registry.flush()
        self.store.insert_audit(self._audit)
        self._audit.clear()

    def flush(self) -> None:
        with self.exclusive():
            pass  # exclusive() writes everything pending on exit

    def close(self) -> None:
        self.flush()
        self.store.close()

    def __enter__(self) -> PIISafeGuard:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
