"""Policy engine: (entity_type, hook_type[, policy_id]) -> action.

Strategy pattern: the action is chosen at runtime per span. Rules within a
named policy are evaluated top to bottom, first match wins; ``"*"`` matches any
entity type. If no named policy for the hook matches, the policy's own
``default_action`` applies, then the global ``default_action``.

Policies are validated on load and every problem is reported at once.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from piisafe import entities as E
from piisafe.detection.patterns import CustomPattern
from piisafe.exceptions import PolicyError
from piisafe.models import Action
from piisafe.resolution.resolver import ResolutionConfig

KNOWN_HOOKS = ("on_prompt", "on_context", "on_tool_call", "on_memory", "export")
_HOOK_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


@dataclass(frozen=True, slots=True)
class Rule:
    entity_types: frozenset[str]
    action: Action

    def matches(self, entity_type: str) -> bool:
        return "*" in self.entity_types or entity_type in self.entity_types


@dataclass(slots=True)
class NamedPolicy:
    name: str
    hook_types: frozenset[str]
    rules: list[Rule]
    default_action: Action | None = None

    def applies_to(self, hook_type: str) -> bool:
        return "*" in self.hook_types or hook_type in self.hook_types


@dataclass(slots=True)
class Settings:
    phone_regions: list[str] = field(default_factory=lambda: ["US"])
    ner: str = "auto"
    spacy_model: str = "en_core_web_sm"
    min_ner_score: float = 0.5
    ner_types: list[str] = field(default_factory=lambda: ["PERSON"])
    decode_encoded: bool = True
    redaction_format: str = "[{type}]"
    mask_char: str = "*"


@dataclass(slots=True)
class Policy:
    version: str = "1.0"
    default_action: Action = Action.PSEUDONYMISE
    policies: list[NamedPolicy] = field(default_factory=list)
    settings: Settings = field(default_factory=Settings)
    resolution: ResolutionConfig = field(default_factory=ResolutionConfig)
    aliases: dict[str, str] = field(default_factory=dict)
    sensitivity: dict[str, float] = field(default_factory=dict)
    allowlist_values: frozenset[str] = frozenset()
    allowlist_patterns: tuple[re.Pattern[str], ...] = ()
    custom_patterns: tuple[CustomPattern, ...] = ()
    field_hints: dict[str, str] = field(default_factory=dict)
    disabled_entities: frozenset[str] = frozenset()
    source: str = "<builtin>"
    _cache: dict[tuple[str, str, str | None], tuple[Action, str | None]] = field(
        default_factory=dict, repr=False
    )

    # ------------------------------------------------------------ loading

    @classmethod
    def default(cls) -> Policy:
        text = resources.files("piisafe").joinpath("policies/default.yaml").read_text("utf-8")
        return cls.from_dict(yaml.safe_load(text), source="<builtin:default.yaml>")

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        p = Path(path)
        try:
            data = yaml.safe_load(p.read_text("utf-8"))
        except FileNotFoundError as exc:
            raise PolicyError(f"policy file not found: {p}") from exc
        except yaml.YAMLError as exc:
            raise PolicyError(f"{p}: invalid YAML: {exc}") from exc
        return cls.from_dict(data, source=str(p))

    @classmethod
    def from_dict(cls, data: Any, source: str = "<dict>") -> Policy:
        errors: list[str] = []
        if not isinstance(data, dict):
            raise PolicyError(f"{source}: top level must be a mapping")

        def action(value: Any, where: str) -> Action:
            try:
                return Action.parse(value)
            except ValueError:
                errors.append(f"{where}: unknown action '{value}' "
                              f"(expected one of {', '.join(a.value for a in Action)})")
                return Action.PSEUDONYMISE

        def type_set(value: Any, where: str) -> frozenset[str]:
            items = value if isinstance(value, list) else [value]
            out = set()
            for it in items:
                s = str(it).strip()
                if s != "*" and not _TYPE_RE.match(s):
                    errors.append(f"{where}: invalid entity_type '{s}' (use UPPER_SNAKE_CASE)")
                out.add(s)
            return frozenset(out)

        pol = cls(source=source)
        pol.version = str(data.get("version", "1.0"))
        pol.default_action = action(data.get("default_action", "pseudonymise"), "default_action")

        # settings
        s = data.get("settings") or {}
        st = Settings()
        regions = s.get("phone_regions", st.phone_regions)
        st.phone_regions = [str(r).upper() for r in (regions if isinstance(regions, list) else [regions])]
        st.ner = str(s.get("ner", st.ner)).lower()
        if st.ner not in ("auto", "spacy", "heuristic", "off"):
            errors.append(f"settings.ner: '{st.ner}' must be auto|spacy|heuristic|off")
        st.spacy_model = str(s.get("spacy_model", st.spacy_model))
        st.min_ner_score = float(s.get("min_ner_score", st.min_ner_score))
        nt = s.get("ner_types", st.ner_types)
        st.ner_types = [str(t) for t in (nt if isinstance(nt, list) else [nt])]
        for t in st.ner_types:
            if t not in ("PERSON", "ORGANIZATION", "LOCATION"):
                errors.append(f"settings.ner_types: '{t}' must be PERSON, ORGANIZATION or LOCATION")
        st.decode_encoded = bool(s.get("decode_encoded", st.decode_encoded))
        st.redaction_format = str(s.get("redaction_format", st.redaction_format))
        st.mask_char = str(s.get("mask_char", st.mask_char))[:1] or "*"
        try:
            st.redaction_format.format(type="X")
        except (KeyError, IndexError, ValueError):
            errors.append("settings.redaction_format: may only use the {type} placeholder")
        pol.settings = st

        # resolution
        r = data.get("resolution") or {}
        rc = ResolutionConfig()
        rc.merge_threshold = float(r.get("merge_threshold", rc.merge_threshold))
        rc.new_entity_threshold = float(r.get("new_entity_threshold", rc.new_entity_threshold))
        rc.min_fuzzy_length = int(r.get("min_fuzzy_length", rc.min_fuzzy_length))
        rc.link_identities = bool(r.get("link_identities", rc.link_identities))
        if not 0 <= rc.new_entity_threshold <= rc.merge_threshold <= 1:
            errors.append("resolution: need 0 <= new_entity_threshold <= merge_threshold <= 1")
        pol.resolution = rc

        # aliases / sensitivity
        aliases = data.get("aliases") or {}
        for k, v in aliases.items():
            if not re.match(r"^[A-Z][A-Z0-9]*$", str(v)):
                errors.append(f"aliases.{k}: prefix '{v}' must be uppercase letters/digits")
        pol.aliases = {str(k): str(v) for k, v in aliases.items()}
        pol.sensitivity = {str(k): float(v) for k, v in (data.get("sensitivity") or {}).items()}

        # allowlist
        allow = data.get("allowlist") or {}
        pol.allowlist_values = frozenset(str(v).casefold() for v in allow.get("values", []) or [])
        pats = []
        for i, p in enumerate(allow.get("patterns", []) or []):
            try:
                pats.append(re.compile(str(p)))
            except re.error as exc:
                errors.append(f"allowlist.patterns[{i}]: bad regex: {exc}")
        pol.allowlist_patterns = tuple(pats)

        # custom patterns
        customs = []
        for i, cp in enumerate(data.get("custom_patterns", []) or []):
            where = f"custom_patterns[{i}]"
            if not isinstance(cp, dict) or "regex" not in cp or "entity_type" not in cp:
                errors.append(f"{where}: needs 'entity_type' and 'regex'")
                continue
            try:
                compiled = re.compile(cp["regex"])
            except re.error as exc:
                errors.append(f"{where}: bad regex: {exc}")
                continue
            group = int(cp.get("group", 0))
            if group > compiled.groups:
                errors.append(f"{where}: group {group} does not exist in regex")
                continue
            etype = str(cp["entity_type"])
            type_set(etype, where)
            customs.append(
                CustomPattern(str(cp.get("name", etype.lower())), etype, cp["regex"],
                              float(cp.get("score", 0.9)), group)
            )
            if cp.get("alias"):
                pol.aliases.setdefault(etype, str(cp["alias"]))
        pol.custom_patterns = tuple(customs)

        pol.field_hints = {str(k).lower(): str(v) for k, v in (data.get("field_hints") or {}).items()}
        ents = data.get("entities") or {}
        pol.disabled_entities = frozenset(k for k, v in ents.items() if v is False)

        # named policies
        names: set[str] = set()
        for i, np_ in enumerate(data.get("policies", []) or []):
            where = f"policies[{i}]"
            if not isinstance(np_, dict) or not np_.get("name"):
                errors.append(f"{where}: each policy needs a 'name'")
                continue
            name = str(np_["name"])
            where = f"policies[{name}]"
            if name in names:
                errors.append(f"{where}: duplicate policy name")
            names.add(name)
            hooks_raw = np_.get("hook_type", "*")
            hooks = frozenset(str(h) for h in (hooks_raw if isinstance(hooks_raw, list) else [hooks_raw]))
            for h in hooks:
                if h != "*" and not _HOOK_RE.match(h):
                    errors.append(f"{where}: invalid hook_type '{h}'")
            rules = []
            for j, rule in enumerate(np_.get("rules", []) or []):
                rw = f"{where}.rules[{j}]"
                if not isinstance(rule, dict) or "entity_type" not in rule or "action" not in rule:
                    errors.append(f"{rw}: needs 'entity_type' and 'action'")
                    continue
                rules.append(Rule(type_set(rule["entity_type"], rw), action(rule["action"], rw)))
            dflt = np_.get("default_action")
            pol.policies.append(
                NamedPolicy(name, hooks, rules, action(dflt, where) if dflt is not None else None)
            )

        if errors:
            raise PolicyError(f"{source}: invalid policy:\n  - " + "\n  - ".join(errors))
        return pol

    # ---------------------------------------------------------- evaluation

    def policy_names(self) -> list[str]:
        return [p.name for p in self.policies]

    def action_for(
        self, entity_type: str, hook_type: str, policy_id: str | None = None
    ) -> tuple[Action, str | None]:
        key = (entity_type, hook_type, policy_id)
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        if policy_id is not None:
            candidates = [p for p in self.policies if p.name == policy_id]
            if not candidates:
                raise PolicyError(
                    f"unknown policy_id '{policy_id}' (have: {', '.join(self.policy_names()) or 'none'})"
                )
        else:
            candidates = [p for p in self.policies if p.applies_to(hook_type)]
        result: tuple[Action, str | None] | None = None
        for p in candidates:
            for rule in p.rules:
                if rule.matches(entity_type):
                    result = (rule.action, p.name)
                    break
            if result:
                break
        if result is None:
            for p in candidates:
                if p.default_action is not None:
                    result = (p.default_action, p.name)
                    break
        if result is None:
            result = (self.default_action, None)
        self._cache[key] = result
        return result

    def is_allowlisted(self, value: str, canonical: str) -> bool:
        if value.casefold() in self.allowlist_values or canonical.casefold() in self.allowlist_values:
            return True
        return any(p.fullmatch(value) or p.fullmatch(canonical) for p in self.allowlist_patterns)

    def enabled_types(self) -> set[str]:
        types = set(E.BUILTIN_TYPES) | {c.entity_type for c in self.custom_patterns}
        return types - set(self.disabled_entities)

    def hint_for_field(self, key: str) -> str | None:
        """Entity type implied by a structured field name ('src_ip' -> IP_ADDRESS)."""
        if not self.field_hints:
            return None
        k = key.strip().lower()
        if k in self.field_hints:
            return self.field_hints[k]
        parts = [p for p in re.split(r"[_\-.\s]+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key.strip())) if p]
        if parts:
            return self.field_hints.get(parts[-1].lower())
        return None

    def matrix(
        self, entity_types: list[str] | None = None, hooks: list[str] | None = None
    ) -> dict[str, dict[str, str]]:
        types = entity_types or sorted(self.enabled_types())
        hks = hooks or list(KNOWN_HOOKS)
        return {t: {h: self.action_for(t, h)[0].value for h in hks} for t in types}
