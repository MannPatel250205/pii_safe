"""Session Entity Registry: (session, canonical form) -> stable typed alias.

Plaintext lives only in memory. On flush, each entity's payload is encrypted
with the session key; lookups go through keyed fingerprints.
"""

from __future__ import annotations

from collections.abc import Iterable

from piisafe import entities as E
from piisafe.crypto import SessionCrypto
from piisafe.exceptions import AliasNotFoundError, KeyMismatchError
from piisafe.models import EntityRecord
from piisafe.storage.base import Store

_MAX_VARIANTS = 50
_MAX_COOCCUR = 64


class SessionRegistry:
    def __init__(
        self,
        session_id: str,
        store: Store,
        crypto: SessionCrypto,
        alias_prefixes: dict[str, str] | None = None,
    ) -> None:
        self.session_id = session_id
        self.store = store
        self.crypto = crypto
        self._prefixes = alias_prefixes or {}
        self.records: dict[str, EntityRecord] = {}
        self._index: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = {}
        self.last_alias_of_type: dict[str, str] = {}
        self.turn = 0
        self.version = 0
        self.created = False
        self._dirty: set[str] = set()
        self._new_fps: list[tuple[str, str, str]] = []
        self._load()

    # ---------------------------------------------------------------- load

    def _load(self) -> None:
        sess = self.store.get_session(self.session_id)
        if sess is None:
            self.store.create_session(self.session_id, self.crypto.key_check())
            self.created = True
            sess = self.store.get_session(self.session_id)
            assert sess is not None
        self.load(sess)

    def load(self, sess: dict | None = None) -> None:
        """(Re)load the session from the store — after another process changed it."""
        sess = sess or self.store.get_session(self.session_id)
        if sess is None:
            raise AliasNotFoundError(f"session '{self.session_id}' no longer exists")
        if sess["key_check"] != self.crypto.key_check():
            raise KeyMismatchError(
                f"the key in use does not belong to session '{self.session_id}'"
            )
        self.turn = sess["turn"]
        self.version = sess.get("version", 0) or 0
        self.records = {}
        self._index = {}
        self._dirty.clear()
        self._new_fps.clear()
        for row in self.store.load_entities(self.session_id):
            payload = self.crypto.decrypt(row["payload"])
            rec = EntityRecord.from_payload(
                row["alias"], row["entity_type"], row["fingerprint"], row["mentions"],
                row["merged_into"], payload,
            )
            self.records[rec.alias] = rec
        for etype, fp, alias in self.store.load_fingerprints(self.session_id):
            self._index[(etype, fp)] = alias
        self._counters = self.store.load_counters(self.session_id)
        latest: dict[str, tuple[int, str]] = {}
        for rec in self.records.values():
            if rec.merged_into is None:
                cur = latest.get(rec.entity_type)
                if cur is None or rec.last_turn > cur[0]:
                    latest[rec.entity_type] = (rec.last_turn, rec.alias)
        self.last_alias_of_type = {t: a for t, (_, a) in latest.items()}

    # -------------------------------------------------------------- lookup

    def fingerprint(self, entity_type: str, canonical: str) -> str:
        return self.crypto.fingerprint(f"{entity_type}\x1f{canonical}")

    def get(self, alias: str) -> EntityRecord:
        seen = set()
        rec = self.records.get(alias)
        while rec is not None and rec.merged_into and rec.alias not in seen:
            seen.add(rec.alias)
            rec = self.records.get(rec.merged_into)
        if rec is None:
            raise AliasNotFoundError(f"alias '{alias}' not found in session '{self.session_id}'")
        return rec

    def lookup(self, entity_type: str, canonical: str) -> EntityRecord | None:
        alias = self._index.get((entity_type, self.fingerprint(entity_type, canonical)))
        return self.get(alias) if alias else None

    def active(self, entity_type: str | None = None) -> list[EntityRecord]:
        return [
            r
            for r in self.records.values()
            if r.merged_into is None and (entity_type is None or r.entity_type == entity_type)
        ]

    # ------------------------------------------------------------ mutation

    def _next_alias(self, entity_type: str) -> str:
        prefix = E.alias_prefix(entity_type, self._prefixes)
        n = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = n
        return f"{prefix}_{n:03d}"

    def create(self, entity_type: str, canonical: str, surface: str) -> EntityRecord:
        alias = self._next_alias(entity_type)
        fp = self.fingerprint(entity_type, canonical)
        rec = EntityRecord(
            alias=alias,
            entity_type=entity_type,
            canonical=canonical,
            surface=surface,
            fingerprint=fp,
            variants={surface},
            canon_variants={canonical},
            first_turn=self.turn,
            last_turn=self.turn,
        )
        self.records[alias] = rec
        self._index[(entity_type, fp)] = alias
        self._new_fps.append((entity_type, fp, alias))
        self._dirty.add(alias)
        return rec

    def add_variant(self, rec: EntityRecord, canonical: str, surface: str) -> None:
        key = (rec.entity_type, self.fingerprint(rec.entity_type, canonical))
        if key not in self._index:
            self._index[key] = rec.alias
            self._new_fps.append((*key, rec.alias))
            self._dirty.add(rec.alias)
        if surface not in rec.variants and len(rec.variants) < _MAX_VARIANTS:
            rec.variants.add(surface)
            self._dirty.add(rec.alias)
        if canonical not in rec.canon_variants and len(rec.canon_variants) < _MAX_VARIANTS:
            rec.canon_variants.add(canonical)
            self._dirty.add(rec.alias)

    def observe(self, rec: EntityRecord, context_aliases: Iterable[str]) -> None:
        rec.mentions += 1
        rec.last_turn = self.turn
        for a in context_aliases:
            if a != rec.alias and len(rec.cooccur) < _MAX_COOCCUR:
                rec.cooccur.add(a)
        self.last_alias_of_type[rec.entity_type] = rec.alias
        self._dirty.add(rec.alias)

    def link(self, a: EntityRecord, b: EntityRecord) -> None:
        if b.alias not in a.linked:
            a.linked.add(b.alias)
            b.linked.add(a.alias)
            self._dirty.update((a.alias, b.alias))

    def merge(self, src_alias: str, dst_alias: str) -> EntityRecord:
        """Fold *src* into *dst* (e.g. after a reviewer confirms a DEFERRED pair)."""
        src, dst = self.get(src_alias), self.get(dst_alias)
        if src.alias == dst.alias:
            return dst
        if src.entity_type != dst.entity_type:
            raise ValueError(f"cannot merge {src.entity_type} into {dst.entity_type}")
        for key, alias in list(self._index.items()):
            if alias == src.alias:
                self._index[key] = dst.alias
                self._new_fps.append((*key, dst.alias))
        dst.variants |= src.variants
        dst.canon_variants |= src.canon_variants
        dst.cooccur |= src.cooccur
        dst.linked |= src.linked
        dst.mentions += src.mentions
        src.merged_into = dst.alias
        self._dirty.update((src.alias, dst.alias))
        return dst

    def next_turn(self) -> int:
        self.turn += 1
        return self.turn

    # --------------------------------------------------------------- flush

    def flush(self) -> None:
        if not self._dirty and not self._new_fps:
            self.store.set_session_turn(self.session_id, self.turn)
            return
        rows = []
        for alias in self._dirty:
            rec = self.records[alias]
            rows.append(
                {
                    "alias": rec.alias,
                    "entity_type": rec.entity_type,
                    "fingerprint": rec.fingerprint,
                    "payload": self.crypto.encrypt(rec.to_payload()),
                    "mentions": rec.mentions,
                    "merged_into": rec.merged_into,
                }
            )
        # Callers hold the session lock, so bumping the version here is race-free;
        # other processes see the new version and reload before writing.
        self.version += 1
        self.store.save_registry(self.session_id, rows, self._new_fps, self._counters, self.turn, self.version)
        self._dirty.clear()
        self._new_fps.clear()
