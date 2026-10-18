"""Dialect-neutral SQL store: session registry, audit log, events, dashboard data.

`SQLiteStore` (single host) and `PostgresStore` (shared, multi-replica) subclass
this and only supply connection handling, a transaction primitive, a session
lock and a few SQL fragments. All queries are written once, with `?` / `:name`
placeholders, and translated per dialect.

No plaintext PII is written: entity payloads are Fernet-encrypted with the
session key; fingerprints and audit value hashes are keyed HMACs.

Connections run in autocommit mode; every multi-statement write is wrapped in
`self._tx()`. That makes "forgot to commit" — an idle transaction holding a
lock that blocks every other connection — impossible by construction.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Sequence
from contextlib import AbstractContextManager
from typing import Any

SCHEMA_VERSION = 3

# {blob} {real} {serial} are filled in per dialect.
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT PRIMARY KEY,
    key_check   TEXT NOT NULL,
    turn        INTEGER NOT NULL DEFAULT 0,
    version     INTEGER NOT NULL DEFAULT 0,
    created_at  {real} NOT NULL,
    updated_at  {real} NOT NULL
);

CREATE TABLE IF NOT EXISTS entities (
    session_id   TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    alias        TEXT NOT NULL,
    entity_type  TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    payload      {blob} NOT NULL,
    mentions     INTEGER NOT NULL DEFAULT 0,
    merged_into  TEXT,
    updated_at   {real} NOT NULL,
    PRIMARY KEY (session_id, alias)
);

CREATE TABLE IF NOT EXISTS fingerprints (
    session_id   TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    entity_type  TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    alias        TEXT NOT NULL,
    PRIMARY KEY (session_id, entity_type, fingerprint)
);

CREATE TABLE IF NOT EXISTS counters (
    session_id  TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    prefix      TEXT NOT NULL,
    value       INTEGER NOT NULL,
    PRIMARY KEY (session_id, prefix)
);

CREATE TABLE IF NOT EXISTS audit (
    id                {serial},
    audit_id          TEXT NOT NULL,
    ts                {real} NOT NULL,
    session_id        TEXT NOT NULL,
    hook_type         TEXT NOT NULL,
    policy            TEXT,
    source            TEXT,
    line              INTEGER,
    entity_type       TEXT NOT NULL,
    value_hash        TEXT NOT NULL,
    alias             TEXT,
    action            TEXT NOT NULL,
    decision          TEXT,
    confidence        {real},
    resolution_score  {real},
    candidate_alias   TEXT,
    tier              INTEGER,
    detector          TEXT
);
CREATE INDEX IF NOT EXISTS audit_session ON audit(session_id, decision);
CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);

CREATE TABLE IF NOT EXISTS runs (
    id           TEXT PRIMARY KEY,
    ts           {real} NOT NULL,
    session_id   TEXT NOT NULL,
    source       TEXT NOT NULL,
    origin       TEXT NOT NULL,
    actor        TEXT,
    hook_type    TEXT NOT NULL,
    format       TEXT,
    status       TEXT NOT NULL,
    records      INTEGER NOT NULL DEFAULT 0,
    findings     INTEGER NOT NULL DEFAULT 0,
    max_risk     {real} NOT NULL DEFAULT 0,
    duration_s   {real} NOT NULL DEFAULT 0,
    output_path  TEXT,
    report       TEXT
);
CREATE INDEX IF NOT EXISTS runs_ts ON runs(ts);

CREATE TABLE IF NOT EXISTS usage_daily (
    day       TEXT NOT NULL,
    origin    TEXT NOT NULL,
    requests  INTEGER NOT NULL DEFAULT 0,
    records   INTEGER NOT NULL DEFAULT 0,
    findings  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, origin)
);

CREATE TABLE IF NOT EXISTS reviews (
    session_id  TEXT NOT NULL,
    alias       TEXT NOT NULL,
    candidate   TEXT NOT NULL,
    decision    TEXT NOT NULL,
    actor       TEXT,
    ts          {real} NOT NULL,
    PRIMARY KEY (session_id, alias, candidate)
);

CREATE TABLE IF NOT EXISTS api_keys (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    role        TEXT NOT NULL,
    key_hash    TEXT NOT NULL UNIQUE,
    prefix      TEXT NOT NULL,
    created_at  {real} NOT NULL,
    last_used   {real},
    revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id          {serial},
    ts          {real} NOT NULL,
    session_id  TEXT,
    kind        TEXT NOT NULL,
    detail      TEXT NOT NULL
);
"""

# Upgrades for databases created by older versions: {target_version: [statements]}.
MIGRATIONS: dict[int, list[str]] = {
    3: ["ALTER TABLE sessions ADD COLUMN version INTEGER NOT NULL DEFAULT 0"],
}

AUDIT_COLS = (
    "audit_id", "ts", "session_id", "hook_type", "policy", "source", "line", "entity_type",
    "value_hash", "alias", "action", "decision", "confidence", "resolution_score",
    "candidate_alias", "tier", "detector",
)
RUN_COLS = (
    "id", "ts", "session_id", "source", "origin", "actor", "hook_type", "format", "status",
    "records", "findings", "max_risk", "duration_s", "output_path", "report",
)


class SQLStore:
    """Shared implementation. Subclasses provide the primitives marked below."""

    dialect = "sql"
    # SQL expression turning the epoch-seconds column `ts` into 'YYYY-MM-DD' (local time).
    day_expr = ""

    # ------------------------------------------------------------ primitives

    def _rows(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> list[dict[str, Any]]:
        raise NotImplementedError

    def _exec(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> int:
        raise NotImplementedError

    def _exec_many(self, sql: str, seq: Sequence[Sequence[Any] | dict[str, Any]]) -> None:
        raise NotImplementedError

    def _tx(self) -> AbstractContextManager[None]:
        raise NotImplementedError

    def session_lock(self, session_id: str) -> AbstractContextManager[None]:
        """Exclusive lock on one session across threads, processes and (Postgres) hosts."""
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    def _one(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> dict[str, Any] | None:
        rows = self._rows(sql, params)
        return rows[0] if rows else None

    def _scalar(self, sql: str, params: Sequence[Any] | dict[str, Any] = ()) -> Any:
        row = self._one(sql, params)
        return next(iter(row.values())) if row else None

    def _schema_sql(self) -> str:
        raise NotImplementedError

    def _schema_version(self) -> int:
        raise NotImplementedError

    def _apply_schema(self) -> None:
        current = self._schema_version()
        if current >= SCHEMA_VERSION:
            return
        with self._tx():
            if current:
                for version in sorted(MIGRATIONS):
                    if current < version:
                        for stmt in MIGRATIONS[version]:
                            self._exec(stmt)
            for stmt in self._schema_sql().split(";"):
                if stmt.strip():
                    self._exec(stmt)
            self._exec(
                "INSERT INTO meta(key, value) VALUES ('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(SCHEMA_VERSION),),
            )

    # ------------------------------------------------------------ meta

    def get_meta(self, key: str) -> str | None:
        return self._scalar("SELECT value FROM meta WHERE key = ?", (key,))

    def set_meta_if_absent(self, key: str, value: str) -> bool:
        return bool(self._exec("INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING", (key, value)))

    def set_meta(self, key: str, value: str) -> None:
        self._exec("INSERT INTO meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                   (key, value))

    # ------------------------------------------------------------ sessions

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        return self._one("SELECT * FROM sessions WHERE session_id = ?", (session_id,))

    def create_session(self, session_id: str, key_check: str) -> None:
        now = time.time()
        self._exec(
            "INSERT INTO sessions(session_id, key_check, turn, version, created_at, updated_at) "
            "VALUES (?, ?, 0, 0, ?, ?) ON CONFLICT(session_id) DO NOTHING",
            (session_id, key_check, now, now),
        )

    def session_version(self, session_id: str) -> int:
        return int(self._scalar("SELECT version FROM sessions WHERE session_id = ?", (session_id,)) or 0)

    def set_session_turn(self, session_id: str, turn: int) -> None:
        self._exec(
            "UPDATE sessions SET turn = ?, updated_at = ? WHERE session_id = ?",
            (turn, time.time(), session_id),
        )

    def list_sessions(self) -> list[dict[str, Any]]:
        return self._rows(
            """
            SELECT s.session_id, s.turn, s.created_at, s.updated_at,
                   (SELECT COUNT(*) FROM entities e
                     WHERE e.session_id = s.session_id AND e.merged_into IS NULL) AS entities,
                   (SELECT COUNT(*) FROM audit a WHERE a.session_id = s.session_id) AS audit_rows,
                   (SELECT COUNT(*) FROM audit a
                     WHERE a.session_id = s.session_id AND a.decision = 'DEFERRED') AS deferred
            FROM sessions s ORDER BY s.updated_at DESC
            """
        )

    def delete_session(self, session_id: str) -> int:
        with self._tx():
            n = self._exec("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            for table in ("audit", "reviews", "runs"):
                self._exec(f"DELETE FROM {table} WHERE session_id = ?", (session_id,))
        return n

    def entity_summary(self, session_id: str) -> list[dict[str, Any]]:
        return self._rows(
            "SELECT alias, entity_type, mentions, merged_into FROM entities "
            "WHERE session_id = ? ORDER BY entity_type, alias",
            (session_id,),
        )

    # ------------------------------------------------------------ registry

    def load_entities(self, session_id: str) -> list[dict[str, Any]]:
        rows = self._rows(
            "SELECT alias, entity_type, fingerprint, payload, mentions, merged_into "
            "FROM entities WHERE session_id = ?",
            (session_id,),
        )
        for r in rows:
            r["payload"] = bytes(r["payload"])
        return rows

    def load_fingerprints(self, session_id: str) -> list[tuple[str, str, str]]:
        rows = self._rows(
            "SELECT entity_type, fingerprint, alias FROM fingerprints WHERE session_id = ?", (session_id,)
        )
        return [(r["entity_type"], r["fingerprint"], r["alias"]) for r in rows]

    def load_counters(self, session_id: str) -> dict[str, int]:
        rows = self._rows("SELECT prefix, value FROM counters WHERE session_id = ?", (session_id,))
        return {r["prefix"]: r["value"] for r in rows}

    def save_registry(
        self,
        session_id: str,
        entities: Iterable[dict[str, Any]],
        fingerprints: Iterable[tuple[str, str, str]],
        counters: dict[str, int],
        turn: int,
        version: int | None = None,
    ) -> None:
        now = time.time()
        ents = [{**e, "session_id": session_id, "updated_at": now} for e in entities]
        fps = [(session_id, t, f, a) for t, f, a in fingerprints]
        with self._tx():
            if ents:
                self._exec_many(
                    """
                    INSERT INTO entities(session_id, alias, entity_type, fingerprint, payload,
                                         mentions, merged_into, updated_at)
                    VALUES (:session_id, :alias, :entity_type, :fingerprint, :payload,
                            :mentions, :merged_into, :updated_at)
                    ON CONFLICT(session_id, alias) DO UPDATE SET
                        payload = excluded.payload, mentions = excluded.mentions,
                        merged_into = excluded.merged_into, updated_at = excluded.updated_at
                    """,
                    ents,
                )
            if fps:
                self._exec_many(
                    "INSERT INTO fingerprints(session_id, entity_type, fingerprint, alias) "
                    "VALUES (?, ?, ?, ?) ON CONFLICT(session_id, entity_type, fingerprint) "
                    "DO UPDATE SET alias = excluded.alias",
                    fps,
                )
            if counters:
                self._exec_many(
                    "INSERT INTO counters(session_id, prefix, value) VALUES (?, ?, ?) "
                    "ON CONFLICT(session_id, prefix) DO UPDATE SET value = excluded.value",
                    [(session_id, p, v) for p, v in counters.items()],
                )
            if version is None:
                self._exec("UPDATE sessions SET turn = ?, updated_at = ? WHERE session_id = ?",
                           (turn, now, session_id))
            else:
                self._exec("UPDATE sessions SET turn = ?, version = ?, updated_at = ? WHERE session_id = ?",
                           (turn, version, now, session_id))

    # ------------------------------------------------------------ audit + events

    def insert_audit(self, rows: Sequence[dict[str, Any]]) -> None:
        if not rows:
            return
        with self._tx():
            self._exec_many(
                f"INSERT INTO audit({', '.join(AUDIT_COLS)}) VALUES ({', '.join(':' + c for c in AUDIT_COLS)})",
                [{c: r.get(c) for c in AUDIT_COLS} for r in rows],
            )

    def query_audit(
        self,
        session_id: str | None = None,
        decision: str | None = None,
        entity_type: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        where, args = [], []
        for col, val in (("session_id", session_id), ("decision", decision), ("entity_type", entity_type)):
            if val is not None:
                where.append(f"{col} = ?")
                args.append(val)
        sql = "SELECT * FROM audit" + (" WHERE " + " AND ".join(where) if where else "")
        return self._rows(sql + " ORDER BY id DESC LIMIT ? OFFSET ?", [*args, limit, offset])

    def log_event(self, session_id: str, kind: str, detail: dict[str, Any]) -> None:
        self._exec(
            "INSERT INTO events(ts, session_id, kind, detail) VALUES (?, ?, ?, ?)",
            (time.time(), session_id, kind, json.dumps(detail, sort_keys=True)),
        )

    def query_events(self, session_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if session_id is None:
            rows = self._rows("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        else:
            rows = self._rows("SELECT * FROM events WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                              (session_id, limit))
        return [{**r, "detail": json.loads(r["detail"])} for r in rows]

    # ------------------------------------------------------------ runs + usage

    def insert_run(self, run: dict[str, Any]) -> None:
        row = {c: run.get(c) for c in RUN_COLS}
        if isinstance(row["report"], dict):
            row["report"] = json.dumps(row["report"])
        self._exec(f"INSERT INTO runs({', '.join(RUN_COLS)}) VALUES ({', '.join(':' + c for c in RUN_COLS)})", row)

    @staticmethod
    def _run(row: dict[str, Any]) -> dict[str, Any]:
        row["report"] = json.loads(row["report"]) if row.get("report") else None
        return row

    def query_runs(self, limit: int = 50, session_id: str | None = None) -> list[dict[str, Any]]:
        if session_id:
            rows = self._rows("SELECT * FROM runs WHERE session_id = ? ORDER BY ts DESC LIMIT ?", (session_id, limit))
        else:
            rows = self._rows("SELECT * FROM runs ORDER BY ts DESC LIMIT ?", (limit,))
        return [self._run(r) for r in rows]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self._one("SELECT * FROM runs WHERE id = ?", (run_id,))
        return self._run(row) if row else None

    def add_usage(self, origin: str, records: int, findings: int, requests: int = 1) -> None:
        self._exec(
            "INSERT INTO usage_daily(day, origin, requests, records, findings) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(day, origin) DO UPDATE SET requests = usage_daily.requests + excluded.requests, "
            "records = usage_daily.records + excluded.records, findings = usage_daily.findings + excluded.findings",
            (time.strftime("%Y-%m-%d"), origin, requests, records, findings),
        )

    # ------------------------------------------------------------ dashboard

    def stats(self, days: int = 30) -> dict[str, Any]:
        since = time.time() - days * 86400
        since_day = time.strftime("%Y-%m-%d", time.localtime(since))

        def grouped(col: str, extra: str = "") -> list[dict[str, Any]]:
            return self._rows(
                f"SELECT {col} AS k, COUNT(*) AS n FROM audit WHERE ts >= ? {extra} GROUP BY {col} ORDER BY n DESC",
                (since,),
            )

        by_type = grouped("entity_type")
        by_day = self._rows(
            f"SELECT {self.day_expr} AS d, COUNT(*) AS n FROM audit WHERE ts >= ? GROUP BY d ORDER BY d", (since,)
        )
        usage = self._rows(
            "SELECT day, SUM(requests) AS requests, SUM(records) AS records FROM usage_daily "
            "WHERE day >= ? GROUP BY day ORDER BY day",
            (since_day,),
        )
        by_origin = self._rows(
            "SELECT origin, SUM(requests) AS requests, SUM(records) AS records FROM usage_daily "
            "WHERE day >= ? GROUP BY origin ORDER BY records DESC",
            (since_day,),
        )
        risk = self._one(
            "SELECT MAX(max_risk) AS mx, AVG(max_risk) AS mean FROM runs WHERE ts >= ? AND status = 'ok'", (since,)
        ) or {}
        return {
            "days": days,
            "findings": sum(r["n"] for r in by_type),
            "records": sum(int(r["records"] or 0) for r in usage),
            "requests": sum(int(r["requests"] or 0) for r in usage),
            "sessions": int(self._scalar("SELECT COUNT(*) AS n FROM sessions") or 0),
            "entities": int(self._scalar("SELECT COUNT(*) AS n FROM entities WHERE merged_into IS NULL") or 0),
            "blocked_runs": int(self._scalar(
                "SELECT COUNT(*) AS n FROM runs WHERE ts >= ? AND status = 'blocked'", (since,)) or 0),
            "max_risk": round(float(risk.get("mx") or 0), 1),
            "mean_run_risk": round(float(risk.get("mean") or 0), 1),
            "by_type": [{"key": r["k"], "count": r["n"]} for r in by_type],
            "by_action": [{"key": r["k"], "count": r["n"]} for r in grouped("action")],
            "by_decision": [{"key": r["k"], "count": r["n"]} for r in grouped("decision", "AND decision IS NOT NULL")],
            "by_tier": [{"key": f"tier{r['k']}", "count": r["n"]} for r in grouped("tier")],
            "by_origin": [{"key": r["origin"], "requests": int(r["requests"] or 0), "records": int(r["records"] or 0)}
                          for r in by_origin],
            "by_day": [{"day": r["d"], "findings": r["n"]} for r in by_day],
            "records_by_day": [{"day": r["day"], "records": int(r["records"] or 0)} for r in usage],
        }

    def risk_analytics(self, days: int = 30) -> dict[str, Any]:
        """Exposure trends for the risk page: per day, per source, per hook, blocked runs."""
        since = time.time() - days * 86400
        per_day = self._rows(
            f"SELECT {self.day_expr} AS d, MAX(max_risk) AS peak, AVG(max_risk) AS mean, COUNT(*) AS runs "
            "FROM runs WHERE ts >= ? AND status = 'ok' GROUP BY d ORDER BY d",
            (since,),
        )
        sources = self._rows(
            "SELECT source, origin, COUNT(*) AS runs, SUM(records) AS records, SUM(findings) AS findings, "
            "MAX(max_risk) AS peak, AVG(max_risk) AS mean, MAX(ts) AS last_ts "
            "FROM runs WHERE ts >= ? AND status = 'ok' GROUP BY source, origin ORDER BY peak DESC, findings DESC "
            "LIMIT 20",
            (since,),
        )
        hooks = self._rows(
            "SELECT hook_type AS k, COUNT(*) AS n FROM audit WHERE ts >= ? GROUP BY hook_type ORDER BY n DESC",
            (since,),
        )
        blocked = self._rows(
            "SELECT id, ts, session_id, source, origin, hook_type, report FROM runs "
            "WHERE ts >= ? AND status = 'blocked' ORDER BY ts DESC LIMIT 20",
            (since,),
        )
        residual = self._scalar(
            "SELECT COUNT(*) AS n FROM audit WHERE ts >= ? AND action = 'allow'", (since,)
        )
        return {
            "days": days,
            "per_day": [
                {"day": r["d"], "peak": round(float(r["peak"] or 0), 1), "mean": round(float(r["mean"] or 0), 1),
                 "runs": r["runs"]}
                for r in per_day
            ],
            "sources": [{**r, "peak": round(float(r["peak"] or 0), 1), "mean": round(float(r["mean"] or 0), 1),
                         "records": int(r["records"] or 0), "findings": int(r["findings"] or 0)} for r in sources],
            "by_hook": [{"key": r["k"], "count": r["n"]} for r in hooks],
            "blocked": [self._run(r) for r in blocked],
            "allowed_in_clear": int(residual or 0),
        }

    # ------------------------------------------------------------ reviews

    def pending_reviews(self, limit: int = 200) -> list[dict[str, Any]]:
        return self._rows(
            """
            SELECT a.session_id, a.alias, a.candidate_alias AS candidate, MIN(a.entity_type) AS entity_type,
                   MAX(a.resolution_score) AS score, COUNT(*) AS occurrences, MAX(a.ts) AS last_seen,
                   MIN(a.source) AS source, MIN(a.line) AS line
            FROM audit a
            JOIN entities e ON e.session_id = a.session_id AND e.alias = a.alias
            LEFT JOIN reviews r ON r.session_id = a.session_id AND r.alias = a.alias
                               AND r.candidate = a.candidate_alias
            WHERE a.decision = 'DEFERRED' AND a.candidate_alias IS NOT NULL
              AND r.decision IS NULL AND e.merged_into IS NULL
            GROUP BY a.session_id, a.alias, a.candidate_alias
            ORDER BY last_seen DESC LIMIT ?
            """,
            (limit,),
        )

    def record_review(self, session_id: str, alias: str, candidate: str, decision: str, actor: str | None) -> None:
        self._exec(
            "INSERT INTO reviews(session_id, alias, candidate, decision, actor, ts) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(session_id, alias, candidate) DO UPDATE SET decision = excluded.decision, "
            "actor = excluded.actor, ts = excluded.ts",
            (session_id, alias, candidate, decision, actor, time.time()),
        )

    # ------------------------------------------------------------ api keys

    def create_api_key(self, key_id: str, name: str, role: str, key_hash: str, prefix: str) -> None:
        self._exec(
            "INSERT INTO api_keys(id, name, role, key_hash, prefix, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (key_id, name, role, key_hash, prefix, time.time()),
        )

    def find_api_key(self, key_hash: str) -> dict[str, Any] | None:
        row = self._one("SELECT * FROM api_keys WHERE key_hash = ? AND revoked = 0", (key_hash,))
        if row is None:
            return None
        now = time.time()
        if not row["last_used"] or now - row["last_used"] > 60:  # avoid a write on every request
            self._exec("UPDATE api_keys SET last_used = ? WHERE id = ?", (now, row["id"]))
        return row

    def list_api_keys(self) -> list[dict[str, Any]]:
        return self._rows(
            "SELECT id, name, role, prefix, created_at, last_used, revoked FROM api_keys ORDER BY created_at"
        )

    def revoke_api_key(self, key_id: str) -> int:
        return self._exec("UPDATE api_keys SET revoked = 1 WHERE id = ? AND revoked = 0", (key_id,))

    def count_admin_keys(self) -> int:
        return int(self._scalar("SELECT COUNT(*) AS n FROM api_keys WHERE role = 'admin' AND revoked = 0") or 0)

    # ------------------------------------------------------------ context manager

    def __enter__(self) -> SQLStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
