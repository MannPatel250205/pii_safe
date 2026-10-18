"""PII-Safe web service: REST API + customer dashboard.

Note: no `from __future__ import annotations` here — FastAPI must resolve the
Annotated dependency aliases defined inside create_app().

    piisafe serve --port 8765

Everything here is a thin layer over PIISafeGuard; the CLI and the web app
share the same store, so CLI runs appear on the dashboard and vice versa.
"""


import csv
import os
import re
import tempfile
import threading
import time
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from importlib import resources
from pathlib import Path
from typing import Annotated, Any

import yaml
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from piisafe import __version__
from piisafe.exceptions import (
    AliasNotFoundError,
    KeyMismatchError,
    PIISafeError,
    PolicyBlockError,
    PolicyError,
    SessionNotFoundError,
)
from piisafe.guard import PIISafeGuard
from piisafe.io import FORMATS, BlockedAt, Processor, detect_format
from piisafe.normalize import normalize_text
from piisafe.policy import KNOWN_HOOKS, Policy
from piisafe.runs import record_run
from piisafe.server.auth import ROLES, authenticate, create_api_key
from piisafe.server.pool import GuardPool
from piisafe.storage import SQLStore, open_store

SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
MAX_TEXT = 1_000_000  # characters per /api/sanitize call
_OUTPUT_EXT = {"text": ".txt", "jsonl": ".jsonl", "json": ".json", "csv": ".csv"}


# ======================================================================= models


class SanitizeIn(BaseModel):
    text: str = Field(max_length=MAX_TEXT)
    session_id: str | None = None
    hook: str = "on_prompt"
    policy_id: str | None = None
    on_block: str = Field("fail", pattern="^(fail|redact)$")


class ScanIn(BaseModel):
    text: str = Field(max_length=MAX_TEXT)
    hook: str = "on_prompt"
    policy_id: str | None = None


class RestoreIn(BaseModel):
    session_id: str
    text: str = Field(max_length=MAX_TEXT)


class ReidentifyIn(BaseModel):
    session_id: str
    aliases: list[str] = Field(max_length=500)


class ReviewIn(BaseModel):
    session_id: str
    alias: str
    candidate: str
    decision: str = Field(pattern="^(merge|keep)$")


class PolicyIn(BaseModel):
    yaml: str = Field(max_length=200_000)


class KeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    role: str = Field(pattern="^(analyst|admin)$")


# ======================================================================= policy


class PolicyManager:
    """The active policy, shared by every replica.

    Precedence: an explicit --policy file (edits are written back to it), else the
    policy stored in the database (edited from the dashboard), else the built-in
    default. Replicas notice a policy saved elsewhere within RELOAD_S seconds.
    """

    META_YAML = "policy.yaml"
    META_VERSION = "policy.version"
    RELOAD_S = 5.0

    def __init__(self, open_db: Callable[[], Any], explicit: Path | None, legacy_file: Path | None = None) -> None:
        self._open_db = open_db
        self.file = explicit
        self._lock = threading.Lock()
        self._version: str | None = None
        self._checked = 0.0
        self.on_change: Callable[[], None] = lambda: None
        if self.file is None and legacy_file is not None and legacy_file.exists():
            # v0.1 saved dashboard edits to <state>/policy.yaml: import once.
            with self._open_db() as st:
                if st.get_meta(self.META_YAML) is None:
                    text = legacy_file.read_text("utf-8")
                    self.validate(text)
                    st.set_meta(self.META_YAML, text)
                    st.set_meta(self.META_VERSION, str(time.time()))
        self._policy = self._load()

    @property
    def location(self) -> str:
        return str(self.file) if self.file else "database (meta: policy.yaml)"

    def _load(self) -> Policy:
        if self.file is not None:
            return Policy.load(self.file)
        with self._open_db() as st:
            text = st.get_meta(self.META_YAML)
            self._version = st.get_meta(self.META_VERSION)
        return Policy.from_dict(yaml.safe_load(text), source="<database>") if text else Policy.default()

    def get(self) -> Policy:
        if self.file is None and time.monotonic() - self._checked > self.RELOAD_S:
            self._checked = time.monotonic()
            with self._open_db() as st:
                version = st.get_meta(self.META_VERSION)
            if version != self._version:
                with self._lock:
                    self._policy = self._load()
                self.on_change()
        return self._policy

    def text(self) -> str:
        if self.file is not None:
            return self.file.read_text("utf-8")
        with self._open_db() as st:
            text = st.get_meta(self.META_YAML)
        return text or resources.files("piisafe").joinpath("policies/default.yaml").read_text("utf-8")

    @staticmethod
    def validate(text: str) -> Policy:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyError(f"invalid YAML: {exc}") from exc
        return Policy.from_dict(data, source="<editor>")

    def save(self, text: str) -> Policy:
        pol = self.validate(text)
        with self._lock:
            if self.file is not None:
                fd, tmp = tempfile.mkstemp(dir=self.file.parent, prefix=".policy.", suffix=".yaml")
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(text)
                os.replace(tmp, self.file)
            else:
                with self._open_db() as st:
                    st.set_meta(self.META_YAML, text)
                    st.set_meta(self.META_VERSION, str(time.time()))
            self._policy = self._load()
        return pol


# ======================================================================= helpers


def _preview(value: str) -> str:
    if len(value) <= 2:
        return "•" * len(value)
    keep = max(1, len(value) // 5)
    return value[:keep] + "•" * min(len(value) - 2 * keep, 10) + value[-keep:]


def _check_session(session_id: str) -> str:
    if not SESSION_RE.match(session_id):
        raise HTTPException(422, "session_id: 1-64 chars of letters, digits and . _ : -")
    return session_id


def _check_hook(hook: str) -> str:
    if not re.match(r"^[a-z][a-z0-9_]{0,40}$", hook):
        raise HTTPException(422, "invalid hook")
    return hook


def _blocked(exc: PolicyBlockError, line: int | None = None) -> HTTPException:
    return HTTPException(
        409,
        {"error": "blocked", "message": str(exc), "entity_types": exc.entity_types,
         "policy": exc.policy_name, "hook": exc.hook_type, "line": line},
    )


# ======================================================================= app


def create_app(
    state_dir: str | Path,
    policy_path: str | Path | None = None,
    max_upload_mb: int = 50,
    database_url: str | None = None,
    key_provider: str | None = None,
) -> FastAPI:
    """Build the app. database_url / key_provider default to $PIISAFE_DATABASE_URL / $PIISAFE_KEY_PROVIDER."""
    state = Path(state_dir).expanduser()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    outputs = state / "outputs"
    uploads = state / "uploads"
    for d in (outputs, uploads):
        d.mkdir(exist_ok=True, mode=0o700)

    @contextmanager
    def db() -> Iterator[SQLStore]:
        store = open_store(database_url, state)
        try:
            yield store
        finally:
            store.close()

    with db():
        pass  # create / migrate the schema up front

    policies = PolicyManager(db, Path(policy_path) if policy_path else None, legacy_file=state / "policy.yaml")
    pool = GuardPool(state, policies.get, database_url=database_url, key_provider=key_provider)
    policies.on_change = pool.invalidate
    max_upload = max_upload_mb * 1024 * 1024

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        pool.clear()

    app = FastAPI(title="PII-Safe", version=__version__, docs_url="/api/docs", redoc_url=None,
                  openapi_url="/api/openapi.json", lifespan=lifespan)
    app.state.pool = pool
    app.state.policies = policies

    def session_exists(sid: str) -> bool:
        with db() as s:
            return s.get_session(sid) is not None

    # ------------------------------------------------------------------ auth

    def current_user(request: Request) -> dict[str, Any]:
        header = request.headers.get("authorization", "")
        key = header[7:].strip() if header.lower().startswith("bearer ") else ""
        if not key:
            raise HTTPException(401, "missing API key", headers={"WWW-Authenticate": "Bearer"})
        with db() as s:
            user = authenticate(s, key)
        if user is None:
            raise HTTPException(401, "invalid or revoked API key", headers={"WWW-Authenticate": "Bearer"})
        return user

    def admin(user: Annotated[dict, Depends(current_user)]) -> dict[str, Any]:
        if user["role"] != "admin":
            raise HTTPException(403, "admin role required")
        return user

    User = Annotated[dict, Depends(current_user)]
    Admin = Annotated[dict, Depends(admin)]

    # ------------------------------------------------------------ middleware

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # noqa: ANN001, ANN202
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith("/api/docs"):
            return response
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(PIISafeError)
    async def piisafe_error(_: Request, exc: PIISafeError) -> JSONResponse:
        status = 404 if isinstance(exc, (SessionNotFoundError, AliasNotFoundError)) else 400
        if isinstance(exc, KeyMismatchError):
            status = 403
        return JSONResponse({"detail": str(exc)}, status_code=status)

    # ------------------------------------------------------------------ info

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @app.get("/api/me")
    def me(user: User) -> dict[str, Any]:
        pol = policies.get()
        return {
            "name": user["name"], "role": user["role"], "version": __version__,
            "hooks": list(KNOWN_HOOKS), "policy_ids": pol.policy_names(), "formats": list(FORMATS),
            "max_upload_mb": max_upload_mb,
        }

    # -------------------------------------------------------------- sanitise

    @app.post("/api/sanitize")
    def sanitize(body: SanitizeIn, user: User) -> dict[str, Any]:
        sid = _check_session(body.session_id or f"api-{time.strftime('%Y%m%d')}")
        hook = _check_hook(body.hook)
        with pool.session(sid) as guard:
            guard.block_mode = "redact" if body.on_block == "redact" else "raise"
            try:
                r = guard.sanitize(body.text, hook, policy_id=body.policy_id, source="api")
            except PolicyBlockError as exc:
                raise _blocked(exc) from exc
            guard.store.add_usage("api", 1, len(r.findings))  # type: ignore[attr-defined]
        out = r.to_dict()
        out["latency_ms"] = r.latency_ms
        return out

    @app.post("/api/sanitize/file")
    def sanitize_file(
        user: User,
        file: Annotated[UploadFile, File()],
        session_id: Annotated[str | None, Form()] = None,
        hook: Annotated[str, Form()] = "on_prompt",
        policy_id: Annotated[str | None, Form()] = None,
        fmt: Annotated[str, Form(alias="format")] = "auto",
        on_block: Annotated[str, Form()] = "fail",
    ) -> dict[str, Any]:
        if on_block not in ("fail", "drop", "redact"):
            raise HTTPException(422, "on_block must be fail, drop or redact")
        if fmt not in ("auto", *FORMATS):
            raise HTTPException(422, f"format must be auto or one of {FORMATS}")
        name = Path(file.filename or "upload.txt").name
        sid = _check_session(session_id or f"web-{time.strftime('%Y%m%d-%H%M%S')}")
        hook = _check_hook(hook)
        kind = detect_format(name, fmt)
        run_id = uuid.uuid4().hex[:16]
        tmp_in = uploads / f"{run_id}.in"
        size = 0
        with open(tmp_in, "wb") as fh:
            while chunk := file.file.read(1024 * 1024):
                size += len(chunk)
                if size > max_upload:
                    fh.close()
                    tmp_in.unlink(missing_ok=True)
                    raise HTTPException(413, f"file larger than {max_upload_mb} MB")
                fh.write(chunk)
        out_path = outputs / f"{run_id}{_OUTPUT_EXT[kind]}"
        t0 = time.perf_counter()
        try:
            with pool.session(sid) as guard:
                guard.block_mode = "redact" if on_block == "redact" else "raise"
                try:
                    with open(tmp_in, encoding="utf-8", errors="surrogateescape", newline="") as src, \
                         open(out_path, "w", encoding="utf-8", errors="surrogateescape", newline="") as dst:
                        stats = Processor(guard, hook, policy_id, on_block, name).run(kind, src, dst)
                except BlockedAt as exc:
                    out_path.unlink(missing_ok=True)
                    record_run(guard.store, session_id=sid, source=name, origin="web", hook=hook, fmt=kind,
                               status="blocked", stats=None, duration_s=time.perf_counter() - t0,
                               actor=user["name"], run_id=run_id,
                               extra={"blocked_line": exc.line, "blocked_types": exc.error.entity_types})
                    raise _blocked(exc.error, exc.line) from exc
                except (ValueError, UnicodeError, csv.Error) as exc:  # bad JSON / CSV
                    out_path.unlink(missing_ok=True)
                    raise HTTPException(422, f"could not parse {kind} input: {exc}") from exc
                elapsed = time.perf_counter() - t0
                record_run(guard.store, session_id=sid, source=name, origin="web", hook=hook, fmt=kind,
                           status="ok", stats=stats, duration_s=elapsed, actor=user["name"],
                           output_path=str(out_path), run_id=run_id,
                           extra={"latency": guard.latency.summary()})
        finally:
            tmp_in.unlink(missing_ok=True)
        with open(out_path, encoding="utf-8", errors="replace") as fh:
            preview = fh.read(20_000)
        return {"run_id": run_id, "session_id": sid, "format": kind, "file": name,
                "duration_s": round(elapsed, 3), "summary": stats.to_dict(), "preview": preview,
                "download": f"/api/runs/{run_id}/output"}

    @app.post("/api/scan")
    def scan(body: ScanIn, user: User) -> dict[str, Any]:
        hook = _check_hook(body.hook)
        guard = PIISafeGuard(policies.get(), "scan", ephemeral=True, block_mode="redact")
        try:
            rows = []
            for n, line in enumerate(body.text.splitlines() or [""], 1):
                r = guard.sanitize(line, hook, policy_id=body.policy_id)
                text = normalize_text(line)
                for f in r.findings:
                    rows.append({"line": n, **f.to_dict(), "preview": _preview(text[f.start:f.end])})
        finally:
            guard.close()
        return {"findings": rows, "count": len(rows)}

    # ------------------------------------------------------------- runs

    @app.get("/api/runs")
    def runs(user: User, limit: int = Query(50, le=500), session_id: str | None = None) -> list[dict]:
        with db() as s:
            items = s.query_runs(limit, session_id)
        for r in items:
            r["has_output"] = bool(r.pop("output_path", None)) and r["status"] == "ok"
        return items

    @app.get("/api/runs/{run_id}/output")
    def run_output(run_id: str, user: User) -> FileResponse:
        with db() as s:
            run = s.get_run(run_id)
        if run is None or not run.get("output_path"):
            raise HTTPException(404, "no output for this run")
        path = Path(run["output_path"]).resolve()
        if path.parent != outputs.resolve() or not path.exists():
            raise HTTPException(404, "output no longer available")
        stem = Path(run["source"]).stem or "output"
        return FileResponse(path, filename=f"{stem}.sanitized{path.suffix}", media_type="application/octet-stream")

    # ------------------------------------------------------------- dashboard

    @app.get("/api/stats")
    def stats(user: User, days: int = Query(30, ge=1, le=365)) -> dict[str, Any]:
        with db() as s:
            data = s.stats(days)
            data["pending_reviews"] = len(s.pending_reviews(1000))
            data["recent_runs"] = s.query_runs(8)
        for r in data["recent_runs"]:
            r.pop("output_path", None)
            r.pop("report", None)
        return data

    @app.get("/api/sessions")
    def sessions(user: User) -> list[dict[str, Any]]:
        with db() as s:
            return s.list_sessions()

    @app.get("/api/sessions/{session_id}")
    def session_detail(session_id: str, user: User) -> dict[str, Any]:
        with db() as s:
            info = s.get_session(session_id)
            if info is None:
                raise HTTPException(404, "session not found")
            info.pop("key_check", None)
            return {
                **info,
                "entities": s.entity_summary(session_id),
                "runs": [
                    {k: v for k, v in r.items() if k not in ("output_path", "report")}
                    for r in s.query_runs(50, session_id)
                ],
            }

    @app.delete("/api/sessions/{session_id}")
    def delete_session(session_id: str, user: Admin) -> dict[str, Any]:
        pool.drop(session_id)
        with db() as s:
            for r in s.query_runs(10_000, session_id):
                if r.get("output_path"):
                    Path(r["output_path"]).unlink(missing_ok=True)
            n = s.delete_session(session_id)
            s.log_event(session_id, "delete_session", {"by": user["name"]})
        if not n:
            raise HTTPException(404, "session not found")
        return {"deleted": session_id}

    @app.get("/api/audit")
    def audit(
        user: User,
        session_id: str | None = None,
        decision: str | None = None,
        entity_type: str | None = None,
        limit: int = Query(100, le=1000),
        offset: int = Query(0, ge=0),
    ) -> list[dict[str, Any]]:
        with db() as s:
            rows = s.query_audit(session_id, decision, entity_type, limit, offset)
        for r in rows:
            r.pop("value_hash", None)
        return rows

    @app.get("/api/events")
    def events(user: Admin, session_id: str | None = None, limit: int = Query(100, le=1000)) -> list[dict]:
        with db() as s:
            return s.query_events(session_id, limit)

    # ------------------------------------------------------------- review

    @app.get("/api/reviews")
    def reviews(user: User) -> list[dict[str, Any]]:
        with db() as s:
            return s.pending_reviews()

    @app.post("/api/reviews")
    def review(body: ReviewIn, user: User) -> dict[str, Any]:
        with pool.session(body.session_id, create=False, store_exists=session_exists) as guard:
            if body.decision == "merge":
                guard.merge(body.alias, body.candidate)
            guard.store.record_review(  # type: ignore[attr-defined]
                body.session_id, body.alias, body.candidate, body.decision, user["name"]
            )
            guard.store.log_event(body.session_id, f"review_{body.decision}",
                                  {"alias": body.alias, "candidate": body.candidate, "by": user["name"]})
        return {"ok": True}

    # ------------------------------------------------------ re-identification

    @app.post("/api/restore")
    def restore(body: RestoreIn, user: Admin) -> dict[str, Any]:
        with pool.session(body.session_id, create=False, store_exists=session_exists) as guard:
            text = guard.restore(body.text)
            guard.store.log_event(body.session_id, "restore_by", {"by": user["name"]})
        return {"text": text}

    @app.post("/api/reidentify")
    def reidentify(body: ReidentifyIn, user: Admin) -> list[dict[str, Any]]:
        out = []
        with pool.session(body.session_id, create=False, store_exists=session_exists) as guard:
            for alias in body.aliases:
                try:
                    out.append(guard.reidentify(alias))
                except AliasNotFoundError as exc:
                    out.append({"alias": alias, "error": str(exc)})
            guard.store.log_event(body.session_id, "reidentify_by", {"by": user["name"], "count": len(body.aliases)})
        return out

    # ------------------------------------------------------------- policy

    @app.get("/api/policy")
    def get_policy(user: User) -> dict[str, Any]:
        pol = policies.get()
        return {"yaml": policies.text(), "path": policies.location, "source": pol.source,
                "policy_ids": pol.policy_names(), "hooks": list(KNOWN_HOOKS), "matrix": pol.matrix()}

    @app.post("/api/policy/validate")
    def validate_policy(body: PolicyIn, user: User) -> dict[str, Any]:
        try:
            pol = policies.validate(body.yaml)
        except PolicyError as exc:
            return {"valid": False, "error": str(exc)}
        return {"valid": True, "policy_ids": pol.policy_names(), "matrix": pol.matrix()}

    @app.put("/api/policy")
    def put_policy(body: PolicyIn, user: Admin) -> dict[str, Any]:
        try:
            pol = policies.save(body.yaml)
        except PolicyError as exc:
            raise HTTPException(422, str(exc)) from exc
        pool.invalidate()
        with db() as s:
            s.log_event("", "policy_update", {"by": user["name"], "where": policies.location})
        return {"saved": True, "policy_ids": pol.policy_names()}

    # ------------------------------------------------------------- api keys

    @app.get("/api/keys")
    def list_keys(user: Admin) -> list[dict[str, Any]]:
        with db() as s:
            return s.list_api_keys()

    @app.post("/api/keys")
    def new_key(body: KeyIn, user: Admin) -> dict[str, Any]:
        with db() as s:
            key_id, key = create_api_key(s, body.name, body.role)
            s.log_event("", "api_key_created", {"by": user["name"], "id": key_id, "role": body.role})
        return {"id": key_id, "key": key, "role": body.role, "name": body.name}

    @app.delete("/api/keys/{key_id}")
    def revoke_key(key_id: str, user: Admin) -> dict[str, Any]:
        with db() as s:
            keys = {k["id"]: k for k in s.list_api_keys()}
            k = keys.get(key_id)
            if k is None or k["revoked"]:
                raise HTTPException(404, "key not found")
            if k["role"] == "admin" and s.count_admin_keys() <= 1:
                raise HTTPException(409, "cannot revoke the last admin key")
            s.revoke_api_key(key_id)
            s.log_event("", "api_key_revoked", {"by": user["name"], "id": key_id})
        return {"revoked": key_id}

    # ------------------------------------------------------------- frontend

    static_dir = Path(str(resources.files("piisafe").joinpath("server/static")))
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="ui")

    return app


def ensure_admin_key(state_dir: Path, database_url: str | None = None) -> str | None:
    """Create a bootstrap admin key on first start; returns it (once) or None."""
    store = open_store(database_url, Path(state_dir))
    try:
        if store.count_admin_keys():
            return None
        _, key = create_api_key(store, "bootstrap-admin", "admin")
        return key
    finally:
        store.close()


__all__ = ["ROLES", "create_app", "ensure_admin_key"]
