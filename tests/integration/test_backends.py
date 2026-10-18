"""Storage backends (SQLite + PostgreSQL), cross-writer consistency, managed keys.

PostgreSQL tests run when PIISAFE_TEST_DATABASE_URL points at a disposable
database (its public schema is wiped per test), e.g.
    PIISAFE_TEST_DATABASE_URL=postgresql://piisafe@127.0.0.1:55432/piisafe_test pytest
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from piisafe import PIISafeGuard
from piisafe.keyproviders import WRAPPED_META_KEY, KeyProviderError
from piisafe.storage import open_store

PG_URL = os.environ.get("PIISAFE_TEST_DATABASE_URL")


def _reset_pg(url: str) -> None:
    import psycopg

    with psycopg.connect(url, autocommit=True) as c:
        c.execute("DROP SCHEMA public CASCADE")
        c.execute("CREATE SCHEMA public")


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(not PG_URL, reason="no PG"))])
def db_url(request, tmp_path, monkeypatch):
    monkeypatch.delenv("PIISAFE_MASTER_KEY", raising=False)
    monkeypatch.delenv("PIISAFE_KEY_PROVIDER", raising=False)
    monkeypatch.setenv("PIISAFE_HOME", str(tmp_path / "state"))
    if request.param == "postgres":
        _reset_pg(PG_URL)
        return PG_URL
    return f"sqlite:///{tmp_path / 'state' / 'piisafe.db'}"


def guard(url: str, sid: str = "S", **kw) -> PIISafeGuard:
    return PIISafeGuard(session_id=sid, database_url=url, ner="heuristic", **kw)


def test_round_trip_and_reopen(db_url):
    with guard(db_url) as g:
        r = g.on_prompt("raj.mehta@corp.com accessed 192.168.1.45; Kavishka logged in")
        assert r.sanitised_text == "MAIL_001 accessed HOST_001; USER_001 logged in"
    with guard(db_url) as g:
        assert g.on_prompt("Kavihska approved 192.168.1.45").sanitised_text == "USER_001 approved HOST_001"
        assert g.reidentify("MAIL_001")["value"] == "raj.mehta@corp.com"
        assert g.restore("USER_001 / HOST_001") == "Kavishka / 192.168.1.45"


def test_dashboard_queries(db_url):
    from piisafe.runs import record_run

    with guard(db_url) as g:
        g.on_prompt("Raj flagged by the system")
        g.on_prompt("Raju accessed 10.0.0.1")
        record_run(g.store, session_id="S", source="x.log", origin="cli", hook="on_prompt", fmt="text",
                   status="ok", stats=None, duration_s=0.1)
    store = open_store(db_url)
    try:
        st = store.stats(30)
        assert st["findings"] == 3 and st["sessions"] == 1 and st["by_day"]
        risk = store.risk_analytics(30)
        assert risk["sources"][0]["source"] == "x.log"
        assert [(r["alias"], r["candidate"]) for r in store.pending_reviews()] == [("USER_002", "USER_001")]
        assert store.list_sessions()[0]["deferred"] == 1
        assert store.delete_session("S") == 1 and store.list_sessions() == []
    finally:
        store.close()


def test_two_writers_never_collide(db_url):
    """Two guards = two processes / replicas with their own connection and cache."""
    a, b = guard(db_url), guard(db_url)
    try:
        assert a.on_prompt("10.0.0.1").sanitised_text == "HOST_001"
        assert b.on_prompt("10.0.0.2").sanitised_text == "HOST_002"  # b reloads: sees HOST_001
        assert a.on_prompt("10.0.0.3 and 10.0.0.2").sanitised_text == "HOST_003 and HOST_002"
    finally:
        a.close()
        b.close()


def test_concurrent_replicas(db_url):
    guards = [guard(db_url) for _ in range(3)]
    results: list[str] = []
    lock = threading.Lock()

    def work(g: PIISafeGuard, base: int) -> None:
        for i in range(8):
            out = g.on_prompt(f"10.1.{base}.{i + 1}").sanitised_text
            with lock:
                results.append(out)

    # One thread per guard (a guard object itself is single-threaded, like a replica's pool slot).
    threads = [threading.Thread(target=work, args=(g, n)) for n, g in enumerate(guards)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for g in guards:
        g.close()
    assert len(results) == 24 and len(set(results)) == 24


def test_sqlite_upgrade_from_v2(tmp_path):
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT INTO meta VALUES ('schema_version', '2');
        CREATE TABLE sessions (session_id TEXT PRIMARY KEY, key_check TEXT NOT NULL,
            turn INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, updated_at REAL NOT NULL);
        INSERT INTO sessions VALUES ('old', 'x', 3, 0, 0);
    """)
    conn.commit()
    conn.close()
    store = open_store(str(db))
    assert store.get_session("old")["version"] == 0
    assert store.get_meta("schema_version") == "3"
    store.close()


# ----------------------------------------------------------------- managed keys


@pytest.fixture
def aws_kms(monkeypatch):
    moto = pytest.importorskip("moto")
    boto3 = pytest.importorskip("boto3")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with moto.mock_aws():
        key_id = boto3.client("kms", region_name="eu-west-1").create_key()["KeyMetadata"]["Arn"]
        monkeypatch.setenv("PIISAFE_KMS_KEY_ID", key_id)
        yield key_id


def test_aws_kms_envelope(db_url, aws_kms, tmp_path):
    from piisafe import crypto

    crypto._UNWRAPPED_CACHE.clear()
    with guard(db_url, key_provider="aws-kms") as g:
        g.on_prompt("raj.mehta@corp.com")
    assert not (tmp_path / "state" / "master.key").exists()  # nothing in clear on disk
    store = open_store(db_url)
    info = json.loads(store.get_meta(WRAPPED_META_KEY))
    store.close()
    assert info["provider"] == "aws-kms" and info["key_ref"] == aws_kms
    crypto._UNWRAPPED_CACHE.clear()  # a fresh replica must unwrap through KMS
    with guard(db_url, key_provider="aws-kms") as g:
        assert g.reidentify("MAIL_001")["value"] == "raj.mehta@corp.com"
    with pytest.raises(KeyProviderError):
        guard(db_url, key_provider="vault-transit")  # wrong provider for this database (and no VAULT_ADDR)


def test_migrate_local_key_to_kms(db_url, aws_kms, tmp_path):
    from piisafe import crypto
    from piisafe.cli import main

    with guard(db_url) as g:  # local master.key
        g.on_prompt("10.9.9.9")
    assert (tmp_path / "state" / "master.key").exists()
    assert main(["master-key", "migrate", "--to", "aws-kms", "--database-url", db_url]) == 0
    (tmp_path / "state" / "master.key").unlink()
    crypto._UNWRAPPED_CACHE.clear()
    with guard(db_url, key_provider="aws-kms") as g:
        assert g.reidentify("HOST_001")["value"] == "10.9.9.9"  # old session still readable


class _FakeTransit(BaseHTTPRequestHandler):
    """Implements Vault's transit encrypt/decrypt request/response shapes."""

    secret = b"k" * 32

    def do_POST(self) -> None:  # noqa: N802
        assert self.headers["X-Vault-Token"] == "root-token"
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path == "/v1/transit/encrypt/piisafe":
            pt = base64.b64decode(body["plaintext"])
            data = {"ciphertext": "vault:v1:" + base64.b64encode(bytes(x ^ 0x5A for x in pt)).decode()}
        elif self.path == "/v1/transit/decrypt/piisafe":
            ct = base64.b64decode(body["ciphertext"].removeprefix("vault:v1:"))
            data = {"plaintext": base64.b64encode(bytes(x ^ 0x5A for x in ct)).decode()}
        else:
            self.send_response(404)
            self.end_headers()
            return
        payload = json.dumps({"data": data}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: object) -> None:
        pass


def test_vault_transit_envelope(db_url, monkeypatch):
    from piisafe import crypto

    srv = HTTPServer(("127.0.0.1", 0), _FakeTransit)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("VAULT_ADDR", f"http://127.0.0.1:{srv.server_port}")
    monkeypatch.setenv("VAULT_TOKEN", "root-token")
    try:
        crypto._UNWRAPPED_CACHE.clear()
        with guard(db_url, key_provider="vault-transit") as g:
            g.on_prompt("10.2.2.2")
        crypto._UNWRAPPED_CACHE.clear()
        with guard(db_url, key_provider="vault-transit") as g:
            assert g.reidentify("HOST_001")["value"] == "10.2.2.2"
        monkeypatch.setenv("VAULT_TOKEN", "wrong")
        crypto._UNWRAPPED_CACHE.clear()
        with pytest.raises(Exception):  # noqa: B017 - fake server rejects the token
            guard(db_url, key_provider="vault-transit")
    finally:
        srv.shutdown()
