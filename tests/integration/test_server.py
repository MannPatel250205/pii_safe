from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from piisafe.server import create_app, ensure_admin_key  # noqa: E402
from piisafe.server.auth import create_api_key  # noqa: E402
from piisafe.storage import open_store  # noqa: E402

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


PG_URL = os.environ.get("PIISAFE_TEST_DATABASE_URL")


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(not PG_URL, reason="no PG"))])
def env(request, tmp_path, monkeypatch):
    monkeypatch.delenv("PIISAFE_MASTER_KEY", raising=False)
    monkeypatch.delenv("PIISAFE_DATABASE_URL", raising=False)
    state = tmp_path / "state"
    url = None
    if request.param == "postgres":
        import psycopg

        with psycopg.connect(PG_URL, autocommit=True) as c:
            c.execute("DROP SCHEMA public CASCADE")
            c.execute("CREATE SCHEMA public")
        url = PG_URL
    app = create_app(state, database_url=url)
    admin_key = ensure_admin_key(state, url)
    assert ensure_admin_key(state, url) is None  # only once
    store = open_store(url, state)
    _, analyst_key = create_api_key(store, "analyst-1", "analyst")
    store.close()
    with TestClient(app) as client:
        yield client, {"Authorization": f"Bearer {admin_key}"}, {"Authorization": f"Bearer {analyst_key}"}


def test_auth_required_and_roles(env):
    c, admin, analyst = env
    assert c.get("/api/health").status_code == 200
    assert c.get("/api/me").status_code == 401
    assert c.get("/api/me", headers={"Authorization": "Bearer psk_wrong"}).status_code == 401
    assert c.get("/api/me", headers=analyst).json()["role"] == "analyst"
    assert c.post("/api/restore", json={"session_id": "x", "text": "y"}, headers=analyst).status_code == 403
    assert c.get("/api/keys", headers=analyst).status_code == 403
    assert c.put("/api/policy", json={"yaml": "default_action: allow"}, headers=analyst).status_code == 403


def test_ui_served_with_security_headers(env):
    c, _, _ = env
    r = c.get("/")
    assert r.status_code == 200 and "app.js" in r.text
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert c.get("/app.js").status_code == 200


def test_sanitize_consistent_and_restorable(env):
    c, admin, analyst = env
    body = {"text": "raj.mehta@corp.com accessed 192.168.1.45", "session_id": "INC-9"}
    r1 = c.post("/api/sanitize", json=body, headers=analyst).json()
    assert r1["sanitised_text"] == "MAIL_001 accessed HOST_001"
    r2 = c.post("/api/sanitize", json={**body, "text": "again 192.168.1.45"}, headers=analyst).json()
    assert r2["sanitised_text"] == "again HOST_001"
    restored = c.post("/api/restore", json={"session_id": "INC-9", "text": r1["sanitised_text"]}, headers=admin)
    assert restored.json()["text"] == body["text"]
    assert c.post("/api/restore", json={"session_id": "nope", "text": "x"}, headers=admin).status_code == 404
    assert c.post("/api/sanitize", json={**body, "session_id": "bad id!"}, headers=analyst).status_code == 422


def test_concurrent_requests_never_duplicate_aliases(env):
    c, _, analyst = env
    results: list[str] = []

    def worker(i: int) -> None:
        r = c.post("/api/sanitize", json={"text": f"host 10.0.0.{i + 1}", "session_id": "conc"}, headers=analyst)
        results.append(r.json()["sanitised_text"])

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    aliases = [t.split()[-1] for t in results]
    assert len(set(aliases)) == 20


def test_file_upload_download_and_dashboard(env):
    c, _, analyst = env
    with open(EXAMPLES / "security.log", "rb") as fh:
        r = c.post("/api/sanitize/file", files={"file": ("security.log", fh)}, data={"session_id": "FILE-1"},
                   headers=analyst)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["summary"]["findings"] > 10 and "raj.mehta@corp.com" not in data["preview"]
    out = c.get(data["download"], headers=analyst)
    assert out.status_code == 200 and b"MAIL_001" in out.content
    st = c.get("/api/stats", headers=analyst).json()
    assert st["findings"] > 10 and st["records"] >= 13
    assert st["recent_runs"][0]["source"] == "security.log"
    assert c.get("/api/sessions/FILE-1", headers=analyst).json()["entities"]


def test_blocked_upload(env):
    c, _, analyst = env
    r = c.post("/api/sanitize/file", files={"file": ("x.log", b"mail raj@corp.com\n")},
               data={"hook": "export"}, headers=analyst)
    assert r.status_code == 409
    assert r.json()["detail"]["entity_types"] == ["EMAIL_ADDRESS"]


def test_review_merge_flow(env):
    c, admin, analyst = env
    for t in ("Raj flagged by the system", "Raju accessed the server"):
        c.post("/api/sanitize", json={"text": t, "session_id": "REV"}, headers=analyst)
    pending = c.get("/api/reviews", headers=analyst).json()
    assert [(p["alias"], p["candidate"]) for p in pending] == [("USER_002", "USER_001")]
    ok = c.post("/api/reviews", json={"session_id": "REV", "alias": "USER_002", "candidate": "USER_001",
                                      "decision": "merge"}, headers=analyst)
    assert ok.status_code == 200
    assert c.get("/api/reviews", headers=analyst).json() == []
    r = c.post("/api/sanitize", json={"text": "Raju logged out", "session_id": "REV"}, headers=analyst).json()
    assert r["sanitised_text"] == "USER_001 logged out"


def test_policy_edit_and_keys(env):
    c, admin, analyst = env
    pol = c.get("/api/policy", headers=analyst).json()
    assert "internal_analysis" in pol["policy_ids"]
    bad = c.post("/api/policy/validate", json={"yaml": "default_action: nope"}, headers=analyst).json()
    assert bad["valid"] is False
    new_yaml = pol["yaml"].replace("default_action: pseudonymise", "default_action: redact", 1)
    assert c.put("/api/policy", json={"yaml": new_yaml}, headers=admin).status_code == 200
    k = c.post("/api/keys", json={"name": "bot", "role": "analyst"}, headers=admin).json()
    assert c.get("/api/me", headers={"Authorization": f"Bearer {k['key']}"}).status_code == 200
    assert c.delete(f"/api/keys/{k['id']}", headers=admin).status_code == 200
    assert c.get("/api/me", headers={"Authorization": f"Bearer {k['key']}"}).status_code == 401
    admin_id = next(x["id"] for x in c.get("/api/keys", headers=admin).json() if x["role"] == "admin")
    assert c.delete(f"/api/keys/{admin_id}", headers=admin).status_code == 409  # last admin
