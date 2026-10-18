"""The entity-resolution test pairs from the proposal (section 6.1), and more."""

from __future__ import annotations

from piisafe import Decision, PIISafeGuard


def persons(g: PIISafeGuard, text: str):
    r = g.on_prompt(text)
    return [f for f in r.findings if f.entity_type == "PERSON"], r.sanitised_text


def test_raj_raju_is_deferred_split(heuristic_guard):
    g = heuristic_guard
    out = [g.on_prompt(t).sanitised_text for t in (
        "raj.mehta@corp.com accessed 192.168.1.45 — FAILED_LOGIN",
        "Raj flagged by the security system",
        "Raju accessed 192.168.1.67 — SUCCESS",
    )]
    assert out == [
        "MAIL_001 accessed HOST_001 — FAILED_LOGIN",
        "USER_001 flagged by the security system",
        "USER_002 accessed HOST_002 — SUCCESS",
    ]
    deferred = g.store  # audit rows are flushed on demand
    g.flush()
    rows = deferred.query_audit("test-h", decision="DEFERRED")
    assert len(rows) == 1 and rows[0]["alias"] == "USER_002" and rows[0]["candidate_alias"] == "USER_001"


def test_exact_repeat_reuses_alias(heuristic_guard):
    a, _ = persons(heuristic_guard, "Raj logged in")
    b, _ = persons(heuristic_guard, "Raj logged out")
    assert a[0].alias == b[0].alias == "USER_001"
    assert b[0].decision is Decision.EXACT


def test_transposition_typo_merges(heuristic_guard):
    a, _ = persons(heuristic_guard, "Kavishka logged in at 09:00")
    b, text = persons(heuristic_guard, "Kavihska approved the request")
    assert a[0].alias == b[0].alias
    assert b[0].decision is Decision.MERGE
    assert text == f"{a[0].alias} approved the request"


def test_unrelated_names_are_new(heuristic_guard):
    a, _ = persons(heuristic_guard, "Alice logged in")
    b, _ = persons(heuristic_guard, "Bob logged in")
    assert a[0].alias != b[0].alias
    assert b[0].decision is Decision.NEW_ENTITY


def test_short_names_never_fuzzy_merge(heuristic_guard):
    persons(heuristic_guard, "Raj logged in")
    b, _ = persons(heuristic_guard, "Ram logged in")
    assert b[0].alias == "USER_002"
    assert b[0].decision in (Decision.NEW_ENTITY, Decision.DEFERRED)


def test_first_name_merges_into_unique_full_name(heuristic_guard):
    a, _ = persons(heuristic_guard, "Kavishka Perera logged in")
    b, _ = persons(heuristic_guard, "Kavishka approved")
    assert a[0].alias == b[0].alias and b[0].decision is Decision.MERGE


def test_surname_only_is_deferred(heuristic_guard):
    persons(heuristic_guard, "Kavishka Perera logged in")
    b, _ = persons(heuristic_guard, "Perera approved")
    assert b[0].decision is Decision.DEFERRED


def test_ambiguous_first_name_is_deferred(heuristic_guard):
    persons(heuristic_guard, "Priya Sharma logged in")
    persons(heuristic_guard, "Priya Patel logged in")
    c, _ = persons(heuristic_guard, "Priya approved")
    assert c[0].decision is Decision.DEFERRED


def test_typo_in_full_name_merges(heuristic_guard):
    a, _ = persons(heuristic_guard, "Kavishka Perera logged in")
    b, _ = persons(heuristic_guard, "Kavihska Perera approved")
    assert a[0].alias == b[0].alias


def test_session_isolation():
    with PIISafeGuard(session_id="s1", ephemeral=True, ner="heuristic") as g1, \
         PIISafeGuard(session_id="s2", ephemeral=True, ner="heuristic") as g2:
        g1.on_prompt("Alice logged in")
        r1 = g1.on_prompt("Raj logged in")
        r2 = g2.on_prompt("Raj logged in")
        assert r1.findings[0].alias == "USER_002"
        assert r2.findings[0].alias == "USER_001"
        # keyed fingerprints differ per session (unlinkable across sessions)
        assert r1.findings[0].value_hash != r2.findings[0].value_hash


def test_email_links_to_person(heuristic_guard):
    heuristic_guard.on_prompt("raj.mehta@corp.com logged in")
    p, _ = persons(heuristic_guard, "Raj flagged by the security system")
    assert p[0].linked == ("MAIL_001",)


def test_session_memory_catches_lowercase_remention(heuristic_guard):
    heuristic_guard.on_prompt("Kavishka logged in")
    r = heuristic_guard.on_prompt("job queued by kavishka")
    assert r.sanitised_text == "job queued by USER_001"


def test_merge_command_redirects_future_mentions(heuristic_guard):
    g = heuristic_guard
    g.on_prompt("Raj logged in")
    g.on_prompt("Raju logged in")
    g.merge("USER_002", "USER_001")
    assert g.on_prompt("Raju logged out").sanitised_text == "USER_001 logged out"
