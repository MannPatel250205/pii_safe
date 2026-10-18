from __future__ import annotations

import os

import pytest

from piisafe import KeyMismatchError, PIISafeGuard, SanitiseResult


def test_on_prompt_contract(guard):
    r = guard.on_prompt("raj.mehta@corp.com accessed 192.168.1.45")
    assert isinstance(r, SanitiseResult)
    assert r.sanitised_text == "MAIL_001 accessed HOST_001"
    assert r.entities_found == {"EMAIL_ADDRESS": 1, "IP_ADDRESS": 1}
    assert 0 < r.risk_score <= 100 and r.residual_risk == 0
    assert len(r.audit_id) == 32


def test_on_context_is_one_turn(guard):
    results = guard.on_context(["doc about 192.168.1.45", "same host 192.168.1.45"])
    assert [r.sanitised_text for r in results] == ["doc about HOST_001", "same host HOST_001"]


def test_on_tool_call_uses_field_hints(guard):
    out = guard.on_tool_call("block_ip", {"src_ip": "192.168.1.45", "reason": "brute force", "count": 3})
    # default policy redacts IPs in tool calls
    assert out == {"src_ip": "[IP_ADDRESS]", "reason": "brute force", "count": 3}


def test_field_hint_forces_detection(guard):
    clean, findings = guard.sanitize_record({"username": "x9_svc", "phone": 4155550132})
    assert clean == {"username": "ACCT_001", "phone": "PHONE_001"}
    assert {f.detector for f in findings} >= {"field_hint"}


def test_invisible_characters_cannot_hide_pii(guard):
    assert guard.on_prompt("raj​.mehta@corp.com").sanitised_text == "MAIL_001"


def test_consistency_and_canonicalisation(guard):
    a = guard.on_prompt("raj.mehta@corp.com").sanitised_text
    b = guard.on_prompt("RAJ.MEHTA@CORP.COM").sanitised_text
    assert a == b == "MAIL_001"


def test_restore_round_trip(guard):
    clean = guard.on_prompt("Kavishka logged in from 192.168.1.45").sanitised_text
    assert "Kavishka" not in clean
    assert guard.restore(clean) == "Kavishka logged in from 192.168.1.45"
    assert guard.restore("USER_999 unknown") == "USER_999 unknown"


def test_persistence_and_keys(state_dir):
    with PIISafeGuard(session_id="INC-1") as g:
        g.on_prompt("raj.mehta@corp.com accessed 192.168.1.45")
        key = g.session_key()
    # reopen: same aliases continue
    with PIISafeGuard(session_id="INC-1") as g:
        assert g.on_prompt("192.168.1.45 and 192.168.1.46").sanitised_text == "HOST_001 and HOST_002"
        assert g.reidentify("MAIL_001")["value"] == "raj.mehta@corp.com"
    # session key works on its own; a wrong key is rejected
    with PIISafeGuard(session_id="INC-1", session_key=key) as g:
        assert g.reidentify("HOST_002")["value"] == "192.168.1.46"
    from piisafe.crypto import generate_key

    with pytest.raises(KeyMismatchError):
        PIISafeGuard(session_id="INC-1", session_key=generate_key())


def test_no_plaintext_pii_on_disk(state_dir):
    with PIISafeGuard(session_id="INC-2") as g:
        g.on_prompt("Kavishka Perera <kavishka.p@corp.com> from 192.168.1.45")
    blob = b"".join(p.read_bytes() for p in state_dir.iterdir() if p.name.startswith("piisafe.db"))
    for needle in (b"Kavishka", b"kavishka", b"Perera", b"corp.com", b"192.168.1.45"):
        assert needle not in blob
    key = state_dir / "master.key"
    if os.name == "posix":  # NTFS has no POSIX mode bits; the key is ACL-protected there
        assert key.stat().st_mode & 0o077 == 0


def test_hook_registry_is_extensible(guard):
    guard.hooks.register("on_tool_result", lambda text: guard.sanitize(text, "on_tool_result"))
    assert guard.hooks.dispatch("on_tool_result", "ip 192.168.1.45").sanitised_text == "ip HOST_001"
