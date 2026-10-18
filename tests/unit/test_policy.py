from __future__ import annotations

import pytest

from piisafe import Action, PIISafeGuard, Policy, PolicyBlockError, PolicyError

POLICY = {
    "default_action": "pseudonymise",
    "policies": [
        {"name": "analysis", "hook_type": "on_prompt",
         "rules": [{"entity_type": "SECRET", "action": "redact"}]},
        {"name": "mem", "hook_type": "on_memory",
         "rules": [{"entity_type": "EMAIL_ADDRESS", "action": "block"}]},
        {"name": "export", "hook_type": "export",
         "rules": [{"entity_type": "PHONE_NUMBER", "action": "mask"},
                   {"entity_type": "*", "action": "redact"}]},
        {"name": "open", "hook_type": "custom_hook", "default_action": "allow", "rules": []},
    ],
    "allowlist": {"values": ["10.0.0.1"]},
}


@pytest.fixture
def policy() -> Policy:
    return Policy.from_dict(POLICY)


def test_rules_by_hook(policy):
    assert policy.action_for("SECRET", "on_prompt")[0] is Action.REDACT
    assert policy.action_for("EMAIL_ADDRESS", "on_prompt")[0] is Action.PSEUDONYMISE  # global default
    assert policy.action_for("EMAIL_ADDRESS", "on_memory")[0] is Action.BLOCK
    assert policy.action_for("PERSON", "export") == (Action.REDACT, "export")
    assert policy.action_for("PHONE_NUMBER", "export")[0] is Action.MASK
    assert policy.action_for("PERSON", "custom_hook") == (Action.ALLOW, "open")


def test_policy_id_overrides_hook(policy):
    assert policy.action_for("PERSON", "on_prompt", policy_id="export")[0] is Action.REDACT
    with pytest.raises(PolicyError):
        policy.action_for("PERSON", "on_prompt", policy_id="nope")


def test_validation_collects_all_errors():
    with pytest.raises(PolicyError) as e:
        Policy.from_dict({
            "default_action": "obliterate",
            "policies": [
                {"hook_type": "on_prompt"},
                {"name": "x", "rules": [{"entity_type": "email", "action": "allow"}]},
            ],
            "custom_patterns": [{"entity_type": "FOO", "regex": "(["}],
            "resolution": {"merge_threshold": 0.5, "new_entity_threshold": 0.9},
        })
    msg = str(e.value)
    for needle in ("obliterate", "needs a 'name'", "'email'", "bad regex", "new_entity_threshold"):
        assert needle in msg


def test_builtin_default_loads():
    p = Policy.default()
    assert "internal_analysis" in p.policy_names()


def test_actions_end_to_end(policy):
    with PIISafeGuard(policy, ephemeral=True, ner="off") as g:
        assert g.on_prompt("token=supersecret123").sanitised_text == "token=[SECRET]"
        assert g.on_export("call +1 415-555-0132").sanitised_text == "call +* ***-***-0132"
        assert g.on_export("raj@corp.com").sanitised_text == "[EMAIL_ADDRESS]"
        assert g.on_prompt("from 10.0.0.1").sanitised_text == "from 10.0.0.1"  # allowlisted
        with pytest.raises(PolicyBlockError) as e:
            g.on_memory("note", "reach me at raj@corp.com")
        assert e.value.entity_types == ["EMAIL_ADDRESS"]


def test_block_does_not_touch_registry(policy):
    with PIISafeGuard(policy, ephemeral=True, ner="off") as g:
        with pytest.raises(PolicyBlockError):
            g.on_memory("k", "raj@corp.com and 192.168.1.1")
        # 192.168.1.1 was not registered by the blocked call
        assert g.on_prompt("192.168.1.9").sanitised_text == "HOST_001"


def test_block_mode_redact(policy):
    with PIISafeGuard(policy, ephemeral=True, ner="off", block_mode="redact") as g:
        r = g.on_memory("k", "raj@corp.com")
        assert r == "[EMAIL_ADDRESS]"


def test_field_hints():
    p = Policy.default()
    assert p.hint_for_field("src_ip") == "IP_ADDRESS"
    assert p.hint_for_field("userEmail") == "EMAIL_ADDRESS"
    assert p.hint_for_field("user_agent") is None
    assert p.hint_for_field("file_name") is None
