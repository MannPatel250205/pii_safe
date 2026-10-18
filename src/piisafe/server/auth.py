"""API keys for the web dashboard and REST API.

Keys look like ``psk_<43 chars>`` (256 random bits). Only a SHA-256 of the key
is stored — with that much entropy a fast hash is safe and lookups stay O(1).
The plaintext key is shown exactly once, at creation.

Roles:
    analyst  sanitise / scan, dashboard, sessions, audit, review queue
    admin    + re-identification (restore / reidentify), deleting sessions,
               editing the policy, managing API keys
"""

from __future__ import annotations

import hashlib
import secrets
import uuid

from piisafe.storage.sql import SQLStore

ROLES = ("analyst", "admin")
KEY_PREFIX = "psk_"


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def create_api_key(store: SQLStore, name: str, role: str) -> tuple[str, str]:
    """Return (key_id, plaintext_key). The plaintext is not recoverable later."""
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    key_id = uuid.uuid4().hex[:12]
    store.create_api_key(key_id, name.strip() or "unnamed", role, hash_key(key), key[:8])
    return key_id, key


def authenticate(store: SQLStore, key: str) -> dict | None:
    if not key.startswith(KEY_PREFIX):
        return None
    return store.find_api_key(hash_key(key))
