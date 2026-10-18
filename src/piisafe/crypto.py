"""Key hierarchy.

    master key (file 0600, $PIISAFE_MASTER_KEY, or wrapped by AWS KMS / Vault — keyproviders.py)
      └── session key = HMAC(master, session_id)      # shareable per incident
            ├── Fernet encryption of entity payloads   # reversible, needs the key
            └── fingerprint key = HMAC(session, ...)   # keyed hashes in DB + audit

Why keyed hashes instead of plain SHA-256: the IPv4 space is 2^32 and name
lists are small, so an unkeyed hash of a PII value is reversible by brute
force. Without the key, fingerprints in the audit log reveal nothing.

Handing someone a *session* key lets them re-identify that one session only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from piisafe.exceptions import KeyMismatchError

MASTER_KEY_ENV = "PIISAFE_MASTER_KEY"
MASTER_KEY_FILE = "master.key"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _unb64(value: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(value.strip().encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise KeyMismatchError("key is not valid base64") from exc
    if len(raw) != 32:
        raise KeyMismatchError("key must decode to 32 bytes")
    return raw


def generate_key() -> str:
    return _b64(os.urandom(32))


_UNWRAPPED_CACHE: dict[tuple[str, str], bytes] = {}


class KeyManager:
    """Resolves the master key from the configured provider (see piisafe.keyproviders)."""

    def __init__(
        self,
        state_dir: Path | None,
        *,
        create: bool = True,
        provider: str | None = None,
        store: Any = None,
    ) -> None:
        from piisafe.keyproviders import provider_name

        self._master: bytes | None = None
        name = provider_name(provider)
        self.provider = name
        if name == "env":
            env = os.environ.get(MASTER_KEY_ENV)
            if not env:
                raise KeyMismatchError(f"key provider 'env' selected but ${MASTER_KEY_ENV} is not set")
            self._master = _unb64(env)
            self.source = f"${MASTER_KEY_ENV}"
        elif name == "local":
            if state_dir is None:
                self._master = os.urandom(32)
                self.source = "ephemeral"
            else:
                self._load_local(state_dir / MASTER_KEY_FILE, create)
        else:
            self._load_managed(name, store, create)

    def _load_local(self, path: Path, create: bool) -> None:
        self.source = str(path)
        if not path.exists() and create:
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:  # another process created it first
                pass
            else:
                with os.fdopen(fd, "w") as fh:
                    fh.write(generate_key() + "\n")
        if path.exists():
            self._master = _unb64(path.read_text())

    def _load_managed(self, name: str, store: Any, create: bool) -> None:
        from piisafe.keyproviders import WRAPPED_META_KEY, KeyProviderError, managed_provider

        if store is None or not hasattr(store, "get_meta"):
            raise KeyProviderError(f"key provider '{name}' needs a database to hold the wrapped key")
        kms = managed_provider(name)
        self.source = f"{name}:{kms.key_ref()}"
        record = store.get_meta(WRAPPED_META_KEY)
        if record is None:
            if not create:
                return
            # Several replicas may race here; only the first insert wins and all use it.
            wrapped = kms.wrap(os.urandom(32))
            store.set_meta_if_absent(
                WRAPPED_META_KEY, json.dumps({"provider": name, "key_ref": kms.key_ref(), "wrapped": wrapped})
            )
            record = store.get_meta(WRAPPED_META_KEY)
        info = json.loads(record)
        if info["provider"] != name:
            raise KeyProviderError(
                f"this database's master key is wrapped by '{info['provider']}', not '{name}' "
                "(set PIISAFE_KEY_PROVIDER accordingly)"
            )
        cache_key = (name, info["wrapped"])
        if cache_key not in _UNWRAPPED_CACHE:
            raw = kms.unwrap(info["wrapped"])
            if len(raw) != 32:
                raise KeyProviderError("unwrapped master key has the wrong length")
            _UNWRAPPED_CACHE[cache_key] = raw
        self._master = _UNWRAPPED_CACHE[cache_key]

    @property
    def available(self) -> bool:
        return self._master is not None

    def master_bytes(self) -> bytes:
        if self._master is None:
            raise KeyMismatchError("no master key available")
        return self._master

    def session_key(self, session_id: str) -> str:
        if self._master is None:
            raise KeyMismatchError("no master key available; pass a session key instead")
        return _b64(hmac.new(self._master, b"piisafe:session:" + session_id.encode(), hashlib.sha256).digest())


class SessionCrypto:
    def __init__(self, session_key: str) -> None:
        raw = _unb64(session_key)
        self._fernet = Fernet(_b64(raw).encode("ascii"))
        self._fp_key = hmac.new(raw, b"piisafe:fingerprint", hashlib.sha256).digest()

    def fingerprint(self, data: str) -> str:
        return hmac.new(self._fp_key, data.encode("utf-8"), hashlib.sha256).hexdigest()[:32]

    def key_check(self) -> str:
        return self.fingerprint("\x00piisafe-key-check")

    def encrypt(self, obj: dict[str, Any]) -> bytes:
        return self._fernet.encrypt(json.dumps(obj, separators=(",", ":")).encode("utf-8"))

    def decrypt(self, token: bytes) -> dict[str, Any]:
        try:
            return json.loads(self._fernet.decrypt(token))
        except InvalidToken as exc:
            raise KeyMismatchError("cannot decrypt session data with this key") from exc
