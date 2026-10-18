"""Where the master key comes from.

    local          <state_dir>/master.key, mode 0600 (default; single host)
    env            $PIISAFE_MASTER_KEY (base64url, 32 bytes) — e.g. from a secrets manager
    aws-kms        envelope encryption with AWS KMS
    vault-transit  envelope encryption with HashiCorp Vault's Transit engine

With the managed providers the plaintext master key never touches disk: PII-Safe
generates it, has the KMS *wrap* it, and stores only the wrapped blob in the
database `meta` table, so every API replica can unwrap the same key and an
attacker with a database dump alone gets nothing. Unwrapped keys are cached in
memory per process.

Select with $PIISAFE_KEY_PROVIDER (or `key_provider=` / `--key-provider`).
Provider settings come from the standard environment of each system:

    aws-kms        PIISAFE_KMS_KEY_ID (key ARN / alias), and the usual AWS chain:
                   AWS_REGION, AWS_PROFILE or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY,
                   or an instance / task / IRSA role.
    vault-transit  VAULT_ADDR, VAULT_TOKEN, optional VAULT_NAMESPACE, VAULT_CACERT,
                   PIISAFE_VAULT_KEY (transit key name, default "piisafe"),
                   PIISAFE_VAULT_MOUNT (default "transit").
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any, Protocol

from piisafe.exceptions import PIISafeError

PROVIDER_ENV = "PIISAFE_KEY_PROVIDER"
WRAPPED_META_KEY = "master_key.wrapped"
_CONTEXT = {"application": "piisafe", "purpose": "master-key"}


class KeyProviderError(PIISafeError):
    """The key management system could not be reached or refused the request."""


class ManagedKeyProvider(Protocol):
    name: str

    def key_ref(self) -> str: ...
    def wrap(self, plaintext: bytes) -> str: ...
    def unwrap(self, wrapped: str) -> bytes: ...


def provider_name(explicit: str | None = None) -> str:
    name = (explicit or os.environ.get(PROVIDER_ENV) or "").strip().lower()
    if not name:
        return "env" if os.environ.get("PIISAFE_MASTER_KEY") else "local"
    if name not in ("local", "env", "aws-kms", "vault-transit"):
        raise KeyProviderError(f"unknown key provider '{name}' (local, env, aws-kms, vault-transit)")
    return name


def managed_provider(name: str) -> ManagedKeyProvider:
    if name == "aws-kms":
        return AwsKmsProvider()
    if name == "vault-transit":
        return VaultTransitProvider()
    raise KeyProviderError(f"'{name}' is not a managed key provider")


class AwsKmsProvider:
    name = "aws-kms"

    def __init__(self, key_id: str | None = None, region: str | None = None, client: Any = None) -> None:
        self.key_id = key_id or os.environ.get("PIISAFE_KMS_KEY_ID")
        if not self.key_id:
            raise KeyProviderError("aws-kms: set PIISAFE_KMS_KEY_ID to a KMS key ARN, key id or alias/…")
        if client is None:
            try:
                import boto3
            except ImportError as exc:
                raise KeyProviderError("aws-kms needs boto3: pip install 'piisafe[aws]'") from exc
            region = region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
            client = boto3.client("kms", region_name=region)
        self._kms = client

    def key_ref(self) -> str:
        return str(self.key_id)

    def wrap(self, plaintext: bytes) -> str:
        try:
            out = self._kms.encrypt(KeyId=self.key_id, Plaintext=plaintext, EncryptionContext=_CONTEXT)
        except Exception as exc:  # botocore.exceptions.*
            raise KeyProviderError(f"aws-kms encrypt failed: {exc}") from exc
        return base64.b64encode(out["CiphertextBlob"]).decode("ascii")

    def unwrap(self, wrapped: str) -> bytes:
        try:
            out = self._kms.decrypt(CiphertextBlob=base64.b64decode(wrapped), EncryptionContext=_CONTEXT,
                                    KeyId=self.key_id)
        except Exception as exc:
            raise KeyProviderError(f"aws-kms decrypt failed: {exc}") from exc
        return bytes(out["Plaintext"])


class VaultTransitProvider:
    name = "vault-transit"

    def __init__(
        self,
        addr: str | None = None,
        token: str | None = None,
        key: str | None = None,
        mount: str | None = None,
        namespace: str | None = None,
    ) -> None:
        self.addr = (addr or os.environ.get("VAULT_ADDR") or "").rstrip("/")
        self.token = token or os.environ.get("VAULT_TOKEN")
        self.key = key or os.environ.get("PIISAFE_VAULT_KEY") or "piisafe"
        self.mount = (mount or os.environ.get("PIISAFE_VAULT_MOUNT") or "transit").strip("/")
        self.namespace = namespace or os.environ.get("VAULT_NAMESPACE")
        if not self.addr or not self.token:
            raise KeyProviderError("vault-transit: set VAULT_ADDR and VAULT_TOKEN")
        cafile = os.environ.get("VAULT_CACERT")
        self._ssl = ssl.create_default_context(cafile=cafile) if cafile else None

    def key_ref(self) -> str:
        return f"{self.addr}/v1/{self.mount}/keys/{self.key}"

    def _post(self, op: str, body: dict[str, str]) -> dict[str, Any]:
        url = f"{self.addr}/v1/{self.mount}/{op}/{self.key}"
        headers = {"X-Vault-Token": str(self.token), "Content-Type": "application/json"}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10, context=self._ssl) as resp:
                return json.loads(resp.read())["data"]
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:200]
            raise KeyProviderError(f"vault-transit {op} failed: HTTP {exc.code} {detail}") from exc
        except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
            raise KeyProviderError(f"vault-transit {op} failed: {exc}") from exc

    def wrap(self, plaintext: bytes) -> str:
        return self._post("encrypt", {"plaintext": base64.b64encode(plaintext).decode()})["ciphertext"]

    def unwrap(self, wrapped: str) -> bytes:
        return base64.b64decode(self._post("decrypt", {"ciphertext": wrapped})["plaintext"])
