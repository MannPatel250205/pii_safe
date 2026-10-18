"""Exception hierarchy. Every error raised by the SDK derives from PIISafeError."""

from __future__ import annotations

from collections.abc import Iterable


class PIISafeError(Exception):
    """Base class for all PII-Safe errors."""


class PolicyError(PIISafeError):
    """The policy file is missing, malformed or fails validation."""


class PolicyBlockError(PIISafeError):
    """A `block` rule matched: the input must not proceed past this hook."""

    def __init__(self, entity_types: Iterable[str], hook_type: str, policy_name: str | None) -> None:
        self.entity_types = sorted(set(entity_types))
        self.hook_type = hook_type
        self.policy_name = policy_name
        where = f"policy '{policy_name}'" if policy_name else "default policy"
        super().__init__(
            f"{where} blocks {', '.join(self.entity_types)} at hook '{hook_type}'"
        )


class KeyMismatchError(PIISafeError):
    """The supplied key does not belong to this session."""


class SessionNotFoundError(PIISafeError):
    """The requested session does not exist in the store."""


class AliasNotFoundError(PIISafeError):
    """The alias is not known in this session."""
