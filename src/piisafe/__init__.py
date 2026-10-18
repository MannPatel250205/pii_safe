"""PII-Safe — privacy guard for agentic AI and MCP workflows."""

from piisafe._version import __version__
from piisafe.exceptions import (
    AliasNotFoundError,
    KeyMismatchError,
    PIISafeError,
    PolicyBlockError,
    PolicyError,
    SessionNotFoundError,
)
from piisafe.guard import PIISafeGuard
from piisafe.models import Action, Decision, Finding, SanitiseResult
from piisafe.policy import Policy

__all__ = [
    "Action",
    "AliasNotFoundError",
    "Decision",
    "Finding",
    "KeyMismatchError",
    "PIISafeError",
    "PIISafeGuard",
    "Policy",
    "PolicyBlockError",
    "PolicyError",
    "SanitiseResult",
    "SessionNotFoundError",
    "__version__",
]
