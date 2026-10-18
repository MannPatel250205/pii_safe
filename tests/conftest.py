from __future__ import annotations

from pathlib import Path

import pytest

from piisafe import PIISafeGuard

TESTS = Path(__file__).parent


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark tests by folder: tests/unit -> `unit`, tests/integration -> `integration`."""
    for item in items:
        parts = Path(item.fspath).relative_to(TESTS).parts
        if parts[0] in ("unit", "integration"):
            item.add_marker(parts[0])


@pytest.fixture
def guard() -> PIISafeGuard:
    g = PIISafeGuard(session_id="test", ephemeral=True)
    yield g
    g.close()


@pytest.fixture
def heuristic_guard() -> PIISafeGuard:
    """Tier 2 without spaCy, so results don't depend on the optional model."""
    g = PIISafeGuard(session_id="test-h", ephemeral=True, ner="heuristic")
    yield g
    g.close()


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("PIISAFE_MASTER_KEY", raising=False)
    monkeypatch.setenv("PIISAFE_HOME", str(tmp_path / "state"))
    return tmp_path / "state"
