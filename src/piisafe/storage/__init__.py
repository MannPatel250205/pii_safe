"""Storage backends and the factory that picks one.

    open_store(None, state_dir)                     -> SQLite at <state_dir>/piisafe.db
    open_store("sqlite:///var/lib/piisafe/p.db")   -> SQLite at that path
    open_store("postgresql://user:pw@host/db")      -> PostgreSQL

The URL can also come from $PIISAFE_DATABASE_URL.
"""

from __future__ import annotations

import os
from pathlib import Path

from piisafe.storage.base import Store
from piisafe.storage.sql import SQLStore
from piisafe.storage.sqlite import SQLiteStore

DATABASE_URL_ENV = "PIISAFE_DATABASE_URL"
DB_FILE = "piisafe.db"


def database_url(explicit: str | None = None) -> str | None:
    return explicit or os.environ.get(DATABASE_URL_ENV) or None


def open_store(url: str | None, state_dir: Path | None = None) -> SQLStore:
    url = database_url(url)
    if url is None:
        if state_dir is None:
            return SQLiteStore(":memory:")
        return SQLiteStore(Path(state_dir) / DB_FILE)
    if url.startswith(("postgresql://", "postgres://")):
        from piisafe.storage.postgres import PostgresStore

        return PostgresStore(url)
    if url.startswith("sqlite:///"):
        return SQLiteStore(url[len("sqlite:///") - 1:] if url.startswith("sqlite:////") else url[len("sqlite:///"):])
    if url == "sqlite://" or url == ":memory:":
        return SQLiteStore(":memory:")
    if "://" in url:
        raise ValueError(f"unsupported database URL scheme: {url.split('://', 1)[0]}")
    return SQLiteStore(url)


def describe(url: str | None, state_dir: Path | None) -> str:
    """Human-readable location without credentials."""
    url = database_url(url)
    if url is None:
        return str(Path(state_dir) / DB_FILE) if state_dir else ":memory:"
    if "@" in url and "://" in url:
        scheme, rest = url.split("://", 1)
        return f"{scheme}://***@{rest.split('@', 1)[1]}"
    return url


__all__ = ["DATABASE_URL_ENV", "SQLStore", "SQLiteStore", "Store", "database_url", "describe", "open_store"]
