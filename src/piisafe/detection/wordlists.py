"""Bundled word lists in piisafe/data (first names, product terms, ambiguous names)."""

from __future__ import annotations

from functools import cache
from importlib import resources


@cache
def word_list(name: str) -> frozenset[str]:
    """A list from piisafe/data: whitespace-separated, '#' comments, case-insensitive."""
    text = resources.files("piisafe").joinpath(f"data/{name}").read_text("utf-8")
    return frozenset(
        w.casefold() for line in text.splitlines() if not line.lstrip().startswith("#") for w in line.split()
    )


def product_terms() -> frozenset[str]:
    """Vendor, product and ops words that are not people or places."""
    return word_list("product_terms.txt")


def first_names() -> frozenset[str]:
    """Given names, minus those that are also everyday words ('will', 'mark')."""
    return word_list("first_names.txt") - word_list("ambiguous_names.txt")
