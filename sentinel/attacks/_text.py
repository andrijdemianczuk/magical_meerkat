"""Shared text helpers for detectors.

Underscore-prefixed so registry discovery skips it — this module registers
nothing.
"""

from __future__ import annotations

import re


def sentences(text: str) -> list[str]:
    """Split into sentences, collapsing wrapped lines first.

    Tool descriptions and response bodies are hard-wrapped, so a single
    instruction routinely spans a newline. Splitting on lines would cut
    sentences in half and lose the co-occurrence detectors depend on.
    """
    normalized = re.sub(r"\s+", " ", text).strip()
    return [s for s in re.split(r"(?<=[.!?])\s+", normalized) if s]


def first_match(pattern: re.Pattern[str], text: str) -> str | None:
    """The first matching span, or None."""
    m = pattern.search(text)
    return m.group(0) if m else None
