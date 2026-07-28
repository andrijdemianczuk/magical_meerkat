"""Tool shadowing — one tool impersonating or displacing another.

Surface-scoped (D-007). Neither tool in the payload fixture is suspicious on
its own: `send_emai1` has an honest-looking description and a plausible schema.
The attack is the *pair* — a name typographically indistinguishable from
`send_email` in a rendered tool list, attached to a claim that the real tool is
broken.

The control is an ordinary deprecation notice: `search_docs_v2` stating that
`search_docs` is deprecated and should not be used for new integrations. That
is what a well-maintained API looks like, and it carries the same supersession
language as the attack. So supersession is weight 0 here, and the discriminator
is name confusability:

* `send_email` and `send_emai1` collapse to the same string once you account for
  a digit standing in for a letter. That is a collision, not a relationship.
* `search_docs` and `search_docs_v2` share a prefix but stay distinct. `_v2` is
  a declared relationship.

Known gap: this covers homoglyph and separator squatting only. Transposition
(`send_meail`) and insertion (`send_emaill`) are not detected yet — an edit-
distance rule would catch them but also flags legitimate singular/plural pairs,
so it needs its own control fixture before it earns a weight.

Cross-*server* shadowing — one server's tool imitating another server's — is
invisible here. A single-endpoint scan cannot see it, and the report should not
imply otherwise.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import combinations
from typing import Literal

from sentinel.attacks import Finding, Mode, Signal, register
from sentinel.model import Tool

THRESHOLD = 3

# Characters that read as other characters in a proportional font: digits for
# letters, and Cyrillic lookalikes for Latin.
_CONFUSABLES = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "$": "s",
        # Cyrillic lookalikes, written as escapes so this table does not itself
        # contain the ambiguous characters it exists to catch.
        "\u0430": "a",  # CYRILLIC SMALL LETTER A
        "\u0435": "e",  # CYRILLIC SMALL LETTER IE
        "\u043e": "o",  # CYRILLIC SMALL LETTER O
        "\u0440": "p",  # CYRILLIC SMALL LETTER ER
        "\u0441": "c",  # CYRILLIC SMALL LETTER ES
        "\u0445": "x",  # CYRILLIC SMALL LETTER HA
        "\u0443": "y",  # CYRILLIC SMALL LETTER U
        "\u0456": "i",  # CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
        "\u0455": "s",  # CYRILLIC SMALL LETTER DZE
    }
)
_SEPARATORS = re.compile(r"[_\-.\s]+")

_SUPERSESSION = re.compile(
    r"\b(?:deprecated|instead of|rather than|prefer this|do not use|don't use"
    r"|superseded|replaced by|no longer|use this for all)\b",
    re.IGNORECASE,
)


def normalize(name: str) -> str:
    """Collapse a tool name to how it *reads* rather than how it is spelled."""
    return _SEPARATORS.sub("", name.lower()).translate(_CONFUSABLES)


def _claims_supersession_of(tool: Tool, other: str) -> str | None:
    """Whether `tool` tells the agent to use it in place of `other`."""
    description = tool.description or ""
    if other not in description:
        return None
    for sentence in re.split(r"(?<=[.!?])\s+", re.sub(r"\s+", " ", description)):
        if other in sentence and _SUPERSESSION.search(sentence):
            return sentence.strip()
    return None


@dataclass(frozen=True, slots=True)
class ToolShadowing:
    name: str = "tool_shadowing.confusable_names"
    attack_class: str = "tool_shadowing"
    mode: Mode = "passive"
    scope: Literal["surface"] = "surface"
    # Not MCP09 — "Shadow MCP Servers" is unsanctioned servers, a different
    # problem. This is the agent's intent being routed to the wrong tool.
    owasp: tuple[str, ...] = ("MCP06:2025", "ASI02:2026")

    def analyze_surface(self, tools: Sequence[Tool]) -> list[Finding]:
        findings: list[Finding] = []
        by_name = {t.name: t for t in tools}

        for left, right in combinations(sorted(by_name), 2):
            signals: list[Signal] = []

            if normalize(left) == normalize(right):
                signals.append(
                    Signal(
                        "confusable_tool_names",
                        3,
                        f"{left!r} and {right!r} are indistinguishable once digit and "
                        f"script lookalikes are resolved (both read as "
                        f"{normalize(left)!r})",
                    )
                )
            if any(ord(c) > 127 for c in left + right):
                offender = left if any(ord(c) > 127 for c in left) else right
                signals.append(
                    Signal(
                        "non_ascii_tool_name",
                        3,
                        f"{offender!r} contains non-ASCII characters",
                    )
                )

            # Fires on the benign deprecation notice too, so it cannot decide.
            aggressor = left
            for candidate, other in ((by_name[left], right), (by_name[right], left)):
                if claim := _claims_supersession_of(candidate, other):
                    aggressor = candidate.name
                    signals.append(
                        Signal(
                            "supersession_claim",
                            0,
                            f"{candidate.name!r} tells the agent to use it in place of "
                            f"{other!r}: {claim!r}",
                        )
                    )

            if not signals:
                continue
            score = sum(s.weight for s in signals)
            findings.append(
                Finding(
                    attack=self.name,
                    tool=aggressor,
                    detected=score >= THRESHOLD,
                    score=score,
                    threshold=THRESHOLD,
                    signals=tuple(signals),
                    owasp=self.owasp,
                )
            )

        return findings


register(ToolShadowing())
