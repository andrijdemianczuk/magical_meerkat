"""OWASP framework catalogs, as data.

Every identifier an attack claims is resolved against these tables, so an
invented or mistyped ID fails at import rather than reaching a report. A
governance scorecard citing a category that does not exist is worse than one
citing none.

Both frameworks are young and still moving. Reports state the version they were
generated against — see `MCP_TOP_10_VERSION` and `ASI_TOP_10_VERSION` — because
a mapping is only meaningful alongside the revision it was made from.

Sources:
  https://owasp.org/www-project-mcp-top-10/
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
"""

from __future__ import annotations

from types import MappingProxyType

MCP_TOP_10_VERSION = "v0.1 (Beta, Phase 3)"
ASI_TOP_10_VERSION = "v2.01 (2026-06-01)"

MCP_TOP_10 = MappingProxyType(
    {
        "MCP01:2025": "Token Mismanagement & Secret Exposure",
        "MCP02:2025": "Privilege Escalation via Scope Creep",
        "MCP03:2025": "Tool Poisoning",
        "MCP04:2025": "Software Supply Chain Attacks & Dependency Tampering",
        "MCP05:2025": "Command Injection & Execution",
        "MCP06:2025": "Intent Flow Subversion",
        "MCP07:2025": "Insufficient Authentication & Authorization",
        "MCP08:2025": "Lack of Audit and Telemetry",
        "MCP09:2025": "Shadow MCP Servers",
        "MCP10:2025": "Context Injection & Over-Sharing",
    }
)

ASI_TOP_10 = MappingProxyType(
    {
        "ASI01:2026": "Agent Goal Hijack",
        "ASI02:2026": "Tool Misuse & Exploitation",
        "ASI03:2026": "Agent Identity & Privilege Abuse",
        "ASI04:2026": "Agentic Supply Chain Compromise",
        "ASI05:2026": "Unexpected Code Execution",
        "ASI06:2026": "Memory & Context Poisoning",
        "ASI07:2026": "Insecure Inter-Agent Communication",
        "ASI08:2026": "Cascading Agent Failures",
        "ASI09:2026": "Human-Agent Trust Exploitation",
        "ASI10:2026": "Rogue Agents",
    }
)

CATALOG = MappingProxyType({**MCP_TOP_10, **ASI_TOP_10})


class UnknownCategory(KeyError):
    """An attack referenced an OWASP identifier that does not exist."""


def title(identifier: str) -> str:
    """Full title for an identifier, raising if it is not in either catalog."""
    try:
        return CATALOG[identifier]
    except KeyError:
        raise UnknownCategory(
            f"{identifier!r} is not in the OWASP MCP Top 10 or Agentic Top 10. "
            f"Known: {', '.join(sorted(CATALOG))}"
        ) from None


def describe(identifier: str) -> str:
    """`MCP03:2025 — Tool Poisoning`, for report output."""
    return f"{identifier} — {title(identifier)}"


def validate(identifiers: tuple[str, ...]) -> tuple[str, ...]:
    """Return the identifiers, raising on the first unknown one."""
    for identifier in identifiers:
        title(identifier)
    return identifiers
