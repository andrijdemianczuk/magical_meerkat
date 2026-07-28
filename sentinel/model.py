"""Core types shared by the client, the testbed, and detectors.

`Tool` is the seam. A fixture builds one from declared YAML; a live client
builds one from `tools/list` and fills `returns` from an actual `tools/call`.
Detectors cannot tell the difference, which is what lets the corpus and a real
scan exercise identical code.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any


@dataclass(frozen=True, slots=True)
class Tool:
    """One tool as a server advertises it in `tools/list`."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    returns: dict[str, Any] | None = None

    @property
    def response_text(self) -> str:
        """Concatenated text blocks from this tool's response, or ''.

        Empty means the tool has not been invoked (or returned no text), which
        is the normal state during a passive scan.
        """
        if not self.returns:
            return ""
        blocks = self.returns.get("content", [])
        return "\n".join(b.get("text", "") for b in blocks if b.get("type") == "text")

    def with_response(self, result: dict[str, Any] | None) -> Tool:
        """Copy carrying a `tools/call` result. Used by active scans."""
        return replace(self, returns=result)

    @classmethod
    def from_wire(cls, payload: dict[str, Any]) -> Tool:
        """Build from a `tools/list` entry."""
        return cls(
            name=payload["name"],
            description=payload.get("description", ""),
            input_schema=payload.get("inputSchema", {}),
        )


@dataclass(frozen=True, slots=True)
class ServerInfo:
    """What a server reports during `initialize`."""

    name: str
    version: str
    protocol_version: str
    capabilities: dict[str, Any] = field(default_factory=dict)
