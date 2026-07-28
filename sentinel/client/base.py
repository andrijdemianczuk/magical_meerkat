"""JSON-RPC session logic shared by every transport.

Two safety properties are enforced here rather than in the CLI, so they hold for
any caller:

* `call_tool` raises unless the client was constructed with
  `allow_invocation=True`. A passive scan physically cannot invoke a target's
  tools, which is D-002 made structural instead of conventional.
* Every request carries a timeout. A scanner that blocks forever on a
  deliberately unresponsive server is a denial of service against itself.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

from sentinel import __version__
from sentinel.model import ServerInfo, Tool

# https://modelcontextprotocol.io/specification/versioning
PROTOCOL_VERSION = "2025-11-25"

CLIENT_INFO = {"name": "mcp-sentinel", "version": __version__}

DEFAULT_TIMEOUT = 30.0
MAX_TOOL_PAGES = 100


class MCPError(Exception):
    """Base for client failures."""


class TransportError(MCPError):
    """The transport failed — process died, connection refused, timeout."""


class ProtocolError(MCPError):
    """The peer replied, but not with something usable."""


class InvocationNotPermitted(MCPError):
    """Attempted `tools/call` on a client that was not opened for active use."""


class BaseClient(ABC):
    """A JSON-RPC 2.0 MCP session over some transport."""

    def __init__(
        self,
        *,
        allow_invocation: bool = False,
        timeout: float = DEFAULT_TIMEOUT,
        protocol_version: str = PROTOCOL_VERSION,
    ) -> None:
        self.allow_invocation = allow_invocation
        self.timeout = timeout
        self.protocol_version = protocol_version
        self.server_info: ServerInfo | None = None
        self._next = 0

    # --- transport hooks -------------------------------------------------

    @abstractmethod
    def _send(self, payload: dict[str, Any], *, expect_response: bool) -> dict[str, Any] | None:
        """Send one JSON-RPC message, returning the reply when one is expected."""

    @abstractmethod
    def close(self) -> None:
        """Release the transport."""

    # --- JSON-RPC --------------------------------------------------------

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._next += 1
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": self._next, "method": method}
        if params is not None:
            payload["params"] = params

        reply = self._send(payload, expect_response=True)
        if reply is None:
            raise ProtocolError(f"no reply to {method!r}")
        if "error" in reply:
            err = reply["error"]
            raise ProtocolError(
                f"{method} failed: {err.get('message', 'unknown error')} "
                f"(code {err.get('code', '?')})"
            )
        result = reply.get("result")
        if not isinstance(result, dict):
            raise ProtocolError(f"{method} returned no result object")
        return result

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._send(payload, expect_response=False)

    # --- MCP -------------------------------------------------------------

    def initialize(self) -> ServerInfo:
        """Handshake. Records what the server reports about itself."""
        result = self.request(
            "initialize",
            {
                "protocolVersion": self.protocol_version,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
        )
        info = result.get("serverInfo", {})
        self.server_info = ServerInfo(
            name=info.get("name", "<unnamed>"),
            version=info.get("version", "<unknown>"),
            protocol_version=result.get("protocolVersion", "<unknown>"),
            capabilities=result.get("capabilities", {}),
        )
        self.notify("notifications/initialized")
        return self.server_info

    def list_tools(self) -> list[Tool]:
        """Every advertised tool, following pagination.

        This is the entire attack surface for a passive scan — no tool is
        invoked to obtain it.
        """
        tools: list[Tool] = []
        cursor: str | None = None
        for _ in range(MAX_TOOL_PAGES):
            params = {"cursor": cursor} if cursor else None
            result = self.request("tools/list", params)
            for entry in result.get("tools", []):
                try:
                    tools.append(Tool.from_wire(entry))
                except KeyError as exc:
                    raise ProtocolError(f"tool entry missing {exc}") from None
            cursor = result.get("nextCursor")
            if not cursor:
                return tools
        raise ProtocolError(f"tools/list did not terminate within {MAX_TOOL_PAGES} pages")

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Invoke a tool. Real side effects on a real server.

        Gated on `allow_invocation` because the target's tools may be
        `send_email` or `delete_repo`, and a scan should not be able to fire
        those by accident.
        """
        if not self.allow_invocation:
            raise InvocationNotPermitted(
                f"refusing to call {name!r}: client opened without allow_invocation. "
                "Active scanning has side effects on the target and must be opted into."
            )
        return self.request("tools/call", {"name": name, "arguments": arguments or {}})

    def probe(self, tool: Tool, arguments: dict[str, Any] | None = None) -> Tool:
        """Invoke `tool` and return a copy carrying its response."""
        return tool.with_response(self.call_tool(tool.name, arguments))

    # --- context manager -------------------------------------------------

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @staticmethod
    def encode(payload: dict[str, Any]) -> bytes:
        return (json.dumps(payload) + "\n").encode()
