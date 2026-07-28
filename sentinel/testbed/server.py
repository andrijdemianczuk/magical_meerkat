"""Serve a fixture as a real MCP server over stdio.

    python -m sentinel.testbed.server testbed/fixtures/tool-poisoning/exfil-ssh-key.yaml

This closes the loop: instead of handing `Tool` objects straight to a detector,
a scan can speak actual JSON-RPC to a process that advertises the fixture's
surface. Same corpus, same ground truth, real protocol.

> This process deliberately serves attack payloads. It is inert — it reads no
> files, opens no sockets, and executes nothing. `tools/call` returns whatever
> the fixture declared, so a payload claiming to exfiltrate a key returns a
> canary string. It speaks stdio only and cannot be reached over a network.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from sentinel import __version__
from sentinel.client.base import PROTOCOL_VERSION
from sentinel.testbed.loader import Fixture, load_fixture

METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602


class FixtureServer:
    """Answers MCP requests from a fixture's declared surface."""

    def __init__(self, fixture: Fixture) -> None:
        self.fixture = fixture
        self.tools = {t.name: t for t in fixture.tools}

    def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """One JSON-RPC message in, at most one reply out."""
        method = message.get("method")
        request_id = message.get("id")

        # Notifications carry no id and get no reply.
        if request_id is None:
            return None

        try:
            result = self._dispatch(method, message.get("params") or {})
        except LookupError as exc:
            return self._error(request_id, METHOD_NOT_FOUND, str(exc))
        except ValueError as exc:
            return self._error(request_id, INVALID_PARAMS, str(exc))
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _dispatch(self, method: str | None, params: dict[str, Any]) -> dict[str, Any]:
        match method:
            case "initialize":
                return {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": f"sentinel-testbed[{self.fixture.id}]",
                        "version": __version__,
                    },
                }
            case "ping":
                return {}
            case "tools/list":
                return {
                    "tools": [
                        {
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": t.input_schema,
                        }
                        for t in self.fixture.tools
                    ]
                }
            case "tools/call":
                name = params.get("name")
                if name not in self.tools:
                    raise ValueError(f"unknown tool {name!r}")
                returns = self.tools[name].returns
                return returns if returns else {"content": []}
            case _:
                raise LookupError(f"method not found: {method!r}")

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def serve(fixture: Fixture, stdin=None, stdout=None) -> None:
    """Read newline-delimited JSON-RPC until stdin closes."""
    stdin = stdin if stdin is not None else sys.stdin.buffer
    stdout = stdout if stdout is not None else sys.stdout.buffer
    server = FixtureServer(fixture)

    for raw in stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            message = json.loads(raw)
        except json.JSONDecodeError:
            continue
        reply = server.handle(message)
        if reply is not None:
            stdout.write((json.dumps(reply) + "\n").encode())
            stdout.flush()


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    serve(load_fixture(Path(args[0])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
