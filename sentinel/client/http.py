"""Streamable HTTP transport.

Uses `urllib` rather than a third-party HTTP client: the non-negotiable is that
this repo stays forkable with no secret-dependent setup, and every dependency
added here is one a forker has to install to run a demo.

A server may answer a POST with either `application/json` or an SSE stream, so
both are handled. Session continuity uses the `Mcp-Session-Id` header the server
issues during initialization.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from sentinel.client.base import BaseClient, ProtocolError, TransportError


class HttpClient(BaseClient):
    """Speaks JSON-RPC over HTTP POST to a single MCP endpoint."""

    def __init__(self, endpoint: str, *, headers: dict[str, str] | None = None, **kwargs: Any):
        super().__init__(**kwargs)
        if not endpoint.lower().startswith(("http://", "https://")):
            raise ValueError(f"endpoint must be an http(s) URL, got {endpoint!r}")
        self.endpoint = endpoint
        self.extra_headers = dict(headers or {})
        self.session_id: str | None = None

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": self.protocol_version,
            **self.extra_headers,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    def _send(self, payload: dict[str, Any], *, expect_response: bool) -> dict[str, Any] | None:
        request = urllib.request.Request(  # noqa: S310 - scheme validated in __init__
            self.endpoint,
            data=json.dumps(payload).encode(),
            headers=self._headers(),
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                if issued := response.headers.get("Mcp-Session-Id"):
                    self.session_id = issued
                body = response.read()
                content_type = response.headers.get("Content-Type", "")
                status = response.status
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:200]
            raise TransportError(f"HTTP {exc.code} from {self.endpoint}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError(f"could not reach {self.endpoint}: {exc}") from exc

        if not expect_response:
            return None
        if status == 202 or not body.strip():
            raise ProtocolError(f"server accepted {payload.get('method')!r} without replying")

        if "text/event-stream" in content_type:
            return self._first_sse_message(body)
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"server sent invalid JSON: {body[:200]!r}") from exc

    @staticmethod
    def _first_sse_message(body: bytes) -> dict[str, Any]:
        """The first `data:` payload in an SSE stream.

        Sentinel issues one request at a time, so the first message is the reply
        to it. Streaming multiple messages per request would need a real event
        loop and is not required for scanning.
        """
        for line in body.decode(errors="replace").splitlines():
            if line.startswith("data:"):
                chunk = line[5:].strip()
                if not chunk:
                    continue
                try:
                    return json.loads(chunk)
                except json.JSONDecodeError as exc:
                    raise ProtocolError(f"invalid JSON in SSE data: {chunk[:200]!r}") from exc
        raise ProtocolError("SSE response contained no data frames")

    def close(self) -> None:
        self.session_id = None
