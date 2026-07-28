"""MCP clients — the only code that touches a target.

Transport choice is a scoping decision, not a detail: stdio means executing the
target locally, HTTP means reaching one over a network. Both produce the same
`Tool` objects, so detectors never learn which was used.
"""

from sentinel.client.base import (
    PROTOCOL_VERSION,
    BaseClient,
    InvocationNotPermitted,
    MCPError,
    ProtocolError,
    TransportError,
)
from sentinel.client.http import HttpClient
from sentinel.client.stdio import StdioClient

__all__ = [
    "PROTOCOL_VERSION",
    "BaseClient",
    "HttpClient",
    "InvocationNotPermitted",
    "MCPError",
    "ProtocolError",
    "StdioClient",
    "TransportError",
]
