"""stdio transport — the target runs as a local subprocess.

Most MCP servers in the wild are launched this way from a client config rather
than reached at a URL, so a scanner that only speaks HTTP misses the common
case.

This transport has its own threat model: scanning over stdio means *executing*
the target. The command is taken as an argument vector and never goes through a
shell, so a server string cannot smuggle in `; rm -rf`. Deciding whether to run
an untrusted command at all is the operator's call, not something this class
can make safe.
"""

from __future__ import annotations

import json
import selectors
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from sentinel.client.base import BaseClient, ProtocolError, TransportError


class StdioClient(BaseClient):
    """Speaks line-delimited JSON-RPC to a subprocess."""

    def __init__(
        self,
        command: Sequence[str],
        *,
        cwd: Path | str | None = None,
        env: Mapping[str, str] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        if isinstance(command, str) or not command:
            raise ValueError("command must be a non-empty argument vector, not a shell string")
        self.command = list(command)
        try:
            self._proc = subprocess.Popen(  # noqa: S603 - argv form, shell=False
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                env=dict(env) if env is not None else None,
                shell=False,
            )
        except OSError as exc:
            raise TransportError(f"could not start {self.command[0]!r}: {exc}") from exc

        self._buffer = b""
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._proc.stdout, selectors.EVENT_READ)

    def _send(self, payload: dict[str, Any], *, expect_response: bool) -> dict[str, Any] | None:
        if self._proc.poll() is not None:
            raise TransportError(f"server exited with code {self._proc.returncode}{self._stderr()}")
        try:
            self._proc.stdin.write(self.encode(payload))
            self._proc.stdin.flush()
        except (BrokenPipeError, ValueError) as exc:
            raise TransportError(f"server closed its input: {exc}{self._stderr()}") from exc

        if not expect_response:
            return None

        line = self._read_line()
        try:
            return json.loads(line)
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"server sent invalid JSON: {line[:200]!r}") from exc

    def _read_line(self) -> bytes:
        """One newline-delimited message, or TransportError on timeout.

        A target that simply stops responding must not hang the scan.
        """
        deadline = time.monotonic() + self.timeout
        while b"\n" not in self._buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportError(f"no response within {self.timeout}s{self._stderr()}")
            if not self._selector.select(timeout=remaining):
                continue
            chunk = self._proc.stdout.read1(65536)
            if not chunk:
                raise TransportError(f"server closed its output{self._stderr()}")
            self._buffer += chunk
        line, _, self._buffer = self._buffer.partition(b"\n")
        return line

    def _stderr(self) -> str:
        """Whatever the server complained about, for the error message."""
        try:
            self._proc.stderr.flush()
        except (ValueError, OSError):
            return ""
        # Only safe to drain once the process is gone; otherwise this blocks.
        if self._proc.poll() is None:
            return ""
        text = self._proc.stderr.read().decode(errors="replace").strip()
        return f"\nserver stderr:\n{text}" if text else ""

    def close(self) -> None:
        self._selector.close()
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5)
        for stream in (self._proc.stdin, self._proc.stdout, self._proc.stderr):
            if stream and not stream.closed:
                stream.close()
