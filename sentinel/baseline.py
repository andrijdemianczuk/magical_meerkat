"""Approved-surface snapshots and the diffs between them.

Rug-pull is the one attack class that cannot be decided from a single scan: a
tool description is only "changed" relative to what someone approved earlier.
That makes a baseline a first-class artifact rather than a cache — it is the
record of what a human agreed to run.

Snapshots store full text, not just digests. A report that says "the description
changed" without showing what it changed *to* leaves the operator to go and find
out, which is the moment they are most likely to skip.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.model import Tool

SNAPSHOT_VERSION = 1


class BaselineError(Exception):
    """A snapshot file is missing, malformed, or from an incompatible version."""


def digest(tool: Tool) -> str:
    """Stable hash over everything a server can change without renaming a tool."""
    payload = json.dumps(
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.input_schema,
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class Snapshot:
    """A tool surface as it stood when someone approved it."""

    endpoint: str
    captured_at: str
    tools: tuple[Tool, ...]
    protocol_version: str = ""

    @property
    def by_name(self) -> dict[str, Tool]:
        return {t.name: t for t in self.tools}

    def to_json(self) -> dict[str, Any]:
        return {
            "snapshotVersion": SNAPSHOT_VERSION,
            "endpoint": self.endpoint,
            "capturedAt": self.captured_at,
            "protocolVersion": self.protocol_version,
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                    "digest": digest(t),
                }
                for t in self.tools
            ],
        }

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> Snapshot:
        version = payload.get("snapshotVersion")
        if version != SNAPSHOT_VERSION:
            raise BaselineError(
                f"snapshot version {version!r} is not supported (expected {SNAPSHOT_VERSION})"
            )
        return cls(
            endpoint=payload.get("endpoint", ""),
            captured_at=payload.get("capturedAt", ""),
            protocol_version=payload.get("protocolVersion", ""),
            tools=tuple(
                Tool(
                    name=t["name"],
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", {}),
                )
                for t in payload.get("tools", [])
            ),
        )


def capture(
    tools: tuple[Tool, ...] | list[Tool],
    *,
    endpoint: str,
    captured_at: str,
    protocol_version: str = "",
) -> Snapshot:
    """Snapshot a surface. `captured_at` is passed in so callers own the clock."""
    return Snapshot(
        endpoint=endpoint,
        captured_at=captured_at,
        tools=tuple(tools),
        protocol_version=protocol_version,
    )


def save(snapshot: Snapshot, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(snapshot.to_json(), indent=2, ensure_ascii=False) + "\n")


def load(path: Path) -> Snapshot:
    try:
        payload = json.loads(path.read_text())
    except FileNotFoundError:
        raise BaselineError(f"no baseline at {path}") from None
    except json.JSONDecodeError as exc:
        raise BaselineError(f"{path}: not valid JSON ({exc})") from None
    if not isinstance(payload, dict):
        raise BaselineError(f"{path}: expected a JSON object")
    return Snapshot.from_json(payload)


@dataclass(frozen=True, slots=True)
class ToolChange:
    """One tool that exists in both surfaces but is no longer identical."""

    name: str
    previous: Tool
    current: Tool

    @property
    def description_changed(self) -> bool:
        return self.previous.description != self.current.description

    @property
    def schema_changed(self) -> bool:
        return self.previous.input_schema != self.current.input_schema


@dataclass(frozen=True, slots=True)
class SurfaceDiff:
    """What moved between an approved surface and the one being scanned."""

    added: tuple[Tool, ...] = ()
    removed: tuple[Tool, ...] = ()
    changed: tuple[ToolChange, ...] = ()
    unchanged: tuple[Tool, ...] = field(default=())

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.changed)


def diff(
    previous: Snapshot | tuple[Tool, ...],
    current: tuple[Tool, ...] | list[Tool],
) -> SurfaceDiff:
    """Compare an approved surface against a current one, keyed by tool name."""
    before = previous.by_name if isinstance(previous, Snapshot) else {t.name: t for t in previous}
    after = {t.name: t for t in current}

    added = tuple(after[n] for n in sorted(set(after) - set(before)))
    removed = tuple(before[n] for n in sorted(set(before) - set(after)))
    changed: list[ToolChange] = []
    unchanged: list[Tool] = []
    for name in sorted(set(before) & set(after)):
        if digest(before[name]) == digest(after[name]):
            unchanged.append(after[name])
        else:
            changed.append(ToolChange(name=name, previous=before[name], current=after[name]))

    return SurfaceDiff(
        added=added,
        removed=removed,
        changed=tuple(changed),
        unchanged=tuple(unchanged),
    )
