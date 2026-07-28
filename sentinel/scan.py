"""Scan orchestration — connect, enumerate, run the applicable attacks.

The important output is not the findings list. It is `ScanResult.skipped`: every
attack that did *not* run, and why. A scanner that quietly checks three of five
classes and prints "no findings" has told the operator something false, and the
report renders coverage as prominently as results because of it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sentinel.attacks import Attack, Finding, registry, run
from sentinel.baseline import Snapshot
from sentinel.client.base import BaseClient, MCPError
from sentinel.model import ServerInfo, Tool
from sentinel.testbed.loader import ATTACK_CLASSES

PLACEHOLDERS: dict[str, Any] = {
    "string": "sentinel-probe",
    "integer": 1,
    "number": 1,
    "boolean": False,
    "array": [],
    "object": {},
}


@dataclass(frozen=True, slots=True)
class Skipped:
    """An attack that was not run, and the reason a reader needs to see."""

    attack: str
    attack_class: str
    reason: str


@dataclass(frozen=True, slots=True)
class ProbeFailure:
    """A tool that could not be invoked during an active scan."""

    tool: str
    reason: str


@dataclass(frozen=True, slots=True)
class ScanResult:
    endpoint: str
    scanned_at: str
    tools: tuple[Tool, ...]
    findings: tuple[Finding, ...]
    active: bool
    server: ServerInfo | None = None
    baseline: Snapshot | None = None
    ran: tuple[str, ...] = ()
    skipped: tuple[Skipped, ...] = ()
    probe_failures: tuple[ProbeFailure, ...] = ()

    @property
    def detected(self) -> tuple[Finding, ...]:
        """Findings that crossed their threshold, worst first."""
        return tuple(sorted((f for f in self.findings if f.detected), key=lambda f: -f.score))

    @property
    def uncovered_classes(self) -> tuple[str, ...]:
        """Attack classes with no detector at all."""
        covered = {a.attack_class for a in registry().values()}
        return tuple(sorted(ATTACK_CLASSES - covered))


def minimal_arguments(schema: dict[str, Any]) -> dict[str, Any]:
    """Placeholder arguments satisfying a tool's required fields.

    Invoking with `{}` fails schema validation on most real servers, so an
    active scan that sends nothing tests nothing. Values are inert markers —
    the goal is a response to inspect, not a meaningful call.
    """
    properties = schema.get("properties", {}) or {}
    arguments: dict[str, Any] = {}
    for name in schema.get("required", []) or []:
        spec = properties.get(name, {})
        if spec.get("enum"):
            arguments[name] = spec["enum"][0]
        else:
            arguments[name] = PLACEHOLDERS.get(spec.get("type", "string"), "sentinel-probe")
    return arguments


def _applicable(attack: Attack, *, active: bool, has_baseline: bool) -> str | None:
    """Why this attack cannot run now, or None if it can."""
    if attack.mode == "active" and not active:
        return "requires --active (invokes tools on the target)"
    if attack.scope == "baseline" and not has_baseline:
        return "requires a baseline to compare against"
    return None


def scan(
    client: BaseClient,
    *,
    scanned_at: str,
    endpoint: str = "",
    active: bool = False,
    baseline: Snapshot | None = None,
) -> ScanResult:
    """Run every applicable attack against a target.

    `scanned_at` is passed in rather than read from the clock so callers own
    timestamps and results stay reproducible.
    """
    server = client.initialize()
    tools = tuple(client.list_tools())
    probe_failures: list[ProbeFailure] = []

    if active:
        probed: list[Tool] = []
        for tool in tools:
            try:
                probed.append(client.probe(tool, minimal_arguments(tool.input_schema)))
            except MCPError as exc:
                # A tool that refuses to run is not a finding; it is a gap in
                # coverage, and saying so beats silently analyzing "".
                probe_failures.append(ProbeFailure(tool=tool.name, reason=str(exc)))
                probed.append(tool)
        tools = tuple(probed)

    findings: list[Finding] = []
    ran: list[str] = []
    skipped: list[Skipped] = []
    baseline_tools = baseline.tools if baseline else None

    for attack in sorted(registry().values(), key=lambda a: a.name):
        if reason := _applicable(attack, active=active, has_baseline=baseline is not None):
            skipped.append(Skipped(attack.name, attack.attack_class, reason))
            continue
        ran.append(attack.name)
        findings.extend(run(attack, tools, baseline=baseline_tools))

    return ScanResult(
        endpoint=endpoint or getattr(client, "endpoint", "") or "stdio",
        scanned_at=scanned_at,
        server=server,
        tools=tools,
        findings=tuple(findings),
        active=active,
        baseline=baseline,
        ran=tuple(ran),
        skipped=tuple(skipped),
        probe_failures=tuple(probe_failures),
    )
