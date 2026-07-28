"""Plaintext scan report.

Two rules shape this output.

**Never print a pass.** There is no "SECURE" line and no green checkmark. The
corpus is small, the detectors are heuristic, and the classes covered are a
subset of the classes that exist — a clean scan means "none of the checks that
ran fired", and the report says exactly that and nothing more.

**Coverage is a first-class section.** What was not checked is rendered with the
same weight as what was, because that is the part an operator will otherwise
assume. Skipped attacks, uncovered classes, and tools that could not be probed
all appear whether or not anything was found.
"""

from __future__ import annotations

from sentinel import __version__, owasp
from sentinel.attacks import Finding, registry
from sentinel.scan import ScanResult

WIDTH = 78
RULE = "─" * WIDTH


def _header(result: ScanResult) -> list[str]:
    server = result.server
    lines = [
        f"MCP Sentinel {__version__} — scan report",
        "═" * WIDTH,
        f"  Target       {result.endpoint}",
    ]
    if server:
        lines.append(f"  Server       {server.name} {server.version}")
        lines.append(f"  Protocol     {server.protocol_version}")
    lines.append(f"  Scanned      {result.scanned_at}")
    lines.append(f"  Mode         {'active (tools were invoked)' if result.active else 'passive'}")
    lines.append(f"  Tools        {len(result.tools)}")
    if result.baseline:
        lines.append(
            f"  Baseline     {result.baseline.endpoint} captured {result.baseline.captured_at}"
        )
    else:
        lines.append("  Baseline     none — change-based checks did not run")
    return lines


def _finding(index: int, finding: Finding) -> list[str]:
    lines = [
        f"[{index}] {finding.attack}",
        f"     tool      {finding.tool}",
        f"     score     {finding.score} (threshold {finding.threshold})",
    ]
    for position, identifier in enumerate(finding.owasp):
        label = "     owasp    " if position == 0 else " " * 14
        lines.append(f"{label} {owasp.describe(identifier)}")

    lines.append("     evidence")
    for signal in finding.fired:
        lines.append(f"       + [{signal.weight}] {signal.name}")
        lines.append(f"             {signal.evidence}")
    if finding.informational:
        lines.append("     also observed (not decisive)")
        for signal in finding.informational:
            lines.append(f"         [0] {signal.name}")
            lines.append(f"             {signal.evidence}")
    return lines


def _findings_section(result: ScanResult) -> list[str]:
    detected = result.detected
    lines = [f"FINDINGS ({len(detected)})", RULE]
    if not detected:
        lines.append("  Nothing fired. This is not a clean bill of health — see COVERAGE.")
        return lines
    for index, finding in enumerate(detected, start=1):
        lines.extend(_finding(index, finding))
        lines.append("")
    return lines[:-1] if lines[-1] == "" else lines


def _coverage_section(result: ScanResult) -> list[str]:
    lines = ["COVERAGE", RULE]
    attacks = registry()

    for name in result.ran:
        attack = attacks[name]
        lines.append(f"  ran        {attack.attack_class:<28} {name}")
    for skip in result.skipped:
        lines.append(f"  SKIPPED    {skip.attack_class:<28} {skip.attack}")
        lines.append(f"             └─ {skip.reason}")
    for attack_class in result.uncovered_classes:
        lines.append(f"  NO CHECK   {attack_class:<28} no detector exists for this class")
    for failure in result.probe_failures:
        lines.append(f"  NOT PROBED {failure.tool:<28} {failure.reason}")
    return lines


def _limitations() -> list[str]:
    return [
        "LIMITATIONS",
        RULE,
        "  A finding is a lead to investigate, not a verdict. Detection is",
        "  heuristic and both false positives and false negatives are expected.",
        "",
        "  No finding does not mean the server is safe. It means none of the",
        "  checks listed above fired. Classes marked SKIPPED or NO CHECK were",
        "  never examined.",
        "",
        "  Scope is the MCP tool boundary. This says nothing about the agent's",
        "  reasoning, the model, or the surrounding application.",
        "",
        "  Cross-server shadowing is invisible to a single-endpoint scan.",
        "",
        f"  OWASP mappings follow MCP Top 10 {owasp.MCP_TOP_10_VERSION} and",
        f"  Agentic Top 10 {owasp.ASI_TOP_10_VERSION}. Both frameworks are moving.",
    ]


def render(result: ScanResult) -> str:
    """The whole report as one string."""
    blocks = [
        _header(result),
        [""],
        _findings_section(result),
        [""],
        _coverage_section(result),
        [""],
        _limitations(),
    ]
    return "\n".join(line for block in blocks for line in block) + "\n"
