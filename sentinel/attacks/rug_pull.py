"""Rug-pull — a tool's definition changes after a human approved it.

Baseline-scoped (D-007): a description is only "changed" relative to one someone
agreed to run. No single scan can decide this, which is why the fixture schema
could not express it until `baseline:` was added.

The naive detector flags any change. That is useless — healthy software changes
constantly, and a scanner that fires on every docs improvement gets muted within
a week. `description_changed_after_approval` therefore fires on both fixtures at
weight 0.

The discriminator is what the change *introduced*. This detector re-runs the
passive tool-scoped detectors against the old and new definitions and fires only
when something now detects that did not before. Composing rather than
re-implementing means every future passive attack automatically becomes a
rug-pull trigger, and the two can never drift apart.

Consequences worth stating in a report:

* A change that introduces an attack this project has no detector for looks
  exactly like a benign edit. Recall here is bounded by the passive corpus.
* An approved-but-already-poisoned tool produces no finding. It was malicious
  before the baseline was taken, so nothing changed. Baselines record what was
  approved, not what was safe.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from sentinel.attacks import Finding, Mode, Signal, register, registry
from sentinel.baseline import ToolChange, diff
from sentinel.model import Tool

THRESHOLD = 3


def _passive_tool_attacks() -> list:
    """Passive per-tool detectors, which are what a diff can be re-judged with.

    Surface- and baseline-scoped attacks are excluded: the first needs the whole
    set, and the second is this one.
    """
    return [
        a
        for a in registry().values()
        if a.scope == "tool" and a.mode == "passive" and a.attack_class != "rug_pull"
    ]


def _newly_detected(change: ToolChange) -> list[tuple[str, Finding]]:
    """Detectors that fire on the current definition but not the approved one."""
    introduced = []
    for attack in _passive_tool_attacks():
        before = attack.analyze(change.previous)
        after = attack.analyze(change.current)
        if after.detected and not before.detected:
            introduced.append((attack.name, after))
    return introduced


@dataclass(frozen=True, slots=True)
class RugPull:
    name: str = "rug_pull.definition_changed_after_approval"
    attack_class: str = "rug_pull"
    mode: Mode = "passive"
    scope: Literal["baseline"] = "baseline"
    owasp: tuple[str, ...] = ("MCP04:2025", "ASI04:2026")

    def analyze_change(
        self, previous: Sequence[Tool], current: Sequence[Tool]
    ) -> list[Finding]:
        surface = diff(tuple(previous), tuple(current))
        findings: list[Finding] = []

        for change in surface.changed:
            signals: list[Signal] = []

            for attack_name, introduced in _newly_detected(change):
                fired = ", ".join(s.name for s in introduced.fired)
                signals.append(
                    Signal(
                        "poisoning_introduced_after_approval",
                        3,
                        f"{attack_name} now fires on {change.name!r} but did not on the "
                        f"approved definition ({fired})",
                    )
                )

            # Both fixtures changed. Change alone cannot decide anything.
            if change.description_changed:
                signals.append(
                    Signal(
                        "description_changed_after_approval",
                        0,
                        f"{change.name!r} description changed since the baseline "
                        f"({len(change.previous.description)} -> "
                        f"{len(change.current.description)} chars)",
                    )
                )
            if change.schema_changed:
                signals.append(
                    Signal(
                        "schema_changed_after_approval",
                        0,
                        f"{change.name!r} input schema changed since the baseline",
                    )
                )

            score = sum(s.weight for s in signals)
            findings.append(
                Finding(
                    attack=self.name,
                    tool=change.name,
                    detected=score >= THRESHOLD,
                    score=score,
                    threshold=THRESHOLD,
                    signals=tuple(signals),
                    owasp=self.owasp,
                )
            )

        # Appearing and disappearing tools are reported, never decisive: servers
        # legitimately ship and retire tools between scans.
        for tool in surface.added:
            findings.append(
                self._informational(tool.name, "tool_added_after_approval", "not in the baseline")
            )
        for tool in surface.removed:
            findings.append(
                self._informational(
                    tool.name, "tool_removed_after_approval", "in the baseline but no longer served"
                )
            )

        return findings

    def _informational(self, tool: str, signal: str, evidence: str) -> Finding:
        return Finding(
            attack=self.name,
            tool=tool,
            detected=False,
            score=0,
            threshold=THRESHOLD,
            signals=(Signal(signal, 0, f"{tool!r} {evidence}"),),
            owasp=self.owasp,
        )


register(RugPull())
