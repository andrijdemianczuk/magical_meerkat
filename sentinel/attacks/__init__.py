"""Attack modules and the registry they register themselves into (D-001).

Adding an attack means adding one file in this package that calls `register`.
Import-time discovery below is the "slight import-time magic" D-001 accepted in
exchange for zero central wiring.

Two axes describe every attack.

`mode` splits by side effects (D-002):

* `passive` — decided from the declared surface (`tools/list`). Safe against any
  target.
* `active`  — requires invoking tools. Opt-in, never the default.

`scope` splits by what the detector has to see (D-007):

* `tool`     — one tool decides it. Poisoning lives entirely in one description.
* `surface`  — only the relationship between tools reveals it. A typosquatted
  name is invisible until you can see the tool it imitates.
* `baseline` — needs a *previous* surface. A description is only "changed"
  relative to one someone approved earlier, so a single scan can never decide
  it.

Use `run()` rather than calling the scope-specific methods directly; it
dispatches so callers do not have to.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from sentinel import owasp
from sentinel.model import Tool

Mode = Literal["passive", "active"]
Scope = Literal["tool", "surface", "baseline"]

_REGISTRY: dict[str, Attack] = {}


@dataclass(frozen=True, slots=True)
class Signal:
    """One named piece of evidence contributing to a finding.

    `weight` 0 means informational: the signal is recorded and shown, but on its
    own it never pushes a finding over the threshold. Reserved for patterns that
    occur just as often in benign surfaces — flagging on those is how a scanner
    becomes unusable. Mitigating signals are also 0, never negative (D-005).
    """

    name: str
    weight: int
    evidence: str


@dataclass(frozen=True, slots=True)
class Finding:
    """The result of running one attack against one tool or one surface."""

    attack: str
    tool: str
    detected: bool
    score: int
    threshold: int
    signals: tuple[Signal, ...] = ()
    owasp: tuple[str, ...] = ()

    @property
    def fired(self) -> tuple[Signal, ...]:
        return tuple(s for s in self.signals if s.weight > 0)

    @property
    def informational(self) -> tuple[Signal, ...]:
        return tuple(s for s in self.signals if s.weight == 0)


@runtime_checkable
class ToolAttack(Protocol):
    """An attack one tool can be judged against on its own."""

    name: str
    attack_class: str
    mode: Mode
    scope: Literal["tool"]
    owasp: tuple[str, ...]

    def analyze(self, tool: Tool) -> Finding: ...


@runtime_checkable
class SurfaceAttack(Protocol):
    """An attack that only exists in the relationship between tools."""

    name: str
    attack_class: str
    mode: Mode
    scope: Literal["surface"]
    owasp: tuple[str, ...]

    def analyze_surface(self, tools: Sequence[Tool]) -> list[Finding]: ...


@runtime_checkable
class BaselineAttack(Protocol):
    """An attack that compares the current surface against an approved one."""

    name: str
    attack_class: str
    mode: Mode
    scope: Literal["baseline"]
    owasp: tuple[str, ...]

    def analyze_change(
        self, previous: Sequence[Tool], current: Sequence[Tool]
    ) -> list[Finding]: ...


Attack = ToolAttack | SurfaceAttack | BaselineAttack


def run(
    attack: Attack,
    tools: Sequence[Tool],
    *,
    baseline: Sequence[Tool] | None = None,
) -> list[Finding]:
    """Run one attack against a surface, dispatching on scope.

    A baseline-scoped attack with no baseline returns nothing rather than
    raising: on a first scan there is genuinely nothing to compare against, and
    that is not an error. Callers that need to distinguish "no baseline" from
    "no findings" should check for one themselves.
    """
    match attack.scope:
        case "surface":
            return list(attack.analyze_surface(tools))
        case "baseline":
            if baseline is None:
                return []
            return list(attack.analyze_change(baseline, tools))
        case _:
            return [attack.analyze(tool) for tool in tools]


def register(attack: Attack) -> Attack:
    """Register an attack. Called at import time by each attack module.

    OWASP identifiers are resolved here, so an invented or mistyped category
    fails at import rather than surfacing in a governance report.
    """
    if attack.name in _REGISTRY:
        raise ValueError(f"duplicate attack name {attack.name!r}")
    if attack.scope not in ("tool", "surface", "baseline"):
        raise ValueError(f"{attack.name}: scope must be 'tool', 'surface', or 'baseline'")
    owasp.validate(attack.owasp)
    _REGISTRY[attack.name] = attack
    return attack


def _discover() -> None:
    for mod in pkgutil.iter_modules(__path__):
        if not mod.name.startswith("_"):
            importlib.import_module(f"{__name__}.{mod.name}")


def registry() -> dict[str, Attack]:
    """All registered attacks, discovering modules on first call."""
    if not _REGISTRY:
        _discover()
    return dict(_REGISTRY)


def for_class(attack_class: str) -> list[Attack]:
    """Registered attacks matching one attack class."""
    return [a for a in registry().values() if a.attack_class == attack_class]


__all__ = [
    "Attack",
    "BaselineAttack",
    "Finding",
    "Signal",
    "SurfaceAttack",
    "ToolAttack",
    "for_class",
    "register",
    "registry",
    "run",
]
