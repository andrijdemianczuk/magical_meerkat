"""Attack modules and the registry they register themselves into (D-001).

Adding an attack means adding one file in this package that calls `@register`.
Import-time discovery below is the "slight import-time magic" D-001 accepted in
exchange for zero central wiring.

`Attack.mode` splits the corpus in two (D-002):

* `passive` — decided from the declared surface (`tools/list`). No side effects,
  safe against any target.
* `active`  — requires invoking tools. Real side effects on a real server, so it
  is opt-in at the CLI, never the default.
"""

from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

Mode = Literal["passive", "active"]

_REGISTRY: dict[str, Attack] = {}


@dataclass(frozen=True, slots=True)
class Signal:
    """One named piece of evidence contributing to a finding.

    `weight` 0 means informational: the signal is recorded and shown, but on its
    own it never pushes a finding over the threshold. Reserved for patterns that
    occur just as often in benign descriptions — flagging on those is how a
    scanner becomes unusable.
    """

    name: str
    weight: int
    evidence: str


@dataclass(frozen=True, slots=True)
class Finding:
    """The result of running one attack against one tool surface."""

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
class Attack(Protocol):
    """Contract every attack module satisfies."""

    name: str
    attack_class: str
    mode: Mode
    owasp: tuple[str, ...]

    def analyze(self, tool) -> Finding:
        """Return a finding for one tool surface."""
        ...


def register(attack: Attack) -> Attack:
    """Register an attack. Called at import time by each attack module."""
    if attack.name in _REGISTRY:
        raise ValueError(f"duplicate attack name {attack.name!r}")
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


__all__ = ["Attack", "Finding", "Signal", "for_class", "register", "registry"]
