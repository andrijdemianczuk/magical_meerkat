"""Load and validate testbed fixtures.

A fixture is inert YAML describing an MCP server surface plus a ground-truth
label. Nothing here executes fixture content — it is parsed as data and handed
to detectors in the same shape `tools/list` returns.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from sentinel.model import Tool

DEFAULT_CORPUS = Path(__file__).resolve().parents[2] / "testbed" / "fixtures"

Label = Literal["vulnerable", "clean"]
Mode = Literal["passive", "active"]

ATTACK_CLASSES = {
    "tool_poisoning",
    "tool_shadowing",
    "prompt_injection_via_output",
    "rug_pull",
    "tenant_leakage",
}


class FixtureError(Exception):
    """A fixture is malformed, mislabelled, or internally inconsistent."""


@dataclass(frozen=True, slots=True)
class Fixture:
    """One MCP server surface with a ground-truth label."""

    id: str
    attack_class: str
    label: Label
    pair: str
    rationale: str
    mode: Mode
    tools: tuple[Tool, ...]
    expect_detect: bool
    expect_signals: tuple[str, ...] = ()
    canary: str | None = None
    source: Path | None = None

    @property
    def is_vulnerable(self) -> bool:
        return self.label == "vulnerable"


def _require(data: dict[str, Any], key: str, source: Path) -> Any:
    if key not in data:
        raise FixtureError(f"{source}: missing required field '{key}'")
    return data[key]


def load_fixture(path: Path) -> Fixture:
    """Parse and validate one fixture file."""
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise FixtureError(f"{path}: expected a YAML mapping")

    label = _require(raw, "label", path)
    if label not in ("vulnerable", "clean"):
        raise FixtureError(f"{path}: label must be 'vulnerable' or 'clean', got {label!r}")

    mode = _require(raw, "mode", path)
    if mode not in ("passive", "active"):
        raise FixtureError(f"{path}: mode must be 'passive' or 'active', got {mode!r}")

    attack_class = _require(raw, "attack_class", path)
    if attack_class not in ATTACK_CLASSES:
        raise FixtureError(f"{path}: unknown attack_class {attack_class!r}")

    expect = _require(raw, "expect", path)
    detect = expect.get("detect")
    if detect is None:
        raise FixtureError(f"{path}: missing 'expect.detect'")

    # The two are stated separately for readability at the assertion site, so
    # a fixture that drifts out of agreement with itself is a hard error.
    if detect is not (label == "vulnerable"):
        raise FixtureError(f"{path}: expect.detect={detect} contradicts label={label!r}")

    canary = raw.get("canary")
    if mode == "active" and label == "vulnerable" and not canary:
        raise FixtureError(f"{path}: active vulnerable fixtures must declare a canary")

    tools = tuple(
        Tool(
            name=t["name"],
            description=t.get("description", ""),
            input_schema=t.get("inputSchema", {}),
            returns=t.get("returns"),
        )
        for t in _require(raw, "tools", path)
    )
    if not tools:
        raise FixtureError(f"{path}: fixture declares no tools")

    return Fixture(
        id=_require(raw, "id", path),
        attack_class=attack_class,
        label=label,
        pair=_require(raw, "pair", path),
        rationale=_require(raw, "rationale", path),
        mode=mode,
        tools=tools,
        expect_detect=detect,
        expect_signals=tuple(expect.get("signals", ())),
        canary=canary,
        source=path,
    )


def load_corpus(root: Path | None = None, *, require_pairs: bool = True) -> list[Fixture]:
    """Load every fixture under `root`, sorted by id.

    With `require_pairs`, an unbalanced pair is an error: a vulnerable fixture
    with no clean counterpart measures recall while silently ignoring precision,
    which is the failure this corpus exists to prevent.
    """
    root = root or DEFAULT_CORPUS
    fixtures = sorted(
        (load_fixture(p) for p in root.rglob("*.yaml")),
        key=lambda f: f.id,
    )
    if not fixtures:
        raise FixtureError(f"{root}: no fixtures found")

    seen: dict[str, Path | None] = {}
    for f in fixtures:
        if f.id in seen:
            raise FixtureError(f"duplicate fixture id {f.id!r}: {seen[f.id]} and {f.source}")
        seen[f.id] = f.source

    if require_pairs:
        pairs: dict[str, set[str]] = {}
        for f in fixtures:
            pairs.setdefault(f.pair, set()).add(f.label)
        for pair, labels in sorted(pairs.items()):
            if labels != {"vulnerable", "clean"}:
                raise FixtureError(
                    f"pair {pair!r} is unbalanced (has {sorted(labels)}); "
                    "every vulnerable fixture needs a clean control"
                )

    return fixtures
