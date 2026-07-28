"""Rug-pull, and the baseline machinery it depends on.

The control is the load-bearing case: both fixtures changed their description
*and* their schema since the baseline. Everything that merely notices change
fires on both.
"""

import json

import pytest

from sentinel import baseline as bl
from sentinel.attacks import registry, run
from sentinel.attacks.rug_pull import RugPull
from sentinel.model import Tool
from sentinel.testbed.evaluate import evaluate
from sentinel.testbed.loader import FixtureError, load_corpus, load_fixture

ATTACK = RugPull()

PAYLOAD = "rug-pull/poisoned-after-approval"
CONTROL = "rug-pull/expanded-documentation"


def fixture(fixture_id: str):
    return next(f for f in load_corpus() if f.id == fixture_id)


def findings(fixture_id: str):
    f = fixture(fixture_id)
    return ATTACK.analyze_change(f.baseline, f.tools)


# --- the attack ----------------------------------------------------------


def test_attack_self_registers_as_baseline_scoped():
    assert ATTACK.name in registry()
    assert ATTACK.scope == "baseline"


def test_poisoning_introduced_after_approval_is_detected():
    assert any(f.detected for f in findings(PAYLOAD))


def test_ordinary_documentation_changes_are_not_detected():
    assert not any(f.detected for f in findings(CONTROL))
    assert all(f.score == 0 for f in findings(CONTROL))


def test_change_signals_fire_on_both_and_stay_informational():
    """Both fixtures changed description and schema. Change cannot decide."""
    for fixture_id in (PAYLOAD, CONTROL):
        signals = {s.name: s for f in findings(fixture_id) for s in f.signals}
        for name in ("description_changed_after_approval", "schema_changed_after_approval"):
            assert name in signals, f"{name} missing on {fixture_id}"
            assert signals[name].weight == 0


def test_detection_composes_the_passive_detectors():
    """The evidence names the detector that started firing, not a regex here."""
    evidence = [
        s.evidence
        for f in findings(PAYLOAD)
        for s in f.fired
        if s.name == "poisoning_introduced_after_approval"
    ]
    assert evidence
    assert "tool_poisoning.description_instructions" in evidence[0]


def test_an_unchanged_surface_produces_no_findings():
    tools = fixture(CONTROL).tools
    assert ATTACK.analyze_change(tools, tools) == []


def test_a_tool_poisoned_before_the_baseline_is_not_a_rug_pull():
    """Baselines record what was approved, not what was safe.

    If the poisoned definition was already there at approval time, nothing
    changed — and this detector must not claim otherwise.
    """
    poisoned = fixture(PAYLOAD).tools
    assert ATTACK.analyze_change(poisoned, poisoned) == []


def test_added_and_removed_tools_are_reported_but_never_decisive():
    before = (Tool(name="a", description="Alpha."),)
    after = (Tool(name="b", description="Beta."),)
    results = ATTACK.analyze_change(before, after)
    names = {s.name for f in results for s in f.signals}
    assert names == {"tool_added_after_approval", "tool_removed_after_approval"}
    assert not any(f.detected for f in results)


def test_run_returns_nothing_without_a_baseline():
    """A first scan has nothing to compare against; that is not an error."""
    assert run(ATTACK, fixture(PAYLOAD).tools) == []
    assert run(ATTACK, fixture(PAYLOAD).tools, baseline=fixture(PAYLOAD).baseline)


def test_corpus_evaluation_is_correct_for_rug_pull():
    for fixture_id in (PAYLOAD, CONTROL):
        result = evaluate(fixture(fixture_id))
        assert result is not None and result.correct


# --- fixtures ------------------------------------------------------------


def test_rug_pull_fixtures_declare_a_baseline():
    for f in load_corpus():
        if f.attack_class == "rug_pull":
            assert f.baseline, f"{f.id} has no baseline"


def test_rug_pull_fixture_without_a_baseline_is_rejected(tmp_path):
    import yaml

    path = tmp_path / "bad.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "id": "rug-pull/no-baseline",
                "attack_class": "rug_pull",
                "label": "vulnerable",
                "pair": "p",
                "rationale": "r",
                "mode": "passive",
                "tools": [{"name": "t", "description": "d"}],
                "expect": {"detect": True},
            }
        )
    )
    with pytest.raises(FixtureError, match="must declare a 'baseline'"):
        load_fixture(path)


# --- snapshots -----------------------------------------------------------


def test_snapshot_round_trips(tmp_path):
    tools = fixture(CONTROL).tools
    snap = bl.capture(tools, endpoint="stdio://testbed", captured_at="2026-07-27T00:00:00Z")
    path = tmp_path / "baseline.json"
    bl.save(snap, path)
    restored = bl.load(path)

    assert restored.endpoint == snap.endpoint
    assert restored.captured_at == snap.captured_at
    assert [t.name for t in restored.tools] == [t.name for t in tools]
    assert bl.diff(restored, tools).is_empty


def test_digest_changes_with_the_description():
    a = Tool(name="t", description="one")
    assert bl.digest(a) != bl.digest(Tool(name="t", description="two"))
    assert bl.digest(a) == bl.digest(Tool(name="t", description="one"))


def test_digest_changes_with_the_schema():
    a = Tool(name="t", description="d", input_schema={"type": "object"})
    b = Tool(name="t", description="d", input_schema={"type": "string"})
    assert bl.digest(a) != bl.digest(b)


def test_diff_classifies_added_removed_changed_and_unchanged():
    before = (
        Tool(name="stays", description="same"),
        Tool(name="edits", description="before"),
        Tool(name="goes", description="bye"),
    )
    after = (
        Tool(name="stays", description="same"),
        Tool(name="edits", description="after"),
        Tool(name="arrives", description="hi"),
    )
    d = bl.diff(before, after)
    assert [t.name for t in d.added] == ["arrives"]
    assert [t.name for t in d.removed] == ["goes"]
    assert [c.name for c in d.changed] == ["edits"]
    assert [t.name for t in d.unchanged] == ["stays"]
    assert not d.is_empty


def test_missing_baseline_file_is_a_baseline_error(tmp_path):
    with pytest.raises(bl.BaselineError, match="no baseline at"):
        bl.load(tmp_path / "nope.json")


def test_malformed_baseline_file_is_a_baseline_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    with pytest.raises(bl.BaselineError, match="not valid JSON"):
        bl.load(path)


def test_unsupported_snapshot_version_is_rejected(tmp_path):
    path = tmp_path / "old.json"
    path.write_text(json.dumps({"snapshotVersion": 99, "tools": []}))
    with pytest.raises(bl.BaselineError, match="not supported"):
        bl.load(path)
