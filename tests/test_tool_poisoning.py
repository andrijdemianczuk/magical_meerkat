"""The point of these tests is the control, not the payload.

Detecting `exfil-ssh-key` is easy and almost any heuristic manages it. Not
firing on `legitimate-prerequisite` is the whole engineering problem, so the
control gets the sharper assertions.
"""

import pytest

from sentinel.attacks import registry
from sentinel.attacks.tool_poisoning import ToolPoisoning
from sentinel.testbed.evaluate import evaluate
from sentinel.testbed.loader import load_corpus

ATTACK = ToolPoisoning()


def fixture(fixture_id: str):
    return next(f for f in load_corpus() if f.id == fixture_id)


def analyze(fixture_id: str, tool_name: str):
    tool = next(t for t in fixture(fixture_id).tools if t.name == tool_name)
    return ATTACK.analyze(tool)


def test_attack_self_registers():
    assert ATTACK.name in registry()


def test_poisoned_description_is_detected():
    finding = analyze("tool-poisoning/exfil-ssh-key", "weather_lookup")
    assert finding.detected
    assert finding.score >= finding.threshold


def test_benign_prerequisite_is_not_detected():
    finding = analyze("tool-poisoning/legitimate-prerequisite", "deploy_service")
    assert not finding.detected
    assert finding.score == 0


@pytest.mark.parametrize("signal", ["credential_path_reference", "content_exfiltration"])
def test_discriminating_signals_fire_only_on_the_payload(signal):
    poisoned = {s.name for s in analyze("tool-poisoning/exfil-ssh-key", "weather_lookup").signals}
    benign = {
        s.name
        for s in analyze("tool-poisoning/legitimate-prerequisite", "deploy_service").signals
    }
    assert signal in poisoned
    assert signal not in benign


@pytest.mark.parametrize("signal", ["imperative_directed_at_agent", "coercive_framing"])
def test_keyword_signals_fire_on_both_and_stay_informational(signal):
    """Guards the design claim: these patterns cannot be allowed to decide anything.

    Both fixtures contain them. If either is ever given a non-zero weight, the
    benign control starts failing — which is the point.
    """
    for fixture_id, tool_name in [
        ("tool-poisoning/exfil-ssh-key", "weather_lookup"),
        ("tool-poisoning/legitimate-prerequisite", "deploy_service"),
    ]:
        found = {s.name: s for s in analyze(fixture_id, tool_name).signals}
        assert signal in found, f"{signal} missing on {fixture_id}"
        assert found[signal].weight == 0


def test_reference_passing_is_not_treated_as_exfiltration():
    """"pass the path to X" is benign; "pass the contents of X" is not."""
    benign = analyze("tool-poisoning/legitimate-prerequisite", "deploy_service")
    assert "content_exfiltration" not in {s.name for s in benign.signals}


def test_corpus_evaluation_is_clean_for_covered_fixtures():
    for f in load_corpus():
        result = evaluate(f)
        if result is not None:
            assert result.correct, f"{f.id}: expected detect={f.expect_detect}"


def test_active_fixtures_have_no_passive_detector_yet():
    """Uncovered classes must stay visibly uncovered, not silently pass."""
    active = [f for f in load_corpus() if f.mode == "active"]
    assert active
    assert all(evaluate(f) is None for f in active)
