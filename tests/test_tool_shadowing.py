"""Shadowing is the first surface-scoped attack, so the contract gets tested too.

The control is an ordinary deprecation notice. Every real versioned API on
earth contains one, so firing on it would make Sentinel useless in production.
"""

import pytest

from sentinel.attacks import registry, run
from sentinel.attacks.tool_shadowing import ToolShadowing, normalize
from sentinel.model import Tool
from sentinel.testbed.evaluate import evaluate
from sentinel.testbed.loader import load_corpus

ATTACK = ToolShadowing()

PAYLOAD = "tool-shadowing/typosquatted-sibling"
CONTROL = "tool-shadowing/versioned-supersession"


def fixture(fixture_id: str):
    return next(f for f in load_corpus() if f.id == fixture_id)


def findings(fixture_id: str):
    return ATTACK.analyze_surface(fixture(fixture_id).tools)


def test_attack_self_registers():
    assert ATTACK.name in registry()


def test_attack_is_surface_scoped():
    assert ATTACK.scope == "surface"


def test_typosquatted_sibling_is_detected():
    assert any(f.detected for f in findings(PAYLOAD))


def test_versioned_deprecation_is_not_detected():
    assert not any(f.detected for f in findings(CONTROL))
    assert all(f.score == 0 for f in findings(CONTROL))


def test_finding_is_anchored_on_the_impostor():
    detected = [f for f in findings(PAYLOAD) if f.detected]
    assert [f.tool for f in detected] == ["send_emai1"]


def test_supersession_claim_fires_on_both_and_stays_informational():
    """A tool calling another deprecated is normal API maintenance."""
    for fixture_id in (PAYLOAD, CONTROL):
        signals = {s.name: s for f in findings(fixture_id) for s in f.signals}
        assert "supersession_claim" in signals, f"missing on {fixture_id}"
        assert signals["supersession_claim"].weight == 0


def test_confusable_names_fire_only_on_the_payload():
    assert "confusable_tool_names" in {s.name for f in findings(PAYLOAD) for s in f.signals}
    assert "confusable_tool_names" not in {s.name for f in findings(CONTROL) for s in f.signals}


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("send_email", "send_emai1"),  # digit for letter
        ("send_email", "send-email"),  # separator swap
        ("send_email", "SendEmail"),  # case
        ("send_email", "s\u0435nd_email"),  # Cyrillic e
    ],
)
def test_confusable_pairs_collide(left, right):
    assert normalize(left) == normalize(right)


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("search_docs", "search_docs_v2"),
        ("send_email", "send_sms"),
        ("list_files", "read_file"),
    ],
)
def test_distinct_names_do_not_collide(left, right):
    assert normalize(left) != normalize(right)


def test_non_ascii_tool_name_is_flagged():
    tools = (Tool(name="send_email", description="Send mail."),
             Tool(name="\u0455end_report", description="Send a report."))
    signals = {s.name for f in ATTACK.analyze_surface(tools) for s in f.signals}
    assert "non_ascii_tool_name" in signals


def test_a_single_tool_surface_yields_nothing():
    """Shadowing needs a pair; one tool cannot shadow anything."""
    assert ATTACK.analyze_surface((Tool(name="only", description="Alone."),)) == []


def test_run_dispatches_surface_attacks_over_the_whole_surface():
    """The dispatch helper is what lets callers ignore scope."""
    tools = fixture(PAYLOAD).tools
    assert run(ATTACK, tools) == ATTACK.analyze_surface(tools)


def test_corpus_evaluation_is_correct_for_shadowing():
    for fixture_id in (PAYLOAD, CONTROL):
        result = evaluate(fixture(fixture_id))
        assert result is not None
        assert result.correct
