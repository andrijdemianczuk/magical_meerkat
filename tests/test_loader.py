from pathlib import Path

import pytest
import yaml

from sentinel.testbed.loader import FixtureError, load_corpus, load_fixture

VALID = {
    "id": "tool-poisoning/example",
    "attack_class": "tool_poisoning",
    "label": "vulnerable",
    "pair": "example-pair",
    "rationale": "why",
    "mode": "passive",
    "tools": [{"name": "t", "description": "d", "inputSchema": {}}],
    "expect": {"detect": True},
}


def write(tmp_path: Path, data: dict, name: str = "f.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data))
    return path


def test_corpus_loads_and_pairs_are_balanced():
    corpus = load_corpus()
    assert len(corpus) >= 4
    pairs: dict[str, set[str]] = {}
    for f in corpus:
        pairs.setdefault(f.pair, set()).add(f.label)
    assert all(labels == {"vulnerable", "clean"} for labels in pairs.values())


def test_vulnerable_and_clean_fixtures_both_present():
    corpus = load_corpus()
    assert {f.label for f in corpus} == {"vulnerable", "clean"}


def test_active_vulnerable_fixtures_carry_a_canary():
    for f in load_corpus():
        if f.mode == "active" and f.is_vulnerable:
            assert f.canary, f"{f.id} is an active vulnerable fixture with no canary"


def test_response_text_extracts_text_blocks():
    fixture = next(f for f in load_corpus() if f.id == "output-injection/instruction-in-response")
    tool = next(t for t in fixture.tools if t.name == "read_ticket")
    assert fixture.canary in tool.response_text


def test_tool_with_no_returns_has_empty_response_text(tmp_path):
    fixture = load_fixture(write(tmp_path, VALID))
    assert fixture.tools[0].response_text == ""


def test_label_and_expect_detect_must_agree(tmp_path):
    bad = VALID | {"expect": {"detect": False}}
    with pytest.raises(FixtureError, match="contradicts label"):
        load_fixture(write(tmp_path, bad))


def test_active_vulnerable_without_canary_is_rejected(tmp_path):
    bad = VALID | {"mode": "active"}
    with pytest.raises(FixtureError, match="must declare a canary"):
        load_fixture(write(tmp_path, bad))


def test_unknown_attack_class_is_rejected(tmp_path):
    bad = VALID | {"attack_class": "telepathy"}
    with pytest.raises(FixtureError, match="unknown attack_class"):
        load_fixture(write(tmp_path, bad))


def test_missing_required_field_is_rejected(tmp_path):
    bad = {k: v for k, v in VALID.items() if k != "rationale"}
    with pytest.raises(FixtureError, match="missing required field 'rationale'"):
        load_fixture(write(tmp_path, bad))


def test_fixture_with_no_tools_is_rejected(tmp_path):
    bad = VALID | {"tools": []}
    with pytest.raises(FixtureError, match="declares no tools"):
        load_fixture(write(tmp_path, bad))


def test_unbalanced_pair_is_rejected(tmp_path):
    write(tmp_path, VALID)
    with pytest.raises(FixtureError, match="unbalanced"):
        load_corpus(tmp_path)


def test_duplicate_ids_are_rejected(tmp_path):
    write(tmp_path, VALID, "a.yaml")
    write(tmp_path, VALID | {"label": "clean", "expect": {"detect": False}}, "b.yaml")
    with pytest.raises(FixtureError, match="duplicate fixture id"):
        load_corpus(tmp_path)


def test_empty_corpus_is_rejected(tmp_path):
    with pytest.raises(FixtureError, match="no fixtures found"):
        load_corpus(tmp_path)
