"""Report tests.

Most of these assert on what the report must *never* say. A governance report
that overstates its own coverage is the failure mode that matters here — a
missed finding is a bug, but a false assurance is the thing that gets believed
and acted on.
"""

import sys

import pytest

from sentinel import owasp
from sentinel.baseline import capture
from sentinel.client import StdioClient
from sentinel.report import render
from sentinel.scan import ScanResult, minimal_arguments, scan
from sentinel.testbed.loader import load_corpus

CORPUS = {f.id: f for f in load_corpus()}
AT = "2026-07-27T00:00:00Z"


def server_command(fixture_id):
    return [sys.executable, "-m", "sentinel.testbed.server", str(CORPUS[fixture_id].source)]


def run_scan(fixture_id, **kwargs):
    with StdioClient(server_command(fixture_id), allow_invocation=kwargs.get("active", False)) as c:
        return scan(c, scanned_at=AT, endpoint=f"stdio://{fixture_id}", **kwargs)


# --- scanning ------------------------------------------------------------


def test_passive_scan_finds_poisoning():
    result = run_scan("tool-poisoning/exfil-ssh-key")
    assert [f.attack for f in result.detected] == ["tool_poisoning.description_instructions"]
    assert not result.active


def test_passive_scan_skips_active_attacks_and_says_so():
    result = run_scan("output-injection/instruction-in-response")
    assert not result.detected
    reasons = {s.attack_class: s.reason for s in result.skipped}
    assert "requires --active" in reasons["prompt_injection_via_output"]


def test_active_scan_finds_output_injection():
    result = run_scan("output-injection/instruction-in-response", active=True)
    assert any(f.attack.startswith("prompt_injection_via_output") for f in result.detected)


def test_rug_pull_runs_only_with_a_baseline():
    fixture = CORPUS["rug-pull/poisoned-after-approval"]

    without = run_scan(fixture.id)
    assert any(s.attack_class == "rug_pull" for s in without.skipped)
    assert not any(f.attack.startswith("rug_pull") for f in without.detected)
    # The current description is poisoned on its own terms, so the passive
    # poisoning check still fires — the baseline only adds *when* it appeared.
    assert any(f.attack.startswith("tool_poisoning") for f in without.detected)

    snapshot = capture(fixture.baseline, endpoint="stdio://approved", captured_at=AT)
    with_baseline = run_scan(fixture.id, baseline=snapshot)
    assert any(f.attack.startswith("rug_pull") for f in with_baseline.detected)


def test_uncovered_classes_are_reported():
    assert "tenant_leakage" in run_scan("tool-poisoning/exfil-ssh-key").uncovered_classes


@pytest.mark.parametrize(
    ("schema", "expected"),
    [
        ({"properties": {"city": {"type": "string"}}, "required": ["city"]},
         {"city": "sentinel-probe"}),
        ({"properties": {"n": {"type": "integer"}}, "required": ["n"]}, {"n": 1}),
        ({"properties": {"env": {"enum": ["staging", "prod"]}}, "required": ["env"]},
         {"env": "staging"}),
        ({"properties": {"opt": {"type": "string"}}}, {}),
        ({}, {}),
    ],
)
def test_minimal_arguments_satisfies_required_fields(schema, expected):
    assert minimal_arguments(schema) == expected


# --- report ---------------------------------------------------------------


def test_report_shows_findings_with_resolved_owasp_titles():
    text = render(run_scan("tool-poisoning/exfil-ssh-key"))
    assert "FINDINGS (1)" in text
    assert owasp.describe("MCP03:2025") in text
    assert "credential_path_reference" in text


def test_report_marks_informational_signals_as_not_decisive():
    text = render(run_scan("tool-poisoning/exfil-ssh-key"))
    assert "also observed (not decisive)" in text
    assert "imperative_directed_at_agent" in text


def test_clean_report_refuses_to_declare_the_server_safe():
    text = render(run_scan("tool-poisoning/legitimate-prerequisite"))
    assert "FINDINGS (0)" in text
    assert "not a clean bill of health" in text
    for forbidden in ("SECURE", "PASSED", "No vulnerabilities", "✓"):
        assert forbidden not in text


def test_report_always_lists_coverage_and_limitations():
    for fixture_id in ("tool-poisoning/exfil-ssh-key", "tool-poisoning/legitimate-prerequisite"):
        text = render(run_scan(fixture_id))
        assert "COVERAGE" in text
        assert "LIMITATIONS" in text
        assert "SKIPPED" in text
        assert "NO CHECK" in text


def test_report_names_the_framework_versions():
    text = render(run_scan("tool-poisoning/exfil-ssh-key"))
    assert owasp.MCP_TOP_10_VERSION in text
    assert owasp.ASI_TOP_10_VERSION in text


def test_report_states_when_no_baseline_was_supplied():
    assert "Baseline     none" in render(run_scan("tool-poisoning/exfil-ssh-key"))


def test_report_handles_an_empty_scan():
    """No server, no tools, no findings — still a coverage and limits section."""
    text = render(ScanResult(endpoint="stdio://nothing", scanned_at=AT, tools=(),
                             findings=(), active=False))
    assert "FINDINGS (0)" in text
    assert "LIMITATIONS" in text
