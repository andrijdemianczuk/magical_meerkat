"""CLI tests.

The authorization gate gets the most attention. It is the one piece of this
project that exists to stop the operator doing something, and a gate that can be
bypassed by accident is not a gate.
"""

import json
import sys

import pytest

from sentinel.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, is_loopback, main
from sentinel.testbed.loader import load_corpus

CORPUS = {f.id: f for f in load_corpus()}


def stdio_args(fixture_id):
    return ["--stdio", "--", sys.executable, "-m", "sentinel.testbed.server",
            str(CORPUS[fixture_id].source)]


# --- exit codes ----------------------------------------------------------


def test_findings_exit_one(capsys):
    assert main(["scan", *stdio_args("tool-poisoning/exfil-ssh-key")]) == EXIT_FINDINGS
    assert "FINDINGS (1)" in capsys.readouterr().out


def test_no_findings_exit_zero(capsys):
    assert main(["scan", *stdio_args("tool-poisoning/legitimate-prerequisite")]) == EXIT_OK
    assert "not a clean bill of health" in capsys.readouterr().out


def test_unreachable_target_exits_two(capsys):
    assert main(["scan", "http://127.0.0.1:9/mcp", "--timeout", "1"]) == EXIT_ERROR
    assert "sentinel:" in capsys.readouterr().err


def test_missing_baseline_file_exits_two(capsys):
    args = ["scan", "--baseline", "/nonexistent/approved.json",
            *stdio_args("tool-poisoning/exfil-ssh-key")]
    assert main(args) == EXIT_ERROR
    assert "no baseline at" in capsys.readouterr().err


def test_url_target_with_stdio_command_is_a_usage_error(capsys):
    assert main(["scan", "http://a/mcp", "http://b/mcp"]) == EXIT_ERROR
    assert "exactly one endpoint" in capsys.readouterr().err


# --- authorization -------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    ["http://localhost:8080/mcp", "http://127.0.0.1:8080/mcp", "http://[::1]:8080/mcp"],
)
def test_loopback_targets_are_recognised(target):
    assert is_loopback(target)


@pytest.mark.parametrize(
    "target",
    ["https://example.com/mcp", "http://10.0.0.5/mcp", "http://internal.corp/mcp"],
)
def test_remote_targets_are_not_loopback(target):
    assert not is_loopback(target)


def test_active_scan_of_a_remote_host_is_refused(capsys):
    assert main(["scan", "--active", "https://example.com/mcp"]) == EXIT_ERROR
    err = capsys.readouterr().err
    assert "refusing to actively scan" in err
    assert "--authorized" in err


def test_passive_scan_of_a_remote_host_is_allowed_through_the_gate(capsys):
    """Passive is read-only, so it is not what the gate exists for.

    It still fails here — nothing is listening — but with a transport error
    rather than a refusal.
    """
    assert main(["scan", "http://10.255.255.1/mcp", "--timeout", "1"]) == EXIT_ERROR
    assert "refusing" not in capsys.readouterr().err


def test_stdio_targets_bypass_the_gate(capsys):
    """A local subprocess is the operator's own machine by construction."""
    code = main(["scan", "--active", *stdio_args("output-injection/instruction-in-response")])
    assert code == EXIT_FINDINGS
    assert "refusing" not in capsys.readouterr().err


def test_authorized_flag_permits_a_remote_active_scan(capsys):
    """With the assertion made, it proceeds to a normal transport failure."""
    args = ["scan", "--active", "--authorized", "http://10.255.255.1/mcp", "--timeout", "1"]
    assert main(args) == EXIT_ERROR
    assert "refusing" not in capsys.readouterr().err


# --- baseline ------------------------------------------------------------


def test_baseline_writes_a_snapshot(tmp_path, capsys):
    destination = tmp_path / "approved.json"
    args = ["baseline", "-o", str(destination),
            *stdio_args("rug-pull/poisoned-after-approval")]
    assert main(args) == EXIT_OK

    payload = json.loads(destination.read_text())
    assert payload["snapshotVersion"] == 1
    assert [t["name"] for t in payload["tools"]] == ["summarize_text"]
    assert all("digest" in t for t in payload["tools"])
    assert "records what was served, not what is safe" in capsys.readouterr().out


def test_scanning_against_a_baseline_reports_rug_pull(tmp_path, capsys):
    approved = tmp_path / "approved.json"
    fixture = CORPUS["rug-pull/poisoned-after-approval"]

    # Approve the pre-change definition by serving the control fixture, whose
    # `tools` block is the benign evolution of the same tool.
    assert main(["baseline", "-o", str(approved),
                 *stdio_args("rug-pull/expanded-documentation")]) == EXIT_OK
    capsys.readouterr()

    assert main(["scan", "--baseline", str(approved), *stdio_args(fixture.id)]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "rug_pull.definition_changed_after_approval" in out
    assert "poisoning_introduced_after_approval" in out
    assert "Baseline     stdio://" in out


# --- corpus --------------------------------------------------------------


def test_corpus_command_evaluates_the_fixtures(capsys):
    assert main(["corpus"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Confusion matrix" in out
    assert "FP 0" in out


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert "sentinel" in capsys.readouterr().out
