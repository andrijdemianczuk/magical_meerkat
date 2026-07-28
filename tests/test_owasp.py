"""The catalog exists to stop invented identifiers reaching a report.

An earlier revision of this project shipped `MCP-01` and `ASI-01`, which are not
identifiers in either framework. These tests are the guardrail against that
recurring.
"""

import pytest

from sentinel import owasp
from sentinel.attacks import register, registry


def test_catalogs_are_complete():
    assert len(owasp.MCP_TOP_10) == 10
    assert len(owasp.ASI_TOP_10) == 10
    assert set(owasp.CATALOG) == set(owasp.MCP_TOP_10) | set(owasp.ASI_TOP_10)


@pytest.mark.parametrize("identifier", ["MCP03:2025", "MCP10:2025", "ASI01:2026"])
def test_known_identifiers_resolve(identifier):
    assert owasp.title(identifier)


@pytest.mark.parametrize("identifier", ["MCP-01", "ASI-01", "MCP11:2025", "", "MCP03"])
def test_unknown_identifiers_are_rejected(identifier):
    with pytest.raises(owasp.UnknownCategory):
        owasp.title(identifier)


def test_describe_includes_the_title():
    assert owasp.describe("MCP03:2025") == "MCP03:2025 — Tool Poisoning"


def test_every_registered_attack_maps_to_real_categories():
    for attack in registry().values():
        assert attack.owasp, f"{attack.name} declares no OWASP mapping"
        for identifier in attack.owasp:
            assert owasp.title(identifier)


def test_registering_an_attack_with_a_bad_mapping_fails():
    """Registration is where a fabricated identifier gets caught."""

    class Bogus:
        name = "bogus.attack"
        attack_class = "tool_poisoning"
        mode = "passive"
        scope = "tool"
        owasp = ("MCP99:2025",)

        def analyze(self, tool):  # pragma: no cover - never reached
            raise AssertionError

    with pytest.raises(owasp.UnknownCategory):
        register(Bogus())


def test_shadow_mcp_servers_is_not_tool_shadowing():
    """MCP09 is unsanctioned servers (shadow IT), not one tool impersonating
    another. Mapping a shadowing detector there would be wrong."""
    assert owasp.title("MCP09:2025") == "Shadow MCP Servers"
    for attack in registry().values():
        if attack.attack_class == "tool_shadowing":
            assert "MCP09:2025" not in attack.owasp
