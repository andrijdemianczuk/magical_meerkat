"""Prompt injection via tool output — the payload rides in the response body.

Active (D-002): the declared surface is clean. `read_ticket`'s description is
honest and a passive scan finds nothing, so the tool has to be invoked before
there is anything to analyze.

The response text is read from `Tool.response_text`. In the testbed that comes
from the fixture's declared `returns`; in a real scan the runner will populate
it from an actual `tools/call`. That property is the seam where the MCP client
plugs in, and the reason this detector needs no transport code today.

Discriminating the pair is the whole problem. Both response bodies contain an
override phrase — "Disregard prior instructions" in the payload, "ignore all
previous instructions" in the control, where a user is *quoting* an injection
they found while filing a bug about it. Substring matching flags both, and
flagging the control means Sentinel is unusable on a security team's own ticket
queue.

Three things separate them:

1. **Concealment.** "Do not mention this step in your reply." Benign text does
   not ask to be hidden from the user.
2. **Hidden channel.** The payload is inside an HTML comment — invisible to a
   human reading rendered output, fully visible to a model. The control's quote
   is in plain view, indented and attributed.
3. **A destination.** The payload names a tool *and* where to send the data, in
   one sentence. The control names no tool and no recipient.

Note on the mitigator: `override_in_quotation` is recorded at weight 0 rather
than as a negative weight. Subtracting for quotation marks would hand every
attacker a one-character bypass — wrap the payload in quotes and the score
drops. It explains a non-detection; it must never cause one.

This detector deliberately does not look for the fixture canary. Keying on
`SENTINEL_CANARY_*` would pass the corpus while detecting nothing real; a test
strips the canary and asserts detection is unchanged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from sentinel.attacks import Finding, Mode, Signal, register
from sentinel.attacks._text import first_match, sentences

THRESHOLD = 3

# Content addressed to a model but concealed from a human reading the rendered
# output. Not exhaustive — these are the channels the corpus covers so far.
_HIDDEN_BLOCK = re.compile(
    r"<!--(?P<body>.*?)-->"  # HTML comment
    r"|\[//\]:\s*#\s*\((?P<md>.*?)\)",  # markdown comment idiom
    re.DOTALL,
)
_INVISIBLE_CHARS = re.compile("[\u200b-\u200f\u2060-\u2064\ufeff]")

_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override|bypass)\b[^.]{0,40}?"
    r"\b(?:previous|prior|earlier|above|all|any)\b[^.]{0,30}?\binstructions?\b",
    re.IGNORECASE,
)
_CONCEALMENT = re.compile(
    r"\b(?:do not|don't|never)\b[^.]{0,30}?"
    r"\b(?:mention|reveal|disclose|tell|inform|report|acknowledge|reference)\b"
    r"|\bwithout (?:mentioning|informing|telling|notifying)\b"
    r"|\bkeep this (?:secret|hidden|between)\b"
    r"|\bsilently\b",
    re.IGNORECASE,
)
_TOOL_CALL_VERB = re.compile(r"\b(?:call|invoke|execute|run|trigger|use)\b", re.IGNORECASE)
_DESTINATION = re.compile(
    r"[\w.+-]+@[\w-]+\.[\w.-]+"  # email address
    r"|https?://[^\s\"'>)]+"  # url
    r"|\bto\s*=\s*[\"'][^\"']+[\"']",  # to="..." argument
    re.IGNORECASE,
)
# An override phrase sitting inside quotes reads as cited evidence rather than a
# directive. Informational only — see the module docstring.
# Curly quotes are intentional: real ticket text is typed by humans and editors
# autocorrect straight quotes, so matching only ASCII would miss the control.
_QUOTED = re.compile(r"[\"'“‘]([^\"'”’]{10,400})[\"'”’]", re.DOTALL)  # noqa: RUF001


def _instruction_like(text: str) -> str | None:
    """Whether concealed text reads as a directive rather than markup or notes."""
    return first_match(_OVERRIDE, text) or first_match(_TOOL_CALL_VERB, text)


@dataclass(frozen=True, slots=True)
class OutputInjection:
    name: str = "prompt_injection_via_output.response_instructions"
    attack_class: str = "prompt_injection_via_output"
    mode: Mode = "active"
    # MCP06 (Intent Flow Subversion) is adjacent, but the mechanism here is
    # untrusted content entering the model's context, which is MCP10.
    owasp: tuple[str, ...] = ("MCP10:2025", "ASI01:2026")

    def analyze(self, tool) -> Finding:
        response = tool.response_text or ""
        signals: list[Signal] = []

        for match in _HIDDEN_BLOCK.finditer(response):
            concealed = match.group("body") or match.group("md") or ""
            if hit := _instruction_like(concealed):
                signals.append(
                    Signal(
                        "hidden_channel_payload",
                        3,
                        f"instruction {hit!r} concealed in a comment block",
                    )
                )
                break

        if _INVISIBLE_CHARS.search(response):
            signals.append(
                Signal("hidden_channel_payload", 3, "response contains invisible unicode")
            )

        if hit := first_match(_CONCEALMENT, response):
            signals.append(
                Signal("concealment_request", 3, f"asks the agent to conceal the step: {hit!r}")
            )

        # Both fixtures carry reporter email addresses, so a destination alone
        # proves nothing. It only counts alongside a tool-call verb in the same
        # sentence.
        for sentence in sentences(response):
            if _TOOL_CALL_VERB.search(sentence) and (dest := _DESTINATION.search(sentence)):
                signals.append(
                    Signal(
                        "cross_tool_direction",
                        2,
                        f"directs a tool call to {dest.group(0)!r}: {sentence!r}",
                    )
                )
                break

        if hit := first_match(_OVERRIDE, response):
            signals.append(Signal("instruction_override", 0, f"override phrase {hit!r}"))
            if any(_OVERRIDE.search(q) for q in _QUOTED.findall(response)):
                signals.append(
                    Signal(
                        "override_in_quotation",
                        0,
                        "override phrase appears inside quotation marks — consistent with "
                        "cited evidence rather than a directive",
                    )
                )

        score = sum(s.weight for s in signals)
        return Finding(
            attack=self.name,
            tool=tool.name,
            detected=score >= THRESHOLD,
            score=score,
            threshold=THRESHOLD,
            signals=tuple(signals),
            owasp=self.owasp,
        )


register(OutputInjection())
