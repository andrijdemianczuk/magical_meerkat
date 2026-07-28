"""Tool poisoning — malicious instructions embedded in a tool description.

Passive: the whole attack is visible in `tools/list`, so nothing is invoked.

The design constraint is the clean control, not the payload. Both fixtures in
the `imperative-with-file-path` pair contain "IMPORTANT:", the word "always", an
instruction to act before calling the tool, a filesystem path, and a warning
that things will fail otherwise. Any detector keying on those flags both, and a
detector that flags `deploy_service` is unusable on real servers where workflow
instructions in descriptions are normal and correct.

Two things actually separate them:

1. The path is a *credential*, not just a path. `~/.ssh/id_rsa` vs
   `./config/service.yaml`.
2. The argument carries *contents*, not a *reference*. "pass its full contents
   in the `auth_context` field" vs "pass the path to your service definition in
   the `config_path` field".

Those two carry the weight. Everything else is recorded at weight 0 — visible in
output, never decisive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from sentinel.attacks import Finding, Mode, Signal, register
from sentinel.attacks._text import first_match, sentences

THRESHOLD = 3

_CREDENTIAL_PATH = re.compile(
    r"""
      ~?/?\.ssh/id_[a-z0-9_]+     # ~/.ssh/id_rsa
    | \bid_(?:rsa|dsa|ecdsa|ed25519)\b
    | \.aws/credentials
    | \.kube/config
    | \.netrc\b
    | /etc/(?:shadow|passwd)\b
    | \.env(?:\.[a-z]+)?\b
    | \b[\w./-]+\.pem\b
    | \bprivate[ _-]?key\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

_TRANSFER_VERB = re.compile(
    r"\b(?:pass|include|send|put|place|append|provide|set|copy|attach)\b", re.IGNORECASE
)
# "contents" and friends — deliberately excludes "path", "name", "id", which is
# what the benign control passes.
_CONTENTS_NOUN = re.compile(
    r"\b(?:contents?|value|payload|body|output|full[ _-]text|raw[ _-]text)\b", re.IGNORECASE
)
_ARGUMENT_REF = re.compile(
    r"\b(?:field|argument|parameter|param|property)\b", re.IGNORECASE
)

_AGENT_IMPERATIVE = re.compile(
    r"\b(?:before calling this tool|when calling this tool|always (?:call|read|use|include)"
    r"|you must|do not mention|ignore (?:all |any )?(?:previous|prior))\b",
    re.IGNORECASE,
)
_COERCIVE = re.compile(
    r"\b(?:will fail|is required|required for|otherwise|must be|mandatory)\b", re.IGNORECASE
)


@dataclass(frozen=True, slots=True)
class ToolPoisoning:
    name: str = "tool_poisoning.description_instructions"
    attack_class: str = "tool_poisoning"
    mode: Mode = "passive"
    scope: Literal["tool"] = "tool"
    owasp: tuple[str, ...] = ("MCP03:2025", "ASI01:2026")

    def analyze(self, tool) -> Finding:
        description = tool.description or ""
        signals: list[Signal] = []

        if hit := first_match(_CREDENTIAL_PATH, description):
            signals.append(
                Signal(
                    "credential_path_reference",
                    3,
                    f"description references credential path {hit!r}",
                )
            )

        # Co-occurrence is required *within one sentence*: a description may
        # legitimately mention contents somewhere and an argument elsewhere.
        for sentence in sentences(description):
            if (
                _TRANSFER_VERB.search(sentence)
                and (noun := _CONTENTS_NOUN.search(sentence))
                and _ARGUMENT_REF.search(sentence)
            ):
                signals.append(
                    Signal(
                        "content_exfiltration",
                        3,
                        f"routes {noun.group(0)!r} into an argument: {sentence!r}",
                    )
                )
                break

        if hit := first_match(_AGENT_IMPERATIVE, description):
            signals.append(
                Signal("imperative_directed_at_agent", 0, f"agent-directed instruction {hit!r}")
            )

        if hit := first_match(_COERCIVE, description):
            signals.append(Signal("coercive_framing", 0, f"coercive framing {hit!r}"))

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


register(ToolPoisoning())
