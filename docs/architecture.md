# MCP Sentinel — Architecture

> Ad-hoc reference. Loaded via @docs/architecture.md only when architecture work is happening — not every session.

## Overview
[Diagram goes here — target → client → attack runner → report. Add a mermaid diagram once shape stabilizes.]

## Components
- **Client** — thin MCP JSON-RPC wrapper. Isolates protocol details from attacks.
- **Attack runner** — loads registered attack modules, executes against target, collects findings.
- **Attacks** — each is a self-contained module. Contract: `name`, `attack_class`, `mode`, `owasp`, `analyze(tool) -> Finding`. `mode` is `passive` (decided from `tools/list`, no side effects) or `active` (invokes tools, opt-in) — see D-002.
- **Testbed** — labelled fixture corpus (`testbed/fixtures/`) plus loader and evaluator. Ground truth for detector development; yields a confusion matrix, not a vibe.
- **Report** — aggregates findings into an OWASP-mapped scorecard.
- **Proxy** (Phase 3) — sits between agent and server, logs attributed traffic, enforces policy.

## Key decisions
See docs/decisions.md.

## Open questions
- Async vs sync client? (decide before Attack 3)
- Report format: JSON-first with rendered views on top.
