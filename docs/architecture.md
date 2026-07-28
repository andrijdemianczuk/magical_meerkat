# MCP Sentinel — Architecture

> Ad-hoc reference. Loaded via @docs/architecture.md only when architecture work is happening — not every session.

## Overview
[Diagram goes here — target → client → attack runner → report. Add a mermaid diagram once shape stabilizes.]

## Components
- **Client** — thin MCP JSON-RPC wrapper. Isolates protocol details from attacks.
- **Attack runner** — loads registered attack modules, executes against target, collects findings.
- **Attacks** — each is a self-contained module. Contract: `name`, `owasp_mapping`, `run(client) -> Finding`, `detect(response) -> bool`.
- **Report** — aggregates findings into an OWASP-mapped scorecard.
- **Proxy** (Phase 3) — sits between agent and server, logs attributed traffic, enforces policy.

## Key decisions
See docs/decisions.md.

## Open questions
- Async vs sync client? (decide before Attack 3)
- Report format: JSON-first with rendered views on top.
