# MCP Sentinel — Project Memory (./CLAUDE.md)

@~/portfolio/shared-context.md

## What this repo is
Open-source MCP governance & red-team harness. Given an MCP server endpoint, run known attack classes and emit an OWASP-mapped governance report. Proxy mode logs every request/response attributed to user+session.

## Architecture (see @docs/architecture.md)
- `sentinel/client/` — MCP JSON-RPC client
- `sentinel/attacks/` — one module per attack class, each self-describing (name, OWASP mapping, payload, detection)
- `sentinel/report/` — scorecard generation
- `sentinel/proxy/` — logging proxy (Phase 3)

## Conventions
- Every attack module registers itself; adding an attack = adding one file, no wiring.
- Never run attacks against third-party servers by default — target must be explicitly local or an allowlisted disclosed-and-patched target.
- Reports map to OWASP MCP Top 10 + Agentic Security Top 10.

## Commands
- Install: `uv pip install -e .`
- Run scan: `sentinel scan <endpoint>`
- Tests: `pytest`

## Current plan
See @docs/plan.md for the phased checklist. Update it every session.
