# MCP Sentinel — Project Memory (./CLAUDE.md)

@~/portfolio/shared-context.md

## What this repo is
**Codename `magical_meerkat`** — the GitHub repo, local directory, and venv prompt all use it. "MCP Sentinel" is the product name (and how `~/portfolio/shared-context.md` refers to this project); they are the same thing.

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

## Environment
Python 3.14.6 in `.venv`, created and managed by **uv** (not pyenv or Homebrew).
- Install with `uv pip install`, never bare `pip install`.
- `.venv/bin/pip` is a hand-written shim that re-routes to `uv pip`. Without it, `pip` falls through to `~/.pyenv/shims/pip` and installs into pyenv's 3.12.3 instead. Re-running `uv venv` recreates the venv and **destroys the shim** — recreate it before using `pip` again.

## Commands
- Install: `uv pip install -e .`
- Run scan: `sentinel scan <endpoint>`
- Tests: `pytest`

## Current plan
See @docs/plan.md for the phased checklist. Update it every session.
