# MCP Sentinel — Project Memory (./CLAUDE.md)

@~/portfolio/shared-context.md

## What this repo is
**Codename `magical_meerkat`** — the GitHub repo, local directory, and venv prompt all use it. "MCP Sentinel" is the product name (and how `~/portfolio/shared-context.md` refers to this project); they are the same thing.

Open-source MCP governance & red-team harness. Given an MCP server endpoint, run known attack classes and emit an OWASP-mapped governance report. Proxy mode logs every request/response attributed to user+session.

## Architecture (see @docs/architecture.md)
- `sentinel/client/` — MCP JSON-RPC over stdio + Streamable HTTP (protocol `2025-11-25`)
- `sentinel/attacks/` — one self-registering module per attack class
- `sentinel/model.py` — `Tool`, the seam shared by client, testbed, and detectors
- `sentinel/owasp.py` — both OWASP catalogs as data; identifiers validated at registration
- `sentinel/baseline.py` — approved-surface snapshots and diffs
- `sentinel/scan.py` — orchestration; records what did *not* run and why
- `sentinel/report/` — plaintext rendering (scorecard is Phase 2)
- `sentinel/testbed/` — fixture loader, corpus evaluator, fixture-backed MCP server
- `sentinel/cli.py` — `sentinel scan | baseline | corpus`
- `sentinel/proxy/` — logging proxy (Phase 3, not started)

## Conventions
Rationale for all of these is in @docs/decisions.md (D-001…D-009). Read it before
changing detector behaviour — most of these rules exist because the obvious
alternative was tried and rejected.

- Every attack module registers itself; adding an attack = adding one file, no wiring.
- Attacks declare **`mode`** (`passive` | `active`) and **`scope`** (`tool` | `surface` | `baseline`). Call `attacks.run()`, which dispatches; don't call the scope-specific method directly.
- **Never add a vulnerable fixture without a clean control** built to defeat the naive detector for that class. The loader rejects an unbalanced pair. The controls are the actual work.
- **Signals that fire on both sides of a pair get weight 0.** Mitigating signals are also 0, never negative — a negative weight is a published bypass.
- **Detectors must not key on testbed artifacts** (the canary). A test enforces this per active attack.
- Never run attacks against third-party servers by default — target must be explicitly local or an allowlisted disclosed-and-patched target. `--active` against a non-loopback host requires `--authorized`.
- Reports map to OWASP MCP Top 10 + Agentic Security Top 10, resolved against `sentinel/owasp.py`. Never hand-write an identifier — `MCP09:2025` is *unsanctioned servers*, not tool shadowing.
- **The report never prints a pass.** Coverage (`SKIPPED` / `NO CHECK`) is rendered with the same weight as findings.

## Environment
Python 3.14.6 in `.venv`, created and managed by **uv** (not pyenv or Homebrew).
- Install with `uv pip install`, never bare `pip install`.
- `.venv/bin/pip` is a hand-written shim that re-routes to `uv pip`. Without it, `pip` falls through to `~/.pyenv/shims/pip` and installs into pyenv's 3.12.3 instead. Re-running `uv venv` recreates the venv and **destroys the shim** — recreate it before using `pip` again.

## Commands
- Install: `uv pip install -e ".[dev]"`
- Scan (HTTP): `sentinel scan <url>` · (local): `sentinel scan --stdio -- <cmd>`
- Ground truth: `sentinel corpus` — confusion matrix over the labelled fixtures
- Tests: `pytest` · Lint: `ruff check .` (flake8-bandit is on; argue for suppressions in a comment)

## Current plan
See @docs/plan.md for the phased checklist. Update it every session.

**State as of 2026-07-27.** Phase 1 complete except video 1. Four attack classes
with detectors, 199 tests, corpus TP 5 / FP 0 / TN 5 / FN 0 over 10 fixtures.
Work is on `sprint-1`; a Phase 1 PR to `main` is prepared but may not be merged.

Next candidates, roughly in order:
1. **Interop check first** — scan a real off-the-shelf MCP server. The client and `testbed/server.py` share one reading of the spec, so the suite proves internal consistency, not interoperability.
2. Phase 2 scorecard — severity, remediation. An LLM judge belongs *here*, never in the detection path (D-009).
3. Known gaps, each needing a control fixture before it earns a weight: transposition typosquatting (`send_meail`); a poisoning payload naming no resource; laundering a bare identifier by declaring an input with that name.
4. `tenant_leakage` has no detector and renders as `NO CHECK`. Phase 3, with the proxy.
