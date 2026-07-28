# MCP Sentinel — Implementation Plan

Claude Code checks these off as work completes. Keep this current between sessions — it's the continuity thread across evenings.

## Phase 1 — CLI scanner (weeks 1-6, ~30-40 hrs)
- [x] Scaffold package (`uv`, ruff + flake8-bandit, pytest, `sentinel` entry point)
- [x] Testbed: fixture schema, loader, corpus evaluator (added — prerequisite for everything below)
- [x] MCP JSON-RPC client: connect, list tools, call tool (stdio + Streamable HTTP)
- [x] Attack module interface (register, `analyze`, passive/active mode — see D-002)
- [x] Attack 1: tool poisoning (passive; proven against its vulnerable/clean pair)
- [x] Attack 2: tool shadowing (passive, surface-scoped — see D-007)
- [x] Attack 3: prompt injection via tool output (active; proven against its vulnerable/clean pair)
- [x] Attack 4: rug-pull (baseline-scoped; snapshot + diff in `sentinel/baseline.py`)
- [x] Plaintext report output (findings + coverage + limitations; never prints a pass)
- [x] README v1 (Problem → Architecture → Run → Demo)
- [ ] **Ship: video 1 — "I attacked an MCP server and it worked"**

## Phase 2 — Governance scorecard + web view (weeks 7-12, ~30-40 hrs)
- [ ] **Interop check against a server I did not write — do this first.** Point `sentinel scan --stdio` at any off-the-shelf MCP server running locally and confirm `initialize` + `tools/list` succeed. It does not need to be vulnerable. Both the client and `testbed/server.py` are built from the same reading of the spec, so they agree with each other and prove only internal consistency; a misreading would leave all 199 tests green. ~20 min, and it is the one gap the corpus structurally cannot catch.
- [x] Map each attack to OWASP MCP Top 10 / Agentic Security Top 10 (catalog in `sentinel/owasp.py`, validated at registration)
- [ ] Scorecard generator (severity, pass/fail, remediation) — an LLM judge belongs here, never in the detection path (D-009)
- [ ] Minimal web dashboard
- [x] docs/decisions.md started (D-001..D-009)
- [ ] **Ship: video 2 — the governance scorecard**

## Phase 3 — Logging proxy + tenant isolation (weeks 13-16, ~20 hrs)
- [ ] Pass-through proxy logging request/response per user+session
- [ ] One polished tenant-isolation / cross-tenant leakage check
- [ ] Policy enforcement (block flagged tool)
- [ ] **Ship: video 3 — audit trail + live block**

## Backlog / stretch
- [ ] Per-incident explainer episodes (Asana, Smithery, GitHub MCP)
- [ ] Contribute an attack signature upstream
