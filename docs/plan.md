# MCP Sentinel — Implementation Plan

Claude Code checks these off as work completes. Keep this current between sessions — it's the continuity thread across evenings.

## Phase 1 — CLI scanner (weeks 1-6, ~30-40 hrs)
- [ ] Scaffold package (`uv`, ruff, pytest, entry point)
- [ ] MCP JSON-RPC client: connect, list tools, call tool
- [ ] Attack module interface (register, run, detect)
- [ ] Attack 1: tool poisoning (malicious instructions in tool description)
- [ ] Attack 2: tool shadowing
- [ ] Attack 3: prompt injection via tool output
- [ ] Attack 4: rug-pull (description changes after approval)
- [ ] Plaintext report output
- [ ] README v1 (Problem → Architecture → Run → Demo)
- [ ] **Ship: video 1 — "I attacked an MCP server and it worked"**

## Phase 2 — Governance scorecard + web view (weeks 7-12, ~30-40 hrs)
- [ ] Map each attack to OWASP MCP Top 10 / Agentic Security Top 10
- [ ] Scorecard generator (severity, pass/fail, remediation)
- [ ] Minimal web dashboard
- [ ] docs/decisions.md started (why these attacks, why this scoring)
- [ ] **Ship: video 2 — the governance scorecard**

## Phase 3 — Logging proxy + tenant isolation (weeks 13-16, ~20 hrs)
- [ ] Pass-through proxy logging request/response per user+session
- [ ] One polished tenant-isolation / cross-tenant leakage check
- [ ] Policy enforcement (block flagged tool)
- [ ] **Ship: video 3 — audit trail + live block**

## Backlog / stretch
- [ ] Per-incident explainer episodes (Asana, Smithery, GitHub MCP)
- [ ] Contribute an attack signature upstream
