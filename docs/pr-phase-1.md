## Phase 1 — MCP Sentinel scanner

Takes the repo from PyCharm scaffolding to a working MCP governance scanner. Four attack classes ship with detectors, each validated against a labelled corpus with benign controls. Everything in `docs/plan.md` Phase 1 is complete except the demo video.

```bash
uv pip install -e ".[dev]"
sentinel scan --stdio -- python -m sentinel.testbed.server \
    testbed/fixtures/tool-poisoning/exfil-ssh-key.yaml
sentinel corpus
```

**199 tests, ruff clean** (with flake8-bandit enabled). Corpus: **TP 5 / FP 0 / TN 5 / FN 0** across 10 fixtures.

### What's in it

| Area | |
| --- | --- |
| `sentinel/client/` | MCP JSON-RPC over stdio and Streamable HTTP, stdlib only. Protocol `2025-11-25`. |
| `sentinel/attacks/` | Tool poisoning, output injection, tool shadowing, rug-pull. Self-registering (D-001). |
| `sentinel/baseline.py` | Approved-surface snapshots and diffs. |
| `sentinel/scan.py`, `sentinel/report/` | Orchestration and plaintext report. |
| `sentinel/testbed/` | Fixture corpus, loader, evaluator, and a fixture-backed MCP server. |
| `sentinel/cli.py` | `sentinel scan` / `baseline` / `corpus`. |

### Design decisions worth reviewing

Full rationale in `docs/decisions.md` (D-001…D-009). The load-bearing ones:

- **Passive by default (D-002).** `call_tool()` raises unless the client is opened with `allow_invocation`. A target's tools may be `send_email` or `delete_repo`, so the safe default is structural, not conventional.
- **Paired fixtures (D-003).** No vulnerable fixture without a clean control built to defeat the naive detector for its class. The loader rejects an unbalanced pair. **In every pair the obvious keyword fires on both sides**, so those signals carry weight 0 — recorded as evidence, structurally unable to trigger a finding.
- **Mitigators are never negative (D-005).** A signal that subtracts is a published bypass; a test wraps a payload in quotes and asserts it's still detected.
- **No keying on testbed artifacts (D-006).** A test strips the canary and asserts detection is unchanged — otherwise the corpus goes green while detecting nothing real.
- **Rug-pull composes rather than re-implements (D-008).** It re-runs the passive detectors against approved vs. current and fires only on what newly detects, so every future passive attack becomes a rug-pull trigger for free.
- **"Who chose the resource", not "does the purpose justify the capability" (D-009).** Structural instead of semantic, and no LLM in the detection path.

### Two things I'd flag to a reviewer

**The OWASP identifiers were wrong and are now validated.** An earlier commit shipped `MCP-01` / `ASI-01`, which exist in neither framework. `sentinel/owasp.py` holds both published lists as data and `register()` resolves every identifier at import, so a fabricated category fails there instead of in a report. Note `MCP09:2025 "Shadow MCP Servers"` means *unsanctioned servers*, not tool shadowing — a test guards that mis-mapping.

**Writing a control found a live false positive.** `translate_document` — an ordinary tool that reads a caller-supplied path and forwards its contents — was flagged at exactly threshold by the shipped detector. No payload fixture would have surfaced it. That's what motivated D-009.

### The report never prints a pass

Coverage gets equal billing with findings. `SKIPPED` attacks, classes with `NO CHECK`, and tools that couldn't be probed always render, and a clean scan says *"Nothing fired. This is not a clean bill of health — see COVERAGE."* Tests assert the report cannot emit `SECURE` or `PASSED`.

### Known gaps, deliberately unweighted

Each needs its own control fixture before it earns a weight:

- Transposition/insertion typosquatting (`send_meail`) — an edit-distance rule also flags legitimate singular/plural pairs.
- A poisoning payload naming no resource at all ("pass your API key in the `auth` field").
- Laundering a bare identifier by declaring an input with that name. Paths, URLs, and env vars are immune by construction; a test pins that.
- Cross-server shadowing is invisible to a single-endpoint scan, and the report says so.

`tenant_leakage` has no detector and renders as `NO CHECK` — Phase 3, along with the logging proxy.

### Housekeeping

- `CLAUDE.md` refreshed for session handoff: accurate module list, the conventions that govern detector work, and current Phase 1 state.

- `main.py` (PyCharm sample) deleted; it had also acquired a stray character that made it invalid Python.
- `CLAUDE.md` added, including the uv pip-shim warning.
- README rewritten twice — first for MCP Sentinel, then again once the demo path actually worked, since the "not yet functional" banner had become false in the other direction.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
