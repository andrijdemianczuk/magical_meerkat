# MCP Sentinel

_Repo codename: `magical_meerkat`._

An MCP governance and red-team harness. Point it at an MCP server endpoint, run a corpus of known attack classes, and get back an OWASP-mapped governance scorecard. Proxy mode sits between agent and server, logging every request and response attributed to user and session.

> **Status: pre-release. No working demo path yet.**
> Phase 1 is in progress and every checklist item in [`docs/plan.md`](docs/plan.md) is still open — there is no `sentinel` package, no CLI entry point, and no tests. The Run section below documents the *intended* interface, not something you can execute today. Fork for the design and the decision log; check back for the demo.

## Problem

MCP servers are trusted tool surfaces handed to autonomous agents, but the trust is largely implicit. A server's tool descriptions are injected into an agent's context, so whoever controls those descriptions has partial control of the agent. The failure modes are not theoretical:

- **Tool poisoning** — malicious instructions embedded in a tool description.
- **Tool shadowing** — a hostile tool that impersonates or overrides a legitimate one.
- **Prompt injection via tool output** — the response body, not the description, carries the payload.
- **Rug-pulls** — a description changes after the user approved it.
- **Cross-tenant leakage** — one tenant's session observing another's data.

These are non-human-identity problems: the thing being exploited holds credentials, acts without a human in the loop, and is trusted by default. Sentinel exists to make that blast radius measurable before it is discovered in production.

## Architecture

Target → client → attack runner → report. See [`docs/architecture.md`](docs/architecture.md) for detail and [`docs/decisions.md`](docs/decisions.md) for why it is shaped this way.

| Component | Role |
| --- | --- |
| `sentinel/client/` | Thin MCP JSON-RPC wrapper. Isolates protocol details from attacks. |
| `sentinel/attacks/` | One self-contained module per attack class. |
| `sentinel/report/` | Aggregates findings into an OWASP-mapped scorecard. |
| `sentinel/proxy/` | Logging proxy and policy enforcement (Phase 3). |

Attack modules are **self-registering** — adding an attack means adding one file, with no central wiring to update. The contract is `name`, `owasp_mapping`, `run(client) -> Finding`, `detect(response) -> bool`. Rationale and the rejected alternative are recorded as D-001 in the decision log.

Findings map to the OWASP MCP Top 10 and the Agentic Security Top 10.

## Run

**Not yet functional** — recorded here so the intended surface is reviewable.

```bash
uv pip install -e .
sentinel scan <endpoint>
pytest
```

### Environment

Python 3.14 in `.venv`, created and managed by [uv](https://docs.astral.sh/uv/).

```bash
uv venv --python 3.14
source .venv/bin/activate
uv pip install -e .
```

Install with `uv pip install`, never bare `pip install`. `.venv/bin/pip` is a shim that re-routes to uv; without it `pip` can fall through to another interpreter on your `PATH` and install into the wrong Python. Re-running `uv venv` recreates the venv and destroys that shim.

No secrets, API keys, or hosted services are required — the demo path targets a local server you run yourself.

## Safety

**Only run Sentinel against MCP servers you own, or against issues already publicly disclosed and patched.** The default target is a local server. Running an attack corpus against a third party's endpoint without written authorization is not a demo, and this project will not ship an allowlist that makes it convenient.

## Limitations

- Absence of a finding is **not** evidence of a secure server. Coverage is limited to the attack classes currently implemented; a clean scorecard means "none of these known classes fired," nothing more.
- Detection is heuristic. Expect both false positives and false negatives, and read findings as leads to investigate rather than verdicts.
- Scope is the MCP tool boundary. Sentinel says nothing about the agent's own reasoning, the model, or the surrounding application.

## Related projects

Part of a three-project body of work on governing agentic systems:

- **EvalDeck** — reliability- and cost-aware agent evals dashboard. _(link TBD)_
- **The Governed Agent** — capstone reference architecture; consumes this project at the tool boundary. _(link TBD)_
- Shared landing page — _(link TBD)_
