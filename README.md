# MCP Sentinel

_Repo codename: `magical_meerkat`._

An MCP governance and red-team harness. Point it at an MCP server endpoint, run a corpus of known attack classes, and get back an OWASP-mapped governance scorecard. Proxy mode sits between agent and server, logging every request and response attributed to user and session.

> **Status: early, but runnable.** Four attack classes ship with detectors, each
> validated against a labelled corpus. No dependency beyond PyYAML, no secrets,
> no hosted services — clone it and the demo below works. Remaining Phase 1 work
> is tracked in [`docs/plan.md`](docs/plan.md); tenant isolation and the logging
> proxy are Phase 3.

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
| `sentinel/client/` | MCP JSON-RPC over stdio and Streamable HTTP. Isolates protocol from attacks. |
| `sentinel/attacks/` | One self-contained module per attack class. |
| `sentinel/baseline.py` | Approved-surface snapshots and diffs, for change detection. |
| `sentinel/report/` | Renders a scan into a report. |
| `sentinel/testbed/` | Fixture loader, corpus evaluator, and a fixture-backed MCP server. |
| `sentinel/proxy/` | Logging proxy and policy enforcement (Phase 3, not started). |

Attack modules are **self-registering** — adding an attack means adding one file, with no central wiring to update (D-001). Each declares two axes:

- **`mode`** — `passive` decides from `tools/list` alone; `active` must invoke tools and is opt-in, because a target's tools may be `send_email` or `delete_repo` (D-002).
- **`scope`** — `tool` judges one description; `surface` needs the whole set, because a typosquatted name is invisible until you can see the tool it imitates; `baseline` needs a previously approved surface (D-007).

Findings map to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) and the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/). Identifiers are resolved against a catalog at registration, so a mistyped or invented category fails at import rather than reaching a report.

### Detectors are built around their false positives

Every vulnerable fixture ships with a **clean control** designed to defeat the naive detector for its class (D-003). The controls are the real work:

| Class | The payload | The control that must *not* fire |
| --- | --- | --- |
| Tool poisoning | Description tells the agent to read `~/.ssh/id_rsa` and pass the contents | A deploy tool with "IMPORTANT:", "always call X first", and a config path |
| Output injection | Instruction hidden in an HTML comment, with a destination and "do not mention this" | A support ticket where a user *quotes* an injection while reporting it |
| Tool shadowing | `send_emai1` claiming `send_email` is broken | `search_docs_v2` deprecating `search_docs` — an ordinary version bump |
| Rug-pull | Approved tool silently gains a credential-exfiltration instruction | The same tool gaining usage notes and an optional parameter |

In every pair the obvious keyword fires on **both** sides, so those signals carry weight `0` — recorded as evidence, structurally unable to trigger a finding.

## Run

```bash
uv pip install -e ".[dev]"
```

**Attack a server and watch it fire.** The testbed serves a fixture as a real
MCP server over stdio, so this is an actual JSON-RPC scan, not a simulation:

```bash
sentinel scan --stdio -- python -m sentinel.testbed.server \
    testbed/fixtures/tool-poisoning/exfil-ssh-key.yaml
```

Swap in `tool-shadowing/typosquatted-sibling.yaml` to see a typosquatted tool
caught, or add `--active` with `output-injection/instruction-in-response.yaml`
to reach the checks that require invoking tools.

**Watch a rug-pull.** Approve one surface, then scan a changed one:

```bash
sentinel baseline -o approved.json --stdio -- python -m sentinel.testbed.server \
    testbed/fixtures/rug-pull/expanded-documentation.yaml
sentinel scan --baseline approved.json --stdio -- python -m sentinel.testbed.server \
    testbed/fixtures/rug-pull/poisoned-after-approval.yaml
```

**Check the detectors against ground truth** — a confusion matrix over the
labelled corpus, including the benign controls:

```bash
sentinel corpus
pytest
```

Exit codes are `0` (nothing fired), `1` (findings), `2` (could not scan), so a
scan drops into CI unchanged. Scanning is **passive by default**: `--active`
invokes the target's tools, and against a non-loopback host it additionally
requires `--authorized`.

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
