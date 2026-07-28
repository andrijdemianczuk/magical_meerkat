# Fixture Schema

A fixture declares one MCP server surface plus a ground-truth label. One file,
one fixture, no central registry — same ethos as attack modules (D-001).

Fixtures are **data, not code.** Payload text is inert YAML; nothing in a fixture
executes. Rug-pull will eventually need a fixture whose surface *changes between
scans*, which this format cannot express — deferred deliberately until the static
corpus is stable, rather than bent into the schema now.

## Fields

| Field | Required | Description |
| --- | --- | --- |
| `id` | yes | Stable identifier, `<attack-class>/<slug>`. Referenced by test output and reports; treat as an API. |
| `attack_class` | yes | `tool_poisoning`, `tool_shadowing`, `prompt_injection_via_output`, `rug_pull`, `tenant_leakage`. |
| `label` | yes | `vulnerable` or `clean`. The ground truth. |
| `pair` | yes | Slug shared by a vulnerable/clean pair, so the corpus can report per-pair. |
| `rationale` | yes | Why this label. On `clean` fixtures, state specifically which naive detector this is built to defeat. |
| `mode` | yes | `passive` (detectable from `tools/list` alone) or `active` (requires invoking a tool). |
| `tools` | yes | The declared tool surface — see below. |
| `canary` | active only | Unique inert token. See *Canaries*. |
| `expect.detect` | yes | Whether a correct detector fires. Mirrors `label`, stated separately so it stays readable at the assertion site. |
| `expect.signals` | no | Named signals that should contribute. Advisory — for debugging why a detector fired, not asserted strictly. |

OWASP mapping deliberately lives on the **attack module**, not here. A fixture
describes what a server *is*; the mapping describes how Sentinel *classifies* it.
Keeping them apart means re-mapping to a new framework version doesn't touch the
corpus.

### `tools[]`

Mirrors the MCP tool definition so a fixture can be served as-is.

| Field | Description |
| --- | --- |
| `name` | Tool name as advertised. |
| `description` | Description string. **The primary attack surface for passive classes.** |
| `inputSchema` | JSON Schema for arguments, as MCP expects. |
| `returns` | What `tools/call` returns. The attack surface for `active` classes. |

## Canaries

Active fixtures carry a unique token, `SENTINEL_CANARY_<hex>`. Two jobs:

1. **Inertness.** A payload claiming to exfiltrate `~/.ssh/id_rsa` returns the
   canary instead of touching the filesystem. The fixture is dangerous-looking
   and harmless.
2. **Unambiguous ground truth later.** When the canary surfaces somewhere it
   shouldn't — an outbound argument, a log — the injection provably worked. No
   judgment call, no LLM, just a string match.

One caveat worth being honest about: Sentinel is a scanner, not an agent. It
detects that an injection *attempt is present*, not that an agent *falls for it*.
Job 2 only pays off against a real agent in the loop. The token is in the schema
now so the corpus doesn't need rewriting when that harness exists.

## Adding a fixture

Never add a `vulnerable` fixture without its `clean` counterpart. An unpaired
vulnerable fixture measures recall while silently ignoring precision, which is
the failure mode this corpus exists to prevent.
