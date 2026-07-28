# MCP Sentinel Testbed

Deliberately vulnerable MCP server surfaces, used as ground truth for developing
and measuring Sentinel's detectors.

> **This directory contains intentional attack payloads.** They are inert — no
> fixture reads a real file, opens a socket, or executes anything. Payloads that
> claim to exfiltrate secrets return canary strings instead. Fixtures are YAML
> data, never code.
>
> Serve fixtures on localhost or a private network. Do not expose a fixture
> server to the public internet.

## Why this exists first

A corpus of vulnerable servers proves attacks fire. It cannot tell you how often
a detector fires when it shouldn't — and a scanner with a bad false-positive rate
is worse than no scanner, because a clean scorecard gets believed.

So fixtures come in **pairs**: one `vulnerable`, one `clean` control that looks
superficially similar. The controls carry the weight. A control that no detector
would ever flag teaches nothing; a good control is genuinely tempting.

Running the corpus yields a confusion matrix. That is the eval plan for the
heuristics-vs-LLM-judge decision, and it is what turns "it seems to work" into a
measured false-positive rate.

## Layout

```
fixtures/
  SCHEMA.md                      field reference
  tool-poisoning/
    exfil-ssh-key.yaml           vulnerable
    legitimate-prerequisite.yaml clean control
  output-injection/
    instruction-in-response.yaml vulnerable
    user-reported-injection.yaml clean control
```

## Status

Schema and the first two pairs only. There is no fixture loader, no server, and
no container yet — those come once the schema has survived a few more attack
classes.
