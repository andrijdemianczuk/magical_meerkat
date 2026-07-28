# MCP Sentinel — Decision Log

> This file IS the interview artifact. Every non-obvious choice gets a short entry: what, why, what was rejected. When an interviewer asks "why did you build it this way," the answer is already written.

Format per entry: **Decision** / **Context** / **Alternatives rejected** / **Tradeoff accepted**

---

## D-001: Self-registering attack modules
- **Decision:** Each attack is one file that registers itself; adding an attack requires no central wiring.
- **Context:** Attack corpus will grow; want contribution to be frictionless.
- **Alternatives rejected:** Central registry list (merge conflicts, easy to forget).
- **Tradeoff accepted:** Slight import-time magic in exchange for zero-wiring extensibility.

## D-002: Attacks declare `passive` or `active`
- **Decision:** Every attack declares a mode. `passive` decides from the declared surface (`tools/list`) with no side effects; `active` must invoke tools and is opt-in, never the default. Replaces the original `run(client) -> Finding` contract with `analyze(tool) -> Finding`.
- **Context:** Tool poisoning and shadowing are fully visible in `tools/list` — the tool never has to be called. Injection-via-output is only visible in a response body. Collapsing both into one "run it" contract means every scan invokes every tool, and a target's tools may be `send_email` or `delete_repo`. The scanner has its own blast radius.
- **Alternatives rejected:** One uniform contract with a "dry run" flag (makes the safe path the exception, and each attack reinterprets the flag); a deny-list of dangerous tool names (unbounded, and wrong by default).
- **Tradeoff accepted:** Two code paths and a mode to keep correct on every new attack, in exchange for a default scan that cannot mutate a target.

## D-003: Fixtures ship in vulnerable/clean pairs
- **Decision:** No vulnerable fixture without a clean control built to defeat the naive detector for that class. The loader rejects an unbalanced pair.
- **Context:** A corpus of only-vulnerable servers measures recall and silently ignores precision. A scanner with a bad false-positive rate is worse than none, because a clean scorecard gets believed. The controls are where the real work is — `deploy_service` deliberately carries "IMPORTANT:", "always", a call-this-first instruction, a filesystem path, and a failure warning.
- **Alternatives rejected:** Vulnerable-only corpus with false positives caught in review (unmeasured, drifts); real-world servers as controls (unlabelled, unstable, unshippable).
- **Tradeoff accepted:** Roughly double the fixture-authoring effort, and the controls are the harder half to write.

## D-004: Weighted signals, with weight-0 signals that never decide
- **Decision:** Findings are a sum of named signals against a threshold. Patterns that occur just as often in benign descriptions are recorded at weight 0 — shown as evidence, never able to fire a finding.
- **Context:** `imperative_directed_at_agent` and `coercive_framing` match *both* fixtures in the first pair. They are genuinely informative to a human reading the report and genuinely useless as a trigger. Dropping them loses explanatory value; weighting them loses the control.
- **Alternatives rejected:** Boolean `detect()` (no evidence trail, no tuning surface); dropping non-discriminating patterns (report says "detected" with nothing to show).
- **Tradeoff accepted:** Threshold and weights are hand-tuned against a tiny corpus and will need refitting as it grows. A test asserts both signals stay at weight 0, so raising one fails loudly.

