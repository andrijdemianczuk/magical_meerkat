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

## D-005: Mitigating signals are never negative
- **Decision:** Signals that argue *against* a finding are recorded at weight 0, never below it. `override_in_quotation` explains why the benign control did not fire; it cannot reduce anyone's score.
- **Context:** The control's injection phrase sits inside quotation marks because a user is citing it in a bug report. That is real evidence and belongs in the report. But any signal that subtracts is a published bypass — an attacker wraps the payload in quotes and the score drops below threshold.
- **Alternatives rejected:** Negative weights (directly exploitable); dropping the mitigator (report shows a non-detection with no explanation).
- **Tradeoff accepted:** Mitigators cannot rescue a false positive on their own, so precision has to come from the positive signals being specific enough. A test wraps the payload in quotes and asserts it is still detected.

## D-006: Detectors may not key on testbed artifacts
- **Decision:** No detector may match the canary token or anything else that exists only in fixtures. Enforced by a test that strips the canary and asserts detection is unchanged.
- **Context:** The canary is the most reliable string in the corpus, so keying on it is the path of least resistance — and it would score 100% while detecting nothing on a real server. This failure is silent: the corpus goes green and the confusion matrix looks excellent.
- **Alternatives rejected:** Code review alone (this is exactly the shortcut a tired evening takes); randomising canaries per run (raises the cost of cheating without preventing it).
- **Tradeoff accepted:** One extra test per active attack, and the canary's payoff is deferred until an agent-in-the-loop harness exists.

## D-007: Attacks declare `tool` or `surface` scope
- **Decision:** A second axis alongside `mode`. `tool` attacks judge one tool via `analyze(tool)`; `surface` attacks judge the whole advertised set via `analyze_surface(tools)`. `attacks.run()` dispatches so callers never branch on it.
- **Context:** Shadowing broke the per-tool contract on contact. Neither `send_email` nor `send_emai1` is suspicious alone — the attack exists only in the relationship between them, and a detector that can see one tool at a time cannot see it at all. Predicted during planning; confirmed on the first attempt to write it.
- **Alternatives rejected:** Passing siblings into `analyze()` as an extra argument (every tool-scoped attack pays for a parameter it ignores, and one finding gets emitted per tool instead of per pair); a separate surface-attack registry (two discovery paths, and the CLI has to know which is which).
- **Tradeoff accepted:** Two call shapes to keep straight, and `Finding.tool` becomes "the tool this is anchored on" rather than "the tool analyzed". Surface findings pick the aggressor where one is identifiable. Extended to a third scope, `baseline`, when rug-pull landed.

## D-008: Rug-pull composes the passive detectors instead of matching text
- **Decision:** A change is a rug-pull when re-running the passive tool-scoped detectors makes something fire on the new definition that did not fire on the approved one. `rug_pull` writes no patterns of its own.
- **Context:** The obvious implementation greps the diff for suspicious strings, which duplicates every detector and immediately drifts from them. Composition means each new passive attack automatically becomes a rug-pull trigger, and there is one place where "what counts as poisoning" is defined.
- **Alternatives rejected:** Independent patterns in `rug_pull` (two definitions of the same thing, guaranteed to diverge); flagging any post-approval change (fires on every documentation edit, gets muted within a week, then catches nothing).
- **Tradeoff accepted:** Recall is bounded by the passive corpus — a change introducing an attack class with no detector reads as a benign edit. And a tool that was *already* poisoned when the baseline was taken produces no finding, because nothing changed. Baselines record what was approved, not what was safe; both limits are stated in the module docstring and one is pinned by a test.

