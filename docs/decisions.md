# MCP Sentinel — Decision Log

> This file IS the interview artifact. Every non-obvious choice gets a short entry: what, why, what was rejected. When an interviewer asks "why did you build it this way," the answer is already written.

Format per entry: **Decision** / **Context** / **Alternatives rejected** / **Tradeoff accepted**

---

## D-001: Self-registering attack modules
- **Decision:** Each attack is one file that registers itself; adding an attack requires no central wiring.
- **Context:** Attack corpus will grow; want contribution to be frictionless.
- **Alternatives rejected:** Central registry list (merge conflicts, easy to forget).
- **Tradeoff accepted:** Slight import-time magic in exchange for zero-wiring extensibility.

## D-002: [next decision here]
