"""Report rendering.

Plaintext only for now. The governance scorecard and web view are Phase 2, and
`docs/architecture.md` records the intent that reports stay JSON-first with
rendered views on top — this module is the first of those views, not the format
of record.
"""

from sentinel.report.plaintext import render

__all__ = ["render"]
