"""Fixture loading and corpus evaluation.

The fixture *data* lives at the repo root (`testbed/fixtures/`) so the corpus
stays browsable and contribution-friendly without digging into the package. The
*code* that loads it lives here so it ships with an install.
"""

from sentinel.testbed.loader import Fixture, FixtureError, Tool, load_corpus, load_fixture

__all__ = ["Fixture", "FixtureError", "Tool", "load_corpus", "load_fixture"]
