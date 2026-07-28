"""Run registered detectors over the fixture corpus and report a confusion matrix.

    python -m sentinel.testbed.evaluate

Fixtures whose attack class has no registered detector are reported as
uncovered rather than silently counted — an uncovered class scoring 0/0 reads
like success otherwise.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from sentinel.attacks import Finding, for_class
from sentinel.testbed.loader import Fixture, load_corpus


@dataclass(frozen=True, slots=True)
class Result:
    fixture: Fixture
    detected: bool
    findings: tuple[Finding, ...]

    @property
    def correct(self) -> bool:
        return self.detected is self.fixture.expect_detect

    @property
    def outcome(self) -> str:
        match (self.fixture.expect_detect, self.detected):
            case (True, True):
                return "TP"
            case (False, False):
                return "TN"
            case (False, True):
                return "FP"
            case _:
                return "FN"


def evaluate(fixture: Fixture) -> Result | None:
    """Run every detector for this fixture's attack class. None if uncovered."""
    attacks = [a for a in for_class(fixture.attack_class) if a.mode == fixture.mode]
    if not attacks:
        return None
    findings = tuple(a.analyze(tool) for a in attacks for tool in fixture.tools)
    return Result(fixture, any(f.detected for f in findings), findings)


def run(root: Path | None = None) -> int:
    """Evaluate the corpus, print a report, return a process exit code."""
    corpus = load_corpus(root)
    results: list[Result] = []
    uncovered: list[Fixture] = []

    for fixture in corpus:
        result = evaluate(fixture)
        if result is None:
            uncovered.append(fixture)
        else:
            results.append(result)

    print("Fixture results")
    print("-" * 78)
    for r in results:
        mark = "ok " if r.correct else "FAIL"
        print(f"{mark} {r.outcome}  {r.fixture.id:<46} {r.fixture.mode}")
        for f in r.findings:
            if not f.signals:
                print(f"      {f.tool}: no signals")
                continue
            print(
                f"      {f.tool}: score {f.score}/{f.threshold} -> detected={f.detected}"
            )
            for s in f.fired:
                print(f"        + [{s.weight}] {s.name}: {s.evidence}")
            for s in f.informational:
                print(f"          [0] {s.name}: {s.evidence}")

    counts = {k: sum(1 for r in results if r.outcome == k) for k in ("TP", "FP", "TN", "FN")}
    tp, fp, tn, fn = counts["TP"], counts["FP"], counts["TN"], counts["FN"]
    precision = tp / (tp + fp) if tp + fp else float("nan")
    recall = tp / (tp + fn) if tp + fn else float("nan")

    print()
    print(f"Confusion matrix over {len(results)} evaluated fixtures")
    print("-" * 78)
    print(f"  TP {tp}   FP {fp}   TN {tn}   FN {fn}")
    print(f"  precision {precision:.2f}   recall {recall:.2f}")

    if uncovered:
        print()
        print(f"Uncovered ({len(uncovered)}) — no registered detector, not scored")
        print("-" * 78)
        for f in uncovered:
            print(f"  {f.id:<46} {f.attack_class} / {f.mode}")

    missing = {
        s
        for r in results
        for s in r.fixture.expect_signals
        if s not in {sig.name for f in r.findings for sig in f.signals}
    }
    if missing:
        print()
        print("Expected signals not implemented (advisory)")
        print("-" * 78)
        for s in sorted(missing):
            print(f"  {s}")

    print()
    print(
        f"NOTE: {len(results)} evaluated fixtures is far too small for these numbers to "
        "generalize.\n      They guard against regression; they do not measure real-world "
        "accuracy."
    )
    return 0 if all(r.correct for r in results) else 1


if __name__ == "__main__":
    sys.exit(run())
