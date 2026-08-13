"""Wall-clock budgets for the regex-timeout ReDoS guard.

No pytest-timeout plugin is used (the project takes no new dependencies):
these assert directly against time.monotonic() and print the measured figure
so a slow CI box shows *why* a budget was blown, not just that it was.
"""

from __future__ import annotations

import random
import time

import pytest

from safepaste.detector import Detector
from safepaste.detector.rules import RuleSet

# These are the suite's "slower paths" (large/pathological inputs, wall-clock
# assertions): the one module where an `-m "not integration"` opt-out during
# fast local iteration is worth having.
pytestmark = pytest.mark.integration


def test_benign_200kb_scan_completes_well_under_5s(detector: Detector) -> None:
    rng = random.Random(42)
    words = [
        "the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "report",
        "quarter", "meeting", "notes", "action", "items", "summary", "project",
    ]
    text = " ".join(rng.choice(words) for _ in range(35_000))
    assert len(text) > 200_000

    started = time.monotonic()
    detector.scan(text)
    elapsed = time.monotonic() - started

    print(f"\n[test_redos] benign {len(text)}-char scan: {elapsed:.3f}s")
    assert elapsed < 5.0


def _pathological_inputs() -> list[pytest.param]:
    rng = random.Random(7)
    base64_alphabet = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    )
    cases = [
        ("100KB of 'a'", "a" * 100_000),
        ("50KB of 'A' + trailing bang", "A" * 50_000 + "!"),
        ("20K run of quotes", '"' * 20_000),
        ("20K run of equals signs", "=" * 20_000),
        (
            "50K run of base64-alphabet chars",
            "".join(rng.choice(base64_alphabet) for _ in range(50_000)),
        ),
    ]
    # Explicit ids: without them pytest derives a node id from the parameter
    # values themselves, and a 100,000-character payload as a test id makes
    # every report and terminal line unreadable.
    return [pytest.param(name, text, id=name) for name, text in cases]


@pytest.mark.parametrize(("name", "text"), _pathological_inputs())
def test_pathological_inputs_do_not_hang(detector: Detector, name: str, text: str) -> None:
    started = time.monotonic()
    detector.scan(text)
    elapsed = time.monotonic() - started

    print(f"\n[test_redos] {name} ({len(text)} chars): {elapsed:.3f}s")
    assert elapsed < 10.0


def test_tight_regex_timeout_guard_still_returns(ruleset: RuleSet) -> None:
    # A per-rule timeout of 1ms should make the guard trip on essentially
    # every rule that even attempts to match; the point is that scan() still
    # *returns* promptly rather than hanging on a superlinear backtrack.
    d = Detector(ruleset=ruleset, regex_timeout=0.001)
    text = "key=" + "a" * 300_000 + "!"

    started = time.monotonic()
    findings = d.scan(text)
    elapsed = time.monotonic() - started

    print(f"\n[test_redos] tight-timeout (0.001s) scan: {elapsed:.3f}s")
    assert elapsed < 10.0
    assert isinstance(findings, list)
