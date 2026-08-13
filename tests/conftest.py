"""Shared fixtures for the SafePaste test suite."""

from __future__ import annotations

import pytest

from safepaste.detector import Detector
from safepaste.detector.rules import RuleSet, load_default


def pytest_configure(config: pytest.Config) -> None:
    # Belt-and-braces registration alongside pyproject.toml's ini option: a
    # conftest-based hook still registers the marker even if the suite is ever
    # invoked with a rootdir that skips the ini file.
    config.addinivalue_line(
        "markers",
        "integration: exercises more than one module together / slower paths",
    )


@pytest.fixture(scope="module")
def ruleset() -> RuleSet:
    """The vendored + SafePaste ruleset, parsed once per test module.

    Parsing ~230 rules out of two TOML files and compiling their regexes is
    real work; tests that only need to inspect rules (not scan text) should
    prefer this over building a whole Detector.
    """
    return load_default()


@pytest.fixture(scope="module")
def detector(ruleset: RuleSet) -> Detector:
    """A default (unrestricted) Detector, shared across a module's tests.

    Building one from scratch is ~200ms, dominated by the rule parse above.
    Tests that need a *different* configuration (categories, excluded_hashes,
    max_scan_bytes, regex_timeout, ...) should construct their own
    `Detector(ruleset=ruleset, ...)` from the `ruleset` fixture rather than
    reaching for this one — that reuses the already-parsed rules and only
    redoes the cheap filtering step.
    """
    return Detector(ruleset=ruleset)
