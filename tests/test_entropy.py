"""Tests for safepaste.detector.entropy."""

from __future__ import annotations

import math

import pytest

from safepaste.detector import entropy


def test_shannon_empty_string_is_zero() -> None:
    assert entropy.shannon("") == 0.0


def test_shannon_single_repeated_char_is_zero() -> None:
    # One symbol at probability 1 contributes -1*log2(1) == 0, no matter how
    # long the run is.
    assert entropy.shannon("aaaaaaaaaaaa") == 0.0


@pytest.mark.parametrize(
    "data",
    [
        "ab",  # 2 equally likely symbols
        "aabb",
        "abcd",  # 4 equally likely symbols
        "aabbccdd",
        "abcdefgh",  # 8 equally likely symbols
    ],
)
def test_shannon_known_values_match_log2_of_symbol_count(data: str) -> None:
    # Cross-check against the textbook formula instead of a second hardcoded
    # magic number: n equally-likely symbols carry exactly log2(n) bits each.
    expected = math.log2(len(set(data)))
    assert entropy.shannon(data) == pytest.approx(expected)


def test_passes_uses_a_strict_greater_than() -> None:
    # Gitleaks' own comparison is strict, and the docstring on `passes` is
    # explicit that this port matches it: a candidate scoring *exactly* the
    # threshold must be rejected, not accepted.
    value = "abcd"  # shannon(...) == log2(4) == 2.0 exactly
    threshold = entropy.shannon(value)
    assert entropy.passes(value, threshold) is False
    assert entropy.passes(value, threshold - 0.001) is True


@pytest.mark.parametrize("threshold", [None, 0])
def test_passes_treats_falsy_threshold_as_no_filter(threshold: float | None) -> None:
    # `if not threshold` in the implementation means both "no threshold set"
    # and "threshold is literally zero" skip the entropy check entirely.
    assert entropy.passes("", threshold) is True
    assert entropy.passes("aaaaaaaa", threshold) is True  # would fail any real bar
