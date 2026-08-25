"""Secret detection: Gitleaks-compatible rules, plus SafePaste's own."""

from .engine import (
    EXCLUSION_SCHEME,
    Detector,
    Finding,
    is_keyed_digest,
    merge_spans,
    summarise,
    value_hash,
)
from .rules import CATEGORIES, CATEGORY_LABELS, Rule, RuleSet, load_default

__all__ = [
    "CATEGORIES",
    "CATEGORY_LABELS",
    "Detector",
    "EXCLUSION_SCHEME",
    "Finding",
    "Rule",
    "RuleSet",
    "is_keyed_digest",
    "load_default",
    "merge_spans",
    "summarise",
    "value_hash",
]
