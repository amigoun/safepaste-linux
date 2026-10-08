"""Secret detection: Gitleaks-compatible rules, plus SafePaste's own."""

from .engine import (
    DEFAULT_PLACEHOLDER,
    EXCLUSION_SCHEME,
    Detector,
    Finding,
    ScanResult,
    is_keyed_digest,
    labelled_placeholder,
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
    "ScanResult",
    "is_keyed_digest",
    "labelled_placeholder",
    "load_default",
    "merge_spans",
    "summarise",
    "value_hash",
]
