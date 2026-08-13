"""Secret detection: Gitleaks-compatible rules, plus SafePaste's own."""

from .engine import Detector, Finding, merge_spans, summarise, value_hash
from .rules import CATEGORIES, CATEGORY_LABELS, Rule, RuleSet, load_default

__all__ = [
    "CATEGORIES",
    "CATEGORY_LABELS",
    "Detector",
    "Finding",
    "Rule",
    "RuleSet",
    "load_default",
    "merge_spans",
    "summarise",
    "value_hash",
]
