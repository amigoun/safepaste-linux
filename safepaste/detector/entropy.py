"""Shannon entropy, kept bit-compatible with Gitleaks' own implementation.

Gitleaks compares with a strict `>`, so a rule declaring `entropy = 3.0` rejects
a candidate scoring exactly 3.0. We match that, because the vendored thresholds
were tuned against it.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon(data: str) -> float:
    """Bits of entropy per character.

    Gitleaks divides by Go's len(), i.e. the *byte* length, while iterating
    runes. For the ASCII-range strings that secrets actually consist of the two
    are identical; for anything else this returns the per-character figure,
    which is the more defensible number anyway.
    """
    if not data:
        return 0.0
    length = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        freq = count / length
        entropy -= freq * math.log2(freq)
    return entropy


def passes(data: str, threshold: float | None) -> bool:
    """True if `data` is random-looking enough to still be considered a secret."""
    if not threshold:
        return True
    return shannon(data) > threshold
