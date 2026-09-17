"""Replacing secrets in place, leaving everything else byte-identical.

The design constraint that matters: a 12 KB document containing one key must
come back as the same 12 KB document with that one key replaced. Nuking the
whole clipboard would be safe but useless, and users would turn SafePaste off.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..detector.engine import Finding, merge_spans

DEFAULT_PLACEHOLDER = "[REDACTED]"

# Kept at each end of a secret by default, so a redacted value can still be told
# apart from its neighbours: the head carries the key type (ghp_, AKIA, ox_) and
# the tail distinguishes two keys of the same type.
DEFAULT_KEEP_PREFIX = 4
DEFAULT_KEEP_SUFFIX = 4

# However much is asked for, this many characters of every secret stay hidden.
# Without a floor, `keep_prefix = 8` on an eight-character password prints the
# password -- the request is per-value and the secret is not.
MIN_HIDDEN_CHARS = 4


@dataclass(frozen=True)
class RedactionStyle:
    """How a replaced secret reads afterwards."""

    placeholder: str = DEFAULT_PLACEHOLDER
    # Name the rule that fired, e.g. [REDACTED:aws-access-token]. Useful when
    # sharing a sanitised log; slightly more revealing.
    label_rules: bool = False
    # Characters kept at each end of the secret, so a redacted value can still
    # be recognised. These are a *request*: see _edges, which lowers them for a
    # secret short enough that honouring them would print most of it.
    keep_prefix: int = DEFAULT_KEEP_PREFIX
    keep_suffix: int = DEFAULT_KEEP_SUFFIX


@dataclass(frozen=True)
class Redaction:
    text: str
    secrets_removed: int
    chars_removed: int
    chars_kept: int
    labels: tuple[str, ...]

    @property
    def changed(self) -> bool:
        return self.secrets_removed > 0


def redact(
    text: str, findings: list[Finding], style: RedactionStyle | None = None
) -> Redaction:
    """Replace every found secret, preserving the surrounding text exactly."""
    style = style or RedactionStyle()
    if not findings:
        return Redaction(text, 0, 0, len(text), ())

    # Merge first: several rules commonly flag one value, and replacing per
    # finding would corrupt offsets and double-report.
    spans = merge_spans(findings)

    # Attribute each merged span to the rules that produced it, for the dialog.
    labels: list[str] = []
    by_span: dict[tuple[int, int], list[str]] = {}
    for span in spans:
        owners = [
            f.rule_id for f in findings if f.start >= span[0] and f.end <= span[1]
        ]
        by_span[span] = owners
        for f in findings:
            if f.start >= span[0] and f.end <= span[1] and f.label not in labels:
                labels.append(f.label)

    out: list[str] = []
    cursor = 0
    removed = 0
    for start, end in spans:
        out.append(text[cursor:start])
        secret = text[start:end]
        prefix, suffix = _edges(secret, style)
        out.append(_replacement(secret, by_span[(start, end)], style))
        # Only the middle is gone. Counting the whole span here would make the
        # dialog's "N characters were kept intact" wrong by however much the
        # edges preserved.
        removed += (end - start) - len(prefix) - len(suffix)
        cursor = end
    out.append(text[cursor:])

    return Redaction(
        text="".join(out),
        secrets_removed=len(spans),
        chars_removed=removed,
        chars_kept=len(text) - removed,
        labels=tuple(labels),
    )


def _edges(secret: str, style: RedactionStyle) -> tuple[str, str]:
    """The head and tail left visible, after the safety floor is applied.

    Two caps, both on the total revealed: never more than half the secret, and
    never so much that fewer than MIN_HIDDEN_CHARS remain. They matter because
    keep_prefix/keep_suffix are configured once against no particular value,
    while the values themselves range from a 4-character PIN to a 3 KB private
    key -- and it is the short ones a fixed count would strip bare.

    When the budget cannot cover both, the head is served first: it carries the
    key type, which is the half that says *what* was redacted.
    """
    want_prefix = max(0, style.keep_prefix)
    want_suffix = max(0, style.keep_suffix)
    if not (want_prefix or want_suffix):
        return "", ""

    budget = min(
        want_prefix + want_suffix,
        len(secret) - MIN_HIDDEN_CHARS,
        len(secret) // 2,
    )
    if budget <= 0:
        return "", ""

    take_prefix = min(want_prefix, budget)
    take_suffix = min(want_suffix, budget - take_prefix)
    return (
        secret[:take_prefix],
        secret[len(secret) - take_suffix :] if take_suffix else "",
    )


def _replacement(secret: str, rule_ids: list[str], style: RedactionStyle) -> str:
    body = style.placeholder
    if style.label_rules and rule_ids:
        # Deduplicate while keeping order, so a span owned by three rules reads
        # as one sensible label rather than a pile.
        seen: list[str] = []
        for rid in rule_ids:
            if rid not in seen:
                seen.append(rid)
        inner = ",".join(seen)
        body = f"{style.placeholder.rstrip(']')}:{inner}]"
    prefix, suffix = _edges(secret, style)
    if prefix and suffix:
        return f"{prefix}…{body}…{suffix}"
    if prefix:
        return f"{prefix}…{body}"
    if suffix:
        return f"{body}…{suffix}"
    return body
