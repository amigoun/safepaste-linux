"""Replacing secrets in place, leaving everything else byte-identical.

The design constraint that matters: a 12 KB document containing one key must
come back as the same 12 KB document with that one key replaced. Nuking the
whole clipboard would be safe but useless, and users would turn SafePaste off.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..detector.engine import Finding, merge_spans

DEFAULT_PLACEHOLDER = "[REDACTED]"


@dataclass(frozen=True)
class RedactionStyle:
    """How a replaced secret reads afterwards."""

    placeholder: str = DEFAULT_PLACEHOLDER
    # Name the rule that fired, e.g. [REDACTED:aws-access-token]. Useful when
    # sharing a sanitised log; slightly more revealing.
    label_rules: bool = False
    # Keep the first N characters of the secret so a key can be told apart from
    # its neighbours. Off by default: a prefix is often enough to identify which
    # key it is, which is exactly what we are trying not to leak.
    keep_prefix: int = 0


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
        out.append(_replacement(secret, by_span[(start, end)], style))
        removed += end - start
        cursor = end
    out.append(text[cursor:])

    return Redaction(
        text="".join(out),
        secrets_removed=len(spans),
        chars_removed=removed,
        chars_kept=len(text) - removed,
        labels=tuple(labels),
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
    if style.keep_prefix > 0:
        prefix = secret[: style.keep_prefix]
        return f"{prefix}…{body}"
    return body
