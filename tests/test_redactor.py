"""Tests for safepaste.redactor: replacing secrets in place."""

from __future__ import annotations

from safepaste.detector import Detector
from safepaste.redactor import RedactionStyle, redact

# ---------------------------------------------------------------------------
# Single secret in a large prose document
# ---------------------------------------------------------------------------


def test_single_secret_in_large_prose_leaves_everything_else_untouched(
    detector: Detector,
) -> None:
    prose_unit = "The quarterly report highlights steady growth across all regions. "
    prose = prose_unit * 170  # ~11.2 KB of filler
    assert len(prose) > 11_000

    secret = "wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u"
    marker = f"AWS_SECRET_ACCESS_KEY={secret}"
    insert_at = 6000
    # A trailing space separates the marker from the resumed prose: without
    # it, generic-api-key's greedy `[\w.=-]{10,150}` capture would keep
    # consuming word characters straight into the next sentence.
    text = prose[:insert_at] + marker + " " + prose[insert_at:]

    findings = detector.scan(text)
    result = redact(text, findings)

    assert result.secrets_removed == 1
    before, _, after = text.partition(marker)
    # Byte-identical outside the replaced span: the prefix up to the secret
    # (including the "AWS_SECRET_ACCESS_KEY=" preamble, which is kept) and the
    # suffix after it must both survive verbatim.
    assert result.text.startswith(before + "AWS_SECRET_ACCESS_KEY=")
    assert result.text.endswith(after)  # `after` already carries the separating space
    assert result.chars_kept == len(text) - len(secret)


# ---------------------------------------------------------------------------
# Two rules flagging one span -> replaced once
# ---------------------------------------------------------------------------


def test_two_rules_on_one_span_are_replaced_once(detector: Detector) -> None:
    text = "DATADOG_API_KEY=4f9b2ac7e1d3805f6b2e9c4a7d1f0836ac52e9d4"
    findings = detector.scan(text)
    assert {f.rule_id for f in findings} == {"datadog-access-token", "generic-api-key"}

    result = redact(text, findings)
    assert result.secrets_removed == 1
    assert result.text.count("[REDACTED]") == 1
    assert result.text == "DATADOG_API_KEY=[REDACTED]"


# ---------------------------------------------------------------------------
# Multi-line PEM block replaced entirely
# ---------------------------------------------------------------------------


def test_multiline_pem_block_replaced_entirely(detector: Detector) -> None:
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpQIBAAKCAQEAv3Hs9YbKq2Nx7RtLpMz4WgVj8DcFo1SaXeUh6TnBk0IrPq5C\n"
        "Zt2Lm9OxWv4RbJd7HqYn1EsUo6VgKp3TfCz8Xa5MiNw0DjRlBu2GhYt6PkQe9Vc4\n"
        "-----END RSA PRIVATE KEY-----"
    )
    text = f"before\n{pem}\nafter"
    findings = detector.scan(text)
    assert len(findings) == 1

    result = redact(text, findings)
    assert result.text == "before\n[REDACTED]\nafter"


# ---------------------------------------------------------------------------
# Unicode before the secret: offsets still correct
# ---------------------------------------------------------------------------


def test_unicode_prefix_does_not_shift_the_redacted_span(detector: Detector) -> None:
    secret = "wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u"
    text = (
        f"emoji before \U0001F600 CJK 你好 then "
        f"AWS_SECRET_ACCESS_KEY={secret} tail"
    )
    findings = detector.scan(text)
    assert findings

    result = redact(text, findings)
    prefix = text[: text.index("AWS_SECRET_ACCESS_KEY=")]
    assert result.text == prefix + "AWS_SECRET_ACCESS_KEY=[REDACTED] tail"


# ---------------------------------------------------------------------------
# Idempotence
# ---------------------------------------------------------------------------


def test_redact_is_idempotent(detector: Detector) -> None:
    text = "AWS_SECRET_ACCESS_KEY=wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u"
    findings = detector.scan(text)
    once = redact(text, findings)

    assert detector.scan(once.text) == []


# ---------------------------------------------------------------------------
# RedactionStyle variations
# ---------------------------------------------------------------------------


def test_redaction_style_custom_placeholder(detector: Detector) -> None:
    text = "SLACK_TOKEN=xoxb-8237456190-8123456789012-Kj83hDbQmZpLxNc9RstV"
    findings = detector.scan(text)

    result = redact(text, findings, RedactionStyle(placeholder="<<HIDDEN>>"))
    assert result.text == "SLACK_TOKEN=<<HIDDEN>>"


def test_redaction_style_label_rules_names_and_dedupes_owners(
    detector: Detector,
) -> None:
    # The Datadog value is owned by two rules on one span; label_rules must
    # name both, once each, not duplicate either.
    text = "DATADOG_API_KEY=4f9b2ac7e1d3805f6b2e9c4a7d1f0836ac52e9d4"
    findings = detector.scan(text)

    result = redact(text, findings, RedactionStyle(label_rules=True))
    assert (
        result.text
        == "DATADOG_API_KEY=[REDACTED:datadog-access-token,generic-api-key]"
    )


def test_redaction_style_keep_prefix_keeps_exactly_n_chars(detector: Detector) -> None:
    secret = "wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u"
    text = f"AWS_SECRET_ACCESS_KEY={secret}"
    findings = detector.scan(text)

    result = redact(text, findings, RedactionStyle(keep_prefix=4))
    assert result.text == f"AWS_SECRET_ACCESS_KEY={secret[:4]}…[REDACTED]"


# ---------------------------------------------------------------------------
# Empty findings
# ---------------------------------------------------------------------------


def test_empty_findings_returns_input_unchanged() -> None:
    text = "nothing to see here"
    result = redact(text, [])
    assert result.text == text
    assert result.changed is False
    assert result.secrets_removed == 0
    assert result.chars_removed == 0
    assert result.chars_kept == len(text)
    assert result.labels == ()
