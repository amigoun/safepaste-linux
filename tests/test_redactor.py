"""Tests for safepaste.redactor: replacing secrets in place."""

from __future__ import annotations

from safepaste.detector import Detector
from safepaste.redactor import MIN_HIDDEN_CHARS, RedactionStyle, _edges, redact

# The default keeps a few characters at each end of a secret. The tests below
# are about something else -- span boundaries, offsets, the
# placeholder, rule labels -- so they ask for the whole value to go, rather than
# restating the current default and having to be rewritten when it moves.
FULL = RedactionStyle(keep_prefix=0, keep_suffix=0)

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
    result = redact(text, findings, FULL)

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

    result = redact(text, findings, FULL)
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

    result = redact(text, findings, FULL)
    assert result.text == "before\n[REDACTED]\nafter"

    # Under the default the kept edges land on the PEM armour, so what shows is
    # dashes rather than key material -- worth pinning, because this is the one
    # secret shape whose first characters are a fixed, public string.
    default = redact(text, findings)
    assert default.text == "before\n----…[REDACTED]…----\nafter"
    for line in pem.splitlines()[1:-1]:
        assert line not in default.text


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

    result = redact(text, findings, FULL)
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

    result = redact(
        text, findings, RedactionStyle(placeholder="<<HIDDEN>>", keep_prefix=0, keep_suffix=0)
    )
    assert result.text == "SLACK_TOKEN=<<HIDDEN>>"


def test_redaction_style_label_rules_names_and_dedupes_owners(
    detector: Detector,
) -> None:
    # The Datadog value is owned by two rules on one span; label_rules must
    # name both, once each, not duplicate either.
    text = "DATADOG_API_KEY=4f9b2ac7e1d3805f6b2e9c4a7d1f0836ac52e9d4"
    findings = detector.scan(text)

    result = redact(
        text, findings, RedactionStyle(label_rules=True, keep_prefix=0, keep_suffix=0)
    )
    assert (
        result.text
        == "DATADOG_API_KEY=[REDACTED:datadog-access-token,generic-api-key]"
    )


def test_redaction_style_keep_prefix_keeps_exactly_n_chars(detector: Detector) -> None:
    secret = "wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u"
    text = f"AWS_SECRET_ACCESS_KEY={secret}"
    findings = detector.scan(text)

    result = redact(text, findings, RedactionStyle(keep_prefix=4, keep_suffix=0))
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


# ---------------------------------------------------------------------------
# Kept edges: what a redacted value still tells you, and what it must not
# ---------------------------------------------------------------------------


def test_default_keeps_both_ends_so_a_key_stays_recognisable(
    detector: Detector,
) -> None:
    """The point of the feature: which key was redacted, without the key."""
    secret = "ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
    text = f"GITHUB_TOKEN={secret}"

    result = redact(text, detector.scan(text))

    assert result.text == f"GITHUB_TOKEN={secret[:4]}…[REDACTED]…{secret[-4:]}"
    # The middle is what carries the entropy, and none of it survives.
    assert secret[4:-4] not in result.text


def test_kept_edges_are_not_counted_as_removed(detector: Detector) -> None:
    """chars_removed feeds the dialog's "N characters were kept intact".

    Counting the whole span would overstate the removal by however much the
    edges preserved, and the dialog would quietly lie about both numbers.
    """
    secret = "wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u"
    text = f"AWS_SECRET_ACCESS_KEY={secret}"
    findings = detector.scan(text)

    kept_edges = redact(text, findings)
    whole = redact(text, findings, FULL)

    assert whole.chars_removed == len(secret)
    assert kept_edges.chars_removed == len(secret) - 8
    assert kept_edges.chars_kept == len(text) - len(secret) + 8
    assert kept_edges.chars_removed + kept_edges.chars_kept == len(text)


def test_suffix_alone_reads_sensibly(detector: Detector) -> None:
    secret = "wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u"
    text = f"AWS_SECRET_ACCESS_KEY={secret}"

    result = redact(text, detector.scan(text), RedactionStyle(keep_prefix=0, keep_suffix=4))
    assert result.text == f"AWS_SECRET_ACCESS_KEY=[REDACTED]…{secret[-4:]}"


# --- the safety floor -----------------------------------------------------
#
# keep_prefix/keep_suffix are configured once, against no particular value,
# while the values range from a 4-character PIN to a 3 KB private key. A fixed
# count honoured literally is what strips the short ones bare.


def test_a_secret_too_short_to_spare_any_characters_reveals_none() -> None:
    for secret in ("abc", "abcd", "hunter2"[:4]):
        assert _edges(secret, RedactionStyle()) == ("", "")


def test_never_reveals_more_than_half_nor_leaves_less_than_the_floor() -> None:
    style = RedactionStyle()
    for length in range(1, 80):
        secret = "x" * length
        prefix, suffix = _edges(secret, style)
        revealed = len(prefix) + len(suffix)
        assert revealed <= length // 2, f"more than half revealed at {length}"
        assert revealed == 0 or length - revealed >= MIN_HIDDEN_CHARS, (
            f"fewer than {MIN_HIDDEN_CHARS} characters hidden at {length}"
        )


def test_an_absurd_request_is_clamped_rather_than_honoured() -> None:
    """`keep_prefix = 100` must not print a 12-character secret."""
    secret = "abcdefghijkl"
    prefix, suffix = _edges(secret, RedactionStyle(keep_prefix=100, keep_suffix=100))

    assert len(prefix) + len(suffix) <= len(secret) // 2
    assert secret not in prefix + suffix


def test_the_head_is_served_first_when_the_budget_cannot_cover_both() -> None:
    """The head carries the key type, which is the half that says what went."""
    prefix, suffix = _edges("abcdefghij", RedactionStyle(keep_prefix=4, keep_suffix=4))
    assert prefix == "abcd"
    assert len(suffix) < 4


def test_edges_can_be_turned_off_entirely(detector: Detector) -> None:
    """Config sets both to 0 to replace the whole value, and must get it."""
    text = "GITHUB_TOKEN=ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"

    assert redact(text, detector.scan(text), FULL).text == "GITHUB_TOKEN=[REDACTED]"


def test_kept_edges_do_not_make_the_output_any_dirtier_on_rescan(
    detector: Detector,
) -> None:
    """The surviving fragments must not trip a detector that full redaction did not.

    Deliberately a comparison against full redaction rather than an assertion
    that the output rescans clean, because it does not: the URL-password rules
    match any `user:<something>@host`, and "[REDACTED]" satisfies that as well
    as a real password does. That predates kept edges and is unchanged by them
    -- what this pins is that keeping a head and a tail introduces no *new*
    detection, which is the part this feature could plausibly have broken.
    """
    for text in (
        "GITHUB_TOKEN=ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z",
        "AWS_SECRET_ACCESS_KEY=wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u",
        "DATABASE_URL=postgres://svc_user:h1ghlyS3cretPw@db.internal:5432/prod",
        "SLACK_TOKEN=xoxb-8237456190-8123456789012-Kj83hDbQmZpLxNc9RstV",
    ):
        findings = detector.scan(text)
        with_edges = redact(text, findings)
        whole = redact(text, findings, FULL)
        assert with_edges.changed

        after_edges = {f.rule_id for f in detector.scan(with_edges.text)}
        after_whole = {f.rule_id for f in detector.scan(whole.text)}
        assert after_edges <= after_whole, (
            f"kept edges added {after_edges - after_whole} on {text!r}"
        )

        # And in particular, no token rule fires on the fragments themselves.
        assert "generic-api-key" not in after_edges
