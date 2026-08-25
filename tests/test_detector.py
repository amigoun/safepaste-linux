"""Tests for safepaste.detector.engine: the Detector pipeline."""

from __future__ import annotations

import pytest

from safepaste.detector import Detector, Finding, merge_spans, summarise, value_hash
from safepaste.detector.rules import RuleSet

# ---------------------------------------------------------------------------
# True positives: one representative case per rule family.
#
# Fixtures here are invented, high-entropy fakes rather than the textbook
# gitleaks examples (e.g. AKIAIOSFODNN7EXAMPLE) — those are *correctly*
# rejected by the vendored aws-access-token allowlist (`.+EXAMPLE$`) and by
# generic-api-key's stopword list, so using them would be testing the
# allowlist, not the detector.
# ---------------------------------------------------------------------------

TRUE_POSITIVES = [
    pytest.param(
        "AWS_ACCESS_KEY_ID=AKIA3XQZ7NBVCD4KLM2P",
        "aws-access-token",
        "AKIA3XQZ7NBVCD4KLM2P",
        id="aws-access-key-id",
    ),
    pytest.param(
        "AWS_SECRET_ACCESS_KEY=wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u",
        "generic-api-key",
        "wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u",
        id="aws-secret-via-generic-api-key",
    ),
    pytest.param(
        "GITHUB_TOKEN=ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z",
        "github-pat",
        "ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z",
        id="github-pat",
    ),
    pytest.param(
        "GITLAB_TOKEN=glpat-9fK3mN7pQ2rS5tU8vW1x",
        "gitlab-pat",
        "glpat-9fK3mN7pQ2rS5tU8vW1x",
        id="gitlab-pat",
    ),
    pytest.param(
        "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJhbGV4ZWkiLCJvcmciOiJveC1zZWN1cml0eSIsImlhdCI6MTcwMDAwMDAwMH0."
        "YT83m2Kx9Lp_QzRt4VbNc7HsW1oXeJd5fGqA8uT6iM",
        "jwt",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJhbGV4ZWkiLCJvcmciOiJveC1zZWN1cml0eSIsImlhdCI6MTcwMDAwMDAwMH0."
        "YT83m2Kx9Lp_QzRt4VbNc7HsW1oXeJd5fGqA8uT6iM",
        id="jwt",
    ),
    pytest.param(
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpQIBAAKCAQEAv3Hs9YbKq2Nx7RtLpMz4WgVj8DcFo1SaXeUh6TnBk0IrPq5C\n"
        "Zt2Lm9OxWv4RbJd7HqYn1EsUo6VgKp3TfCz8Xa5MiNw0DjRlBu2GhYt6PkQe9Vc4\n"
        "-----END RSA PRIVATE KEY-----",
        "private-key",
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpQIBAAKCAQEAv3Hs9YbKq2Nx7RtLpMz4WgVj8DcFo1SaXeUh6TnBk0IrPq5C\n"
        "Zt2Lm9OxWv4RbJd7HqYn1EsUo6VgKp3TfCz8Xa5MiNw0DjRlBu2GhYt6PkQe9Vc4\n"
        "-----END RSA PRIVATE KEY-----",
        id="pem-private-key-block",
    ),
    pytest.param(
        "SLACK_TOKEN=xoxb-8237456190-8123456789012-Kj83hDbQmZpLxNc9RstV",
        "slack-bot-token",
        "xoxb-8237456190-8123456789012-Kj83hDbQmZpLxNc9RstV",
        id="slack-bot-token",
    ),
    pytest.param(
        "DATABASE_URL=postgres://svc_user:h1ghlyS3cretPw@db.internal:5432/prod",
        "safepaste-database-url-password",
        "h1ghlyS3cretPw",
        id="database-url-password",
    ),
    pytest.param(
        "Authorization: Bearer aZ9xQ2wE7rT4yU6iO1pL3kJ8hG5fD0sA",
        "safepaste-authorization-bearer",
        "aZ9xQ2wE7rT4yU6iO1pL3kJ8hG5fD0sA",
        id="authorization-bearer-header",
    ),
    pytest.param(
        "machine api.example.com login svc_deploy password Tr0ub4dourAndeeper99",
        "safepaste-netrc-password",
        "Tr0ub4dourAndeeper99",
        id="netrc-password",
    ),
    pytest.param(
        # A tilde in the body. 0.5.0 shipped with a base64url character class and
        # was therefore silently quiet on a real key shaped like this one.
        "ox_Kj83hDbQmZpLxNc9Rst~1uW4yA7zE2qXbT9m",
        "safepaste-ox-api-key",
        "ox_Kj83hDbQmZpLxNc9Rst~1uW4yA7zE2qXbT9m",
        id="ox-api-key-with-a-tilde",
    ),
    pytest.param(
        # Bare, with no `KEY=` around it -- which is how one of these arrives
        # in a chat window, and what nothing in the vendored set catches.
        "ox_Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT9-",
        "safepaste-ox-api-key",
        "ox_Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT9-",
        id="ox-api-key-bare-paste",
    ),
    pytest.param(
        "export DB_PASSWORD=Kx92mQzR7v",
        "safepaste-env-password-assignment",
        "Kx92mQzR7v",
        id="env-password-assignment",
    ),
]


@pytest.mark.parametrize(("text", "rule_id", "secret"), TRUE_POSITIVES)
def test_true_positive_families(
    detector: Detector, text: str, rule_id: str, secret: str
) -> None:
    findings = detector.scan(text)
    matching = [f for f in findings if f.rule_id == rule_id]
    assert matching, (
        f"expected rule {rule_id!r} to fire on {text!r}; "
        f"got rule_ids={[f.rule_id for f in findings]}"
    )
    # The offset assertion is the point of this test: start/end must bound
    # exactly the secret we planted, nothing more and nothing less.
    assert text[matching[0].start : matching[0].end] == secret


# ---------------------------------------------------------------------------
# False positives: this corpus must produce exactly zero findings.
# ---------------------------------------------------------------------------

FALSE_POSITIVES = [
    pytest.param('const token = "hello-world";', id="js-const-hello-world"),
    pytest.param(
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod "
        "tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim "
        "veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea "
        "commodo consequat.",
        id="lorem-ipsum-paragraph",
    ),
    pytest.param("3f29b8a0-9c1d-4e5a-8b7f-2d6c1a9e4f3b", id="bare-uuid"),
    pytest.param("a1b2c3d", id="git-sha-short-7-hex"),
    pytest.param("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678", id="git-sha-long-40-hex"),
    pytest.param("API_KEY=${MY_API_KEY}", id="env-var-reference"),
    pytest.param("password=changeme", id="placeholder-password"),
    pytest.param("token: $TOKEN", id="shell-style-var-reference"),
    pytest.param("PASSWORD=true", id="boolean-looking-value"),
    pytest.param(
        "Requires v1.2.3, v2.0.0-beta.1, v10.4.12, and v0.9.0-rc.2 or later.",
        id="semver-list",
    ),
    pytest.param(
        "Log window: 2026-08-01T00:00:00Z to 2026-08-02T12:30:45Z, "
        "next run 2026-08-03T06:15:00Z.",
        id="iso-timestamp-list",
    ),
    pytest.param(
        "ox_runtime_policy_shadow_flags_override", id="ox-snake-case-name"
    ),
    pytest.param(
        "ox_runtime.policy.shadow.flags.override", id="ox-dotted-name"
    ),
    pytest.param("ox_a3f9c1e07b52d84f6a0c9d3e1b7f2a48d5e6", id="ox-hex-digest"),
]


@pytest.mark.parametrize("text", FALSE_POSITIVES)
def test_false_positive_corpus_yields_no_findings(detector: Detector, text: str) -> None:
    findings = detector.scan(text)
    assert findings == [], (
        f"expected no findings for {text!r}, got "
        f"{[(f.rule_id, text[f.start:f.end]) for f in findings]}"
    )


# ---------------------------------------------------------------------------
# OX API keys: the shape questions the two corpora above cannot express.
# ---------------------------------------------------------------------------

# The one accepted length, differing only in the last character. The hyphen is
# the one that matters: `-` is not a word character, so an earlier draft ending
# the pattern in `\b` could not match a body that ended with one -- the engine
# hunted for a boundary, could not find one and quietly gave up. It cost 7 keys
# in 2000 random ones.
OX_BODIES = [
    "Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT9m",
    "Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT9-",
    "Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT9_",
    "Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT99",
]


@pytest.mark.parametrize("body", OX_BODIES)
def test_ox_api_key_is_found_whatever_the_body_ends_with(
    detector: Detector, body: str
) -> None:
    text = f"ox_{body}"
    spans = [
        text[f.start : f.end] for f in detector.scan(text)
        if f.rule_id == "safepaste-ox-api-key"
    ]
    assert spans == [text], f"body ending {body[-1]!r} was not matched whole"


@pytest.mark.parametrize(
    "text",
    [
        "here it is: ox_Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT9-, do not share",
        '{"apiKey": "ox_Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT9-"}',
        "https://api.example.test/v1?key=ox_Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT9-&page=2",
        # A sentence ending in the key. This is why the delimiter class omits `.`
        # while the body accepts it: with `.` in both, the exact {36} leaves the
        # engine no way to hand the full stop back, and the key goes undetected.
        "the key is ox_Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT9-.",
    ],
)
def test_ox_api_key_span_excludes_whatever_delimits_it(
    detector: Detector, text: str
) -> None:
    """The trailing delimiter is consumed by the match but must stay out of the
    secret, or redaction would eat the comma, the quote or the `&`."""
    key = "ox_Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT9-"
    found = [f for f in detector.scan(text) if f.rule_id == "safepaste-ox-api-key"]
    assert found, f"no OX key found in {text!r}"
    assert text[found[0].start : found[0].end] == key


@pytest.mark.parametrize("char", ["-", ".", "_", "~"])
def test_ox_api_key_takes_the_whole_unreserved_set_inside_the_body(
    detector: Detector, char: str
) -> None:
    """`- . _ ~` are all RFC 3986 unreserved characters, and keys use them.

    0.5.0 accepted only `[A-Za-z0-9_-]`, so a key carrying a tilde matched nothing
    -- found by copying a real one, not by a test, which is why all four are pinned
    here now.
    """
    text = "ox_Kj83hDbQmZpLxNc9Rst" + char + "1uW4yA7zE2qXbT9m"
    assert len(text) - 3 == 36, "fixture must be exactly one body length"
    spans = [
        text[f.start : f.end]
        for f in detector.scan(text)
        if f.rule_id == "safepaste-ox-api-key"
    ]
    assert spans == [text], f"a body containing {char!r} was not matched whole"


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("box_Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT9m", "another vendor's prefix ends in ox_"),
        ("my_ox_Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT9m", "mid-identifier, not a key"),
        ("ox_Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT9", "35 characters: one short"),
        ("ox_Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT9mn", "37 characters: one long"),
        ("ox_" + "a" * 36, "no entropy at all"),
    ],
)
def test_ox_api_key_does_not_fire_on_lookalikes(
    detector: Detector, text: str, why: str
) -> None:
    fired = [f for f in detector.scan(text) if f.rule_id == "safepaste-ox-api-key"]
    assert not fired, f"fired on {text!r} ({why})"


def test_ox_api_key_label_reads_as_a_name(detector: Detector) -> None:
    """What the dialog shows. `humanise` would say "Ox api key" unaided."""
    text = "ox_Kj83hDbQmZpLxNc9RstV1uW4yA7zE2qXbT9m"
    finding = next(f for f in detector.scan(text) if f.rule_id == "safepaste-ox-api-key")
    assert finding.label == "OX API key"
    assert finding.category == "api_keys"


# ---------------------------------------------------------------------------
# Value-only spans
# ---------------------------------------------------------------------------


def test_value_only_span_excludes_the_env_var_prefix(detector: Detector) -> None:
    prefix = "AWS_SECRET_ACCESS_KEY="
    secret = "wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u"
    text = prefix + secret
    findings = detector.scan(text)
    f = next(f for f in findings if f.rule_id == "generic-api-key")
    assert text[f.start : f.end] == secret
    assert prefix not in text[f.start : f.end]
    assert f.start == len(prefix)


# ---------------------------------------------------------------------------
# categories restricts active_rules and results
# ---------------------------------------------------------------------------


def test_categories_restricts_active_rules_and_results(ruleset: RuleSet) -> None:
    d = Detector(ruleset=ruleset, categories=frozenset({"connection_strings"}))
    assert d.active_rules
    assert all(r.category == "connection_strings" for r in d.active_rules)

    # An AWS key id (category 'tokens') must not surface...
    assert d.scan("AWS_ACCESS_KEY_ID=AKIA3XQZ7NBVCD4KLM2P") == []

    # ...but a database URL password (connection_strings) still does.
    findings = d.scan(
        "DATABASE_URL=postgres://svc_user:h1ghlyS3cretPw@db.internal:5432/prod"
    )
    assert "safepaste-database-url-password" in {f.rule_id for f in findings}


# ---------------------------------------------------------------------------
# excluded_hashes suppresses exactly that secret
# ---------------------------------------------------------------------------


def test_excluded_hashes_suppresses_only_the_named_secret(ruleset: RuleSet) -> None:
    secret = "wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u"
    text = f"AWS_SECRET_ACCESS_KEY={secret}"

    d_plain = Detector(ruleset=ruleset)
    assert d_plain.scan(text), "sanity check: detected without any exclusion"

    key = bytes(range(32))
    d_excluded = Detector(
        ruleset=ruleset,
        excluded_hashes=frozenset({value_hash(secret, key)}),
        exclusion_key=key,
    )
    assert d_excluded.scan(text) == []

    # An unrelated secret is not caught up in the exclusion.
    other_text = "GITHUB_TOKEN=ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
    assert d_excluded.scan(other_text)


# ---------------------------------------------------------------------------
# max_scan_bytes truncates on a character boundary
# ---------------------------------------------------------------------------


def test_max_scan_bytes_truncates_before_but_not_after(ruleset: RuleSet) -> None:
    cap = 200
    secret = "AKIA3XQZ7NBVCD4KLM2P"  # 20 chars
    d = Detector(ruleset=ruleset, max_scan_bytes=cap)

    # Secret ends at offset 190, safely inside the 200-byte cap; the text
    # continues well past the cap so real truncation still happens. Spaces
    # (not more filler word-chars) must flank the secret so the rule's `\b`
    # word boundaries still land where a real paste would put them.
    before_text = ("x" * 169) + " " + secret + " " + ("y" * 299)
    findings_before = d.scan(before_text)
    assert any(f.rule_id == "aws-access-token" for f in findings_before)
    hit = next(f for f in findings_before if f.rule_id == "aws-access-token")
    assert before_text[hit.start : hit.end] == secret

    # Secret starts at offset 201, after the cap, so it is cut away entirely.
    after_text = ("x" * cap) + " " + secret + " " + ("y" * 50)
    assert d.scan(after_text) == []


# ---------------------------------------------------------------------------
# safepaste-high-entropy-string: off by default, opt-in via categories
# ---------------------------------------------------------------------------


def test_high_entropy_rule_is_disabled_by_default(ruleset: RuleSet) -> None:
    d = Detector(ruleset=ruleset)
    assert "safepaste-high-entropy-string" not in {r.id for r in d.active_rules}


def test_high_entropy_rule_activates_when_category_is_requested(
    ruleset: RuleSet,
) -> None:
    d = Detector(ruleset=ruleset, categories=frozenset({"high_entropy"}))
    assert "safepaste-high-entropy-string" in {r.id for r in d.active_rules}

    # And it must actually fire end-to-end, not just appear in the rule list.
    candidate = "Zm8k92QpXr7NvLc4WseYt6BgUo1DaHi3JlKq5RtNwXz8VbCm2FpQr9Ts"
    findings = d.scan(f"blob: {candidate} end")
    assert any(f.rule_id == "safepaste-high-entropy-string" for f in findings)


# ---------------------------------------------------------------------------
# merge_spans()
# ---------------------------------------------------------------------------


def _finding(
    start: int, end: int, rule_id: str = "r", label: str = "L", category: str = "api_keys"
) -> Finding:
    """A minimal Finding for exercising span math, with dummy metadata."""
    return Finding(
        rule_id=rule_id,
        label=label,
        category=category,
        start=start,
        end=end,
        match_start=start,
        match_end=end,
    )


def test_merge_spans_empty_list() -> None:
    assert merge_spans([]) == []


def test_merge_spans_disjoint_kept_separate() -> None:
    spans = merge_spans([_finding(0, 5), _finding(50, 55)])
    assert spans == [(0, 5), (50, 55)]


def test_merge_spans_overlapping_unioned() -> None:
    spans = merge_spans([_finding(10, 20), _finding(15, 25)])
    assert spans == [(10, 25)]


def test_merge_spans_identical_collapsed() -> None:
    spans = merge_spans([_finding(30, 40, rule_id="a"), _finding(30, 40, rule_id="b")])
    assert spans == [(30, 40)]


def test_merge_spans_adjacent_but_not_overlapping_not_merged() -> None:
    # A real (if narrow) gap between the spans: index 5 belongs to neither,
    # so unlike the overlapping case above these must stay two spans.
    spans = merge_spans([_finding(0, 5), _finding(6, 10)])
    assert spans == [(0, 5), (6, 10)]


# ---------------------------------------------------------------------------
# summarise()
# ---------------------------------------------------------------------------


def test_summarise_counts_merged_spans_not_raw_findings(detector: Detector) -> None:
    # A Datadog-shaped value matches both datadog-access-token and
    # generic-api-key on the exact same span.
    text = "DATADOG_API_KEY=4f9b2ac7e1d3805f6b2e9c4a7d1f0836ac52e9d4"
    findings = detector.scan(text)
    assert {f.rule_id for f in findings} == {"datadog-access-token", "generic-api-key"}

    summary = summarise(findings)
    assert summary["findings"] == 2
    assert summary["secrets"] == 1
    assert summary["labels"] == ["Datadog access token", "Generic API key"]


def test_summarise_labels_are_deduped_and_order_preserving(detector: Detector) -> None:
    # Two separate secrets, in a known left-to-right order. The slack value
    # is itself double-owned (slack-bot-token + generic-api-key), so this
    # also confirms dedup does not drop a distinct later label.
    text = (
        "SLACK_TOKEN=xoxb-8237456190-8123456789012-Kj83hDbQmZpLxNc9RstV "
        "AWS_ACCESS_KEY_ID=AKIA3XQZ7NBVCD4KLM2P"
    )
    findings = detector.scan(text)
    summary = summarise(findings)
    assert summary["secrets"] == 2
    assert summary["labels"] == ["Generic API key", "Slack bot token", "AWS access token"]
    assert len(summary["labels"]) == len(set(summary["labels"]))  # no duplicates
