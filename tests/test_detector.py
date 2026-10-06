"""Tests for safepaste.detector.engine: the Detector pipeline."""

from __future__ import annotations

import pytest

import random

import regex

from safepaste.detector import (
    Detector,
    Finding,
    ScanResult,
    merge_spans,
    summarise,
    value_hash,
)
from safepaste.detector.rules import Rule, RuleSet

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
# Password assignments in the shapes they are actually written
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "password"),
    [
        ("DB_PASSWORD=Zq8v#R2kLmN4pT7w", "Zq8v#R2kLmN4pT7w"),
        ("db_password: 'Zq8v#R2kLmN4pT7w'", "Zq8v#R2kLmN4pT7w"),
        ('{"username": "svc", "password": "Zq8v!R2k$LmN4pT7w"}', "Zq8v!R2k$LmN4pT7w"),
        ('  "Password": "Zq8v!R2k$LmN4pT7w",', "Zq8v!R2k$LmN4pT7w"),
        (
            'export DB_PASSWORD="correct horse battery staple"',
            "correct horse battery staple",
        ),
        ("DB_PASSWORD=Kx92mQzR7v  # rotated monthly", "Kx92mQzR7v"),
        ('connect(user="svc", password="Zq8v!R2k$LmN4pT7w")', "Zq8v!R2k$LmN4pT7w"),
    ],
    ids=["hash-unquoted", "hash-single-quoted", "json-inline", "json-indented",
         "spaces-quoted", "trailing-comment", "keyword-argument"],
)
def test_a_password_assignment_is_found_whole(
    detector: Detector, text: str, password: str
) -> None:
    found = [
        text[f.start : f.end]
        for f in detector.scan(text)
        if f.rule_id == "safepaste-env-password-assignment"
    ]
    assert found == [password]


@pytest.mark.parametrize(
    "text",
    [
        "password: ${DB_PASSWORD}",
        'password: "${DB_PASSWORD}"',
        "password: ${DB_PASSWORD:-postgres}",
        'DB_PASSWORD="$(cat /run/secrets/db)"',
        'password = os.environ["DB_PASSWORD"]',
        'password: "{{ .Values.db.password }}"',
        '"password": "string"',
        "password: <your-password>",
        "password_reset_url=/account/reset",
        "Your password: must be 8+ characters",
    ],
)
def test_a_reference_or_placeholder_password_is_not_flagged(
    detector: Detector, text: str
) -> None:
    assert detector.scan(text) == []


@pytest.mark.parametrize(
    "text",
    [
        "client.login(username=username, password=password)",
        "connect(host, password=cfg.db_password)",
        "connect(host, secret=False)",
        '{"password": 123456789},',
    ],
)
def test_code_that_passes_a_password_along_is_not_flagged(
    detector: Detector, text: str
) -> None:
    assert detector.scan(text) == []


# ---------------------------------------------------------------------------
# Placeholders are whole words, not prefixes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "password",
    ["Football2024", "Barcelona1992", "Testarossa88", "Enterprise2024Prod"],
)
def test_a_password_that_starts_like_a_placeholder_is_found(
    detector: Detector, password: str
) -> None:
    text = f"DB_PASSWORD={password}"
    assert password in [text[f.start : f.end] for f in detector.scan(text)]


@pytest.mark.parametrize(
    "value",
    [
        "changeme", "foo", "foobar", "test", "testing", "example_key",
        "your_api_key", "yourApiKey", "<enter-token-here>",
        "enter_your_token_here", "paste-your-api-key", "dummy_password",
        "sample-secret-value", "mock_api_key", "test_token", "lorem_ipsum",
        "placeholder_token", "xxx_api_key",
    ],
)
def test_a_placeholder_value_is_not_flagged(detector: Detector, value: str) -> None:
    assert detector.scan(f"DB_PASSWORD={value}") == []


@pytest.mark.parametrize(
    "text",
    [
        "password = MyPassword123",
        "DB_PASSWORD=mysecret2024",
        "password: TheToken99",
        "DB_PASSWORD=test123",
        "DB_PASSWORD=example_key1",
        "DB_PASSWORD=testkey",
        "DB_PASSWORD=mockingbird",
    ],
)
def test_a_weak_password_made_of_ordinary_words_is_found(
    detector: Detector, text: str
) -> None:
    """`my`, `the` and a number are how real weak passwords are made, not how
    placeholders are marked."""
    value = text.split("=", 1)[-1].split(":", 1)[-1].strip()
    assert value in [text[f.start : f.end] for f in detector.scan(text)]


# ---------------------------------------------------------------------------
# UUID-shaped vendor keys: noise to the catch-all rules, the format to these
# ---------------------------------------------------------------------------

_UUID = "3f6b2c1e-8d4a-4f7b-9c2e-1a5d7e9b0c4f"


@pytest.mark.parametrize(
    ("name", "rule_id"),
    [
        ("HEROKU_API_KEY", "heroku-api-key"),
        ("HUBSPOT_API_KEY", "hubspot-api-key"),
        ("KUCOIN_SECRET_KEY", "kucoin-secret-key"),
        ("MESSAGEBIRD_CLIENT_ID", "messagebird-client-id"),
        ("SENDBIRD_APP_ID", "sendbird-access-id"),
        ("SNYK_TOKEN", "snyk-api-token"),
        ("SQUARESPACE_ACCESS_TOKEN", "squarespace-access-token"),
    ],
)
def test_a_uuid_shaped_vendor_key_is_found(
    detector: Detector, name: str, rule_id: str
) -> None:
    text = f"{name}={_UUID}"
    found = [f for f in detector.scan(text) if f.rule_id == rule_id]
    assert [text[f.start : f.end] for f in found] == [_UUID]


@pytest.mark.parametrize(
    "text",
    [f"idempotency_key={_UUID}", f"trace token={_UUID}", "api_key=a1b2c3d4"],
)
def test_a_uuid_or_short_sha_under_a_generic_name_is_still_not_flagged(
    detector: Detector, text: str
) -> None:
    assert detector.scan(text) == []


# ---------------------------------------------------------------------------
# Kubernetes Secret manifests: every value, not the first
# ---------------------------------------------------------------------------

_SECRET_VALUES = [
    "c3ZjX2FwcF9wcm9k",
    "cG9zdGdyZXM6Ly9zdmM6WnE4dlIya0xtTjRwVDd3QGRiOjU0MzIvcHJvZA==",
    "c2tfbGl2ZV81MUhxOHZSMmtMbU40cFQ3d1hiWTljRTFmRzNoSjVrUTBy",
]
_SECRET_DATA = (
    "data:\n"
    f"  username: {_SECRET_VALUES[0]}\n"
    f"  DATABASE_URL: {_SECRET_VALUES[1]}\n"
    f"  stripe: {_SECRET_VALUES[2]}\n"
)


def _k8s_values(detector: Detector, text: str) -> list[str]:
    return [
        text[f.start : f.end]
        for f in detector.scan(text)
        if f.rule_id == "kubernetes-secret-yaml"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app-creds\n"
        "type: Opaque\n" + _SECRET_DATA,
        # `kubectl get -o yaml` sorts keys, which puts data above kind.
        "apiVersion: v1\n" + _SECRET_DATA + "kind: Secret\nmetadata:\n"
        "  name: app-creds\ntype: Opaque\n",
    ],
    ids=["kind-first", "kubectl-order"],
)
def test_every_value_of_a_secret_manifest_is_found(
    detector: Detector, text: str
) -> None:
    assert _k8s_values(detector, text) == _SECRET_VALUES


def test_string_data_values_are_found_and_templates_are_not(
    detector: Detector,
) -> None:
    text = (
        "kind: Secret\n"
        "stringData:\n"
        '  password: "Zq8v!R2k$LmN4pT7w"  # rotated monthly\n'
        "  template: {{ .Values.password | b64enc }}\n"
        "  empty: \"\"\n"
        "  last: Zq8vR2kLmN4pT7wX\n"
    )
    assert _k8s_values(detector, text) == ["Zq8v!R2k$LmN4pT7w", "Zq8vR2kLmN4pT7wX"]


@pytest.mark.parametrize(
    "text",
    [
        "kind: ConfigMap\n" + _SECRET_DATA,
        "kind: Secret\nmetadata:\n  name: a\n---\nkind: ConfigMap\n" + _SECRET_DATA,
        "kind: SecretProviderClass\n" + _SECRET_DATA,
    ],
    ids=["configmap", "secret-in-another-document", "lookalike-kind"],
)
def test_data_outside_a_secret_is_not_flagged(detector: Detector, text: str) -> None:
    assert _k8s_values(detector, text) == []


def test_every_capture_of_a_repeated_secret_group_is_a_finding() -> None:
    rule = Rule(
        id="test-list",
        description="a list of values",
        pattern=regex.compile(r"keys:(?:\s+([A-Za-z0-9]{8,}))+"),
        keywords=(),
        category="api_keys",
    )
    text = "keys: Zq8vR2kL N4pT7wXb Y9cE1fG3"

    found = Detector(ruleset=RuleSet(rules=[rule])).scan(text)

    assert [text[f.start : f.end] for f in found] == ["Zq8vR2kL", "N4pT7wXb", "Y9cE1fG3"]


# ---------------------------------------------------------------------------
# kubeconfig tokens anywhere in the file
# ---------------------------------------------------------------------------

_EKS_TOKEN = (
    "k8s-aws-v1.aHR0cHM6Ly9zdHMudXMtZWFzdC0xLmFtYXpvbmF3cy5jb20vP0FjdGlvbj1H"
    "ZXRDYWxsZXJJZGVudGl0eSZWZXJzaW9uPTIwMTEtMDYtMTUmWC1BbXotQWxnb3JpdGhtPUFX"
    "UzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BU0lBM1haUTdOQlZDRDRLTE0yUA"
)


@pytest.mark.parametrize(
    "text",
    [
        "apiVersion: v1\nkind: Config\nusers:\n- name: eks-admin\n  user:\n"
        f"    token: {_EKS_TOKEN}\n",
        f"    token: {_EKS_TOKEN}",
    ],
    ids=["whole-kubeconfig", "token-line-alone"],
)
def test_a_kubeconfig_token_is_found_on_any_line(detector: Detector, text: str) -> None:
    found = [f for f in detector.scan(text) if f.rule_id == "safepaste-kubeconfig-token"]
    assert [text[f.start : f.end] for f in found] == [_EKS_TOKEN]


# ---------------------------------------------------------------------------
# Passwords inside URLs
# ---------------------------------------------------------------------------

URL_PASSWORDS = [
    pytest.param(
        "mysql://admin:Zq8v@R2kLmN4pT7w@db.internal:3306/app",
        "Zq8v@R2kLmN4pT7w",
        id="at-sign-in-password",
    ),
    pytest.param(
        "redis://:Zq8vR2kLmN4pT7wXbY9c@cache.internal:6379/0",
        "Zq8vR2kLmN4pT7wXbY9c",
        id="no-username",
    ),
    pytest.param(
        "postgres://svc:Zq8vR2kL/N4pT7wXb+Y9c@db.internal:5432/prod",
        "Zq8vR2kL/N4pT7wXb+Y9c",
        id="slash-in-password",
    ),
    pytest.param(
        "mongodb://admin:P@ssw0rd!2024x@db.internal:27017/app",
        "P@ssw0rd!2024x",
        id="at-sign-and-bang",
    ),
    pytest.param(
        "https://deploy:Zq8v@R2kLmN4pT7w@registry.example.test/v2/",
        "Zq8v@R2kLmN4pT7w",
        id="generic-scheme",
    ),
]


@pytest.mark.parametrize(("text", "password"), URL_PASSWORDS)
def test_a_url_password_is_found_whole(
    detector: Detector, text: str, password: str
) -> None:
    """Up to the last `@` before the host: stopping at the first one printed
    the rest of the password as though it were the hostname."""
    spans = {text[f.start : f.end] for f in detector.scan(text)}
    assert spans == {password}


@pytest.mark.parametrize(
    "text",
    [
        "https://user@host.example.test/path",
        "git@github.com:org/repo.git",
        "ssh://git@github.com:22/org/repo.git",
        "https://example.test:8443/users/@alice",
        "postgres://db.internal:5432/app?user=svc@corp",
        "redis://cache.internal:6379/0",
        "https://example.test/a:b@c",
    ],
)
def test_a_url_without_a_password_is_not_flagged(
    detector: Detector, text: str
) -> None:
    assert detector.scan(text) == []


def test_an_at_sign_in_the_path_does_not_extend_a_url_password(
    detector: Detector,
) -> None:
    """An `@` belongs to the password only when another follows before the
    path; npm scopes and profile URLs put one after the host."""
    text = "https://alice:s3cretPassw0rd@registry.example.com/@scope/pkg"
    assert [text[f.start : f.end] for f in detector.scan(text)] == ["s3cretPassw0rd"]
    assert detector.scan("https://medium.com/@user/post") == []


@pytest.mark.parametrize(
    "text",
    [
        "x://a:" + "@" * 5000,
        "postgres://a:" + "@" * 5000,
        "x://a:" + "b" * 50_000,
        "postgres://a:" + "b" * 50_000,
        "x://a:" + "b@" * 5000 + "/",
    ],
    ids=["at-run", "db-at-run", "no-at", "db-no-at", "at-chain-then-slash"],
)
def test_a_url_password_rule_does_not_backtrack_badly(text: str) -> None:
    from safepaste.detector import load_default

    found = Detector(load_default(), regex_timeout=0.25).scan(text)
    assert not found.skipped_rules


# ---------------------------------------------------------------------------
# PEM private keys beside other PEM blocks, and cut short
# ---------------------------------------------------------------------------

_KEY_BODY = (
    "IpHYzcMQQR5+wnN4pmHJNRh8B+TVY26bw8QAsnJEuM06l/Ea5lEHBQamigLw4WGv\n"
    "N/hsuQeHOMNw8H6NO1g7rTjCdfNK7QVq1uqO7KQZL6H+udxLHr5V5bj5toDv92yB\n"
    "1OmrME1Ilvnhf9jwgWSW2gh6Pr7MZ2qqLF2M4bPGrLxfFnCpghvHKYXXZF59uwd4\n"
    "6VH4mfh0HEA3yJ7H+uSK3rB4qVtCLoo1\n"
)
_REAL_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n" + _KEY_BODY + "-----END RSA PRIVATE KEY-----"
)


@pytest.mark.parametrize(
    "before",
    [
        "-----BEGIN RSA PRIVATE KEY-----\n[REDACTED]\n-----END RSA PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----\n<base64>\n-----END RSA PRIVATE KEY-----",
    ],
    ids=["hand-redacted-key-first", "template-key-first"],
)
def test_a_real_key_after_a_short_pem_block_is_found_on_its_own(
    detector: Detector, before: str
) -> None:
    """A match must not run from one block's BEGIN into the next one.

    It used to, and the result depended on what came first: a hand-redacted
    block made the whole span read as already redacted and nothing was
    reported; a template block made the match end on the real key's BEGIN
    line, so redacting it printed the real key's body.
    """
    text = f"Old key:\n{before}\n\nNew key:\n{_REAL_KEY}\n"

    keys = [f for f in detector.scan(text) if f.rule_id == "private-key"]

    assert [text[f.start : f.end] for f in keys] == [_REAL_KEY]


def test_the_top_of_a_key_copied_without_its_end_line_is_found(
    detector: Detector,
) -> None:
    head = "-----BEGIN RSA PRIVATE KEY-----\n" + _KEY_BODY[:150]
    text = f"here is what I have so far:\n{head}\n\nany idea why it fails?"

    keys = [f for f in detector.scan(text) if f.rule_id == "private-key"]

    assert [text[f.start : f.end] for f in keys] == [head]


def test_the_top_of_an_encrypted_key_is_found_from_its_header(
    detector: Detector,
) -> None:
    head = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "Proc-Type: 4,ENCRYPTED\n"
        "DEK-Info: AES-128-CBC,3F2A9C1E7B5D4F6A8C0E2B4D6F8A0C1E\n"
        "\n" + _KEY_BODY.rstrip("\n")
    )

    keys = [f for f in detector.scan(head) if f.rule_id == "private-key"]

    assert [head[f.start : f.end] for f in keys] == [head]


def test_a_short_pem_block_alone_is_not_a_key(detector: Detector) -> None:
    text = "-----BEGIN PRIVATE KEY-----\n<base64>\n-----END PRIVATE KEY-----\n"

    assert detector.scan(text) == []


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
# Large inputs: scanned in full, and anything left unscanned is said out loud
# ---------------------------------------------------------------------------

_AWS_SECRET = "wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u"


def _config_log(size: int) -> str:
    """Debug output dense with the words generic-api-key keys on.

    Shaped like this because it is what made that rule cost more than its
    timeout over a whole paste: half a megabyte of it was enough.
    """
    rng = random.Random(3)
    names = ["api_key_id", "auth_token_ttl", "secret_ref", "access_key_hint",
             "client_secret_name", "password_policy"]
    values = ["enabled", "default", "none", "rotate-weekly", "v2", "kms-alias"]
    lines: list[str] = []
    total = 0
    while total < size:
        pairs = " ".join(
            f"{rng.choice(names)}={rng.choice(values)}" for _ in range(4)
        )
        line = f"2026-10-06 12:00:00,{rng.randint(0, 999):03d} DEBUG config: {pairs}"
        lines.append(line)
        total += len(line) + 1
    return "\n".join(lines) + "\n"


@pytest.mark.integration
@pytest.mark.parametrize("size", [500_000, 1_000_000], ids=["500KB", "1MB"])
def test_a_secret_at_the_end_of_a_large_log_is_found(
    detector: Detector, size: int
) -> None:
    text = _config_log(size) + f"AWS_SECRET_ACCESS_KEY={_AWS_SECRET}\n"
    assert len(text.encode()) <= detector.max_scan_bytes

    findings = detector.scan(text)

    assert not findings.incomplete, f"skipped: {findings.skipped_rules}"
    assert _AWS_SECRET in [text[f.start : f.end] for f in findings]


@pytest.mark.parametrize("offset", range(57_000, 58_200, 150))
def test_a_key_across_a_window_seam_is_found_once_and_whole(
    detector: Detector, offset: int
) -> None:
    """Windows overlap, so the seam can neither cut a key nor report it twice."""
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + "MIIEpQIBAAKCAQEAv3Hs9YbKq2Nx7RtLpMz4WgVj8DcFo1SaXeUh6TnBk0IrPq5C\n" * 50
        + "-----END RSA PRIVATE KEY-----"
    )
    filler = "the quick brown fox jumps over the lazy dog\n"
    head = (filler * (offset // len(filler) + 1))[:offset]
    text = head + "\n" + pem + "\n" + filler * 2000

    keys = [f for f in detector.scan(text) if f.rule_id == "private-key"]

    assert [text[f.start : f.end] for f in keys] == [pem]


def test_a_match_longer_than_a_window_is_not_cut_at_the_window_edge(
    ruleset: RuleSet,
) -> None:
    rng = random.Random(9)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    blob = "".join(rng.choice(alphabet) for _ in range(100_000))
    text = f"image: {blob}\n"
    d = Detector(ruleset=ruleset, categories=frozenset({"high_entropy"}))

    found = [f for f in d.scan(text) if f.rule_id == "safepaste-high-entropy-string"]

    assert [(f.start, f.end) for f in found] == [(7, 7 + len(blob))]


def test_scan_result_is_a_list_that_says_whether_it_is_complete(
    detector: Detector,
) -> None:
    result = detector.scan("GITHUB_TOKEN=ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z")

    assert isinstance(result, ScanResult) and isinstance(result, list)
    assert result.incomplete is False
    assert result.skipped_rules == ()
    assert result.truncated is False
    assert isinstance(detector.scan(""), ScanResult)


def test_text_past_the_scan_cap_marks_the_result_incomplete(ruleset: RuleSet) -> None:
    d = Detector(ruleset=ruleset, max_scan_bytes=200)

    result = d.scan("x" * 500)

    assert result == []
    assert result.truncated is True
    assert result.incomplete is True


def test_a_rule_over_its_time_budget_is_named_as_skipped() -> None:
    slow = Rule(
        id="test-catastrophic",
        description="nested quantifiers, exponential on a near miss",
        pattern=regex.compile(r"(?:a|a)+$"),
        keywords=(),
        category="api_keys",
    )
    d = Detector(ruleset=RuleSet(rules=[slow]), regex_timeout=0.01)

    result = d.scan("a" * 40 + "!")

    assert result == []
    assert result.skipped_rules == ("test-catastrophic",)
    assert result.incomplete is True


# ---------------------------------------------------------------------------
# The CLI's exit code for an incomplete scan
# ---------------------------------------------------------------------------


def _cli(argv: list[str]) -> int:
    from safepaste import cli

    args = cli._build_parser().parse_args(argv)
    return args.func(args)


def test_scan_exits_2_when_it_found_nothing_but_did_not_scan_everything(
    tmp_path, capsys
) -> None:
    path = tmp_path / "big.txt"
    path.write_text("nothing to see here\n" * 200, encoding="utf-8")

    code = _cli(["scan", "--max-bytes", "1024", str(path)])

    err = capsys.readouterr().err
    assert code == 2
    assert "scan incomplete" in err and "1024 bytes" in err
    assert len(err.strip().splitlines()) == 1


def test_scan_still_exits_1_on_findings_but_warns_when_incomplete(
    tmp_path, capsys
) -> None:
    path = tmp_path / "big.txt"
    path.write_text(
        "GITHUB_TOKEN=ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z\n"
        + "nothing to see here\n" * 200,
        encoding="utf-8",
    )

    code = _cli(["scan", "--max-bytes", "1024", str(path)])

    assert code == 1
    assert "scan incomplete" in capsys.readouterr().err


def test_a_complete_clean_scan_still_exits_0(tmp_path, capsys) -> None:
    path = tmp_path / "small.txt"
    path.write_text("nothing to see here\n", encoding="utf-8")

    assert _cli(["scan", str(path)]) == 0
    assert "incomplete" not in capsys.readouterr().err


def test_redact_warns_when_its_scan_was_incomplete(tmp_path, capsys) -> None:
    path = tmp_path / "big.txt"
    path.write_text("nothing to see here\n" * 200, encoding="utf-8")

    code = _cli(["redact", "--max-bytes", "1024", str(path)])

    assert code == 0
    assert "scan incomplete" in capsys.readouterr().err


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


@pytest.mark.parametrize("length", [129, 200, 600])
def test_high_entropy_rule_takes_a_run_longer_than_128_whole(
    ruleset: RuleSet, length: int
) -> None:
    rng = random.Random(length)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    run = "".join(rng.choice(alphabet) for _ in range(length))
    text = f"blob: {run} end"
    d = Detector(ruleset=ruleset, categories=frozenset({"high_entropy"}))

    found = [f for f in d.scan(text) if f.rule_id == "safepaste-high-entropy-string"]

    assert [text[f.start : f.end] for f in found] == [run]


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


# ---------------------------------------------------------------------------
# Recognising SafePaste's own output
# ---------------------------------------------------------------------------
#
# The suppression is a substring test against the secret span, which is cheap
# and which two things could turn into a silent disaster: a placeholder short
# enough to appear inside real secrets, and a placeholder sitting next to a
# real secret rather than in place of one. Both are pinned below.


def test_a_placeholder_in_the_secret_span_is_not_a_finding(ruleset) -> None:
    detector = Detector(ruleset=ruleset)
    text = "DATABASE_URL=postgres://svc_user:[REDACTED]@db.internal:5432/prod"

    assert detector.scan(text) == []


def test_a_custom_placeholder_is_honoured(ruleset) -> None:
    """Whatever the user set must be recognised, not just the default."""
    text = "DATABASE_URL=postgres://svc_user:<<HIDDEN>>@db.internal:5432/prod"

    assert Detector(ruleset=ruleset, placeholder="<<HIDDEN>>").scan(text) == []
    # ...and the default placeholder does not excuse someone else's marker.
    assert Detector(ruleset=ruleset).scan(text) != []


def test_a_placeholder_beside_a_real_secret_does_not_excuse_it(ruleset) -> None:
    """Checked against the secret span, not the whole line.

    A line that carries one redacted value and one live one must still report
    the live one, or sanitising a file once would blind the scanner to
    everything sharing a line with the result.
    """
    detector = Detector(ruleset=ruleset)
    text = (
        "OLD_TOKEN=[REDACTED]\n"
        "NEW_TOKEN=ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z\n"
    )

    found = detector.scan(text)
    assert found, "the live token must still be reported"
    assert all("[REDACTED]" not in text[f.start : f.end] for f in found)


def test_a_placeholder_too_short_to_be_safe_suppresses_nothing(ruleset, caplog) -> None:
    """A one-character placeholder would match inside almost every secret.

    Suppressing on it would switch detection off and report "no secrets
    found", which is the worst thing a scanner can do. It is refused, loudly.
    """
    import logging

    with caplog.at_level(logging.WARNING):
        detector = Detector(ruleset=ruleset, placeholder="X")

    assert detector._suppress_placeholder is False
    assert "shorter than" in caplog.text

    text = "GITHUB_TOKEN=ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
    assert detector.scan(text), "a short placeholder must not disable detection"


def test_an_empty_placeholder_suppresses_nothing(ruleset) -> None:
    """"" is a substring of every string; honouring it would find nothing."""
    detector = Detector(ruleset=ruleset, placeholder="")

    assert detector._suppress_placeholder is False
    assert detector.scan("GITHUB_TOKEN=ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z")


def test_the_config_default_placeholder_matches_the_detectors() -> None:
    """The literal is written twice, so this is what keeps it honest.

    Config cannot import the detector without dragging rule loading and
    `regex` into every config read, so the default lives in two places. Two
    copies are fine; two *different* copies would mean the shipped default
    redaction is not the one detection knows to ignore.
    """
    from safepaste.config import Config
    from safepaste.detector import DEFAULT_PLACEHOLDER

    assert Config().placeholder == DEFAULT_PLACEHOLDER
