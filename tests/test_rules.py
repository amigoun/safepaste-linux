"""Tests for safepaste.detector.rules: loading, classification, allowlists."""

from __future__ import annotations

import pathlib

import pytest
import regex

from safepaste.detector import CATEGORIES, CATEGORY_LABELS, Detector
from safepaste.detector.rules import (
    Allowlist,
    RuleSet,
    classify,
    humanise,
    load_default,
    translate_re2,
)

# --- loaded ruleset shape --------------------------------------------------


def test_every_rule_has_a_compiled_pattern_and_a_nonempty_id(ruleset: RuleSet) -> None:
    assert ruleset.rules, "expected the vendored + extra rule files to load something"
    for rule in ruleset.rules:
        assert rule.id
        assert isinstance(rule.pattern, regex.Pattern)


def test_every_rule_category_is_known(ruleset: RuleSet) -> None:
    for rule in ruleset.rules:
        assert rule.category in CATEGORIES
        assert rule.category in CATEGORY_LABELS


def test_pkcs12_file_is_skipped_not_loaded_as_a_rule(ruleset: RuleSet) -> None:
    # Path-only rules cannot apply to clipboard text: there is no filename to
    # match against, so load_file() records why and drops them rather than
    # keeping a rule that can never fire.
    assert any(rule_id == "pkcs12-file" for rule_id, _reason in ruleset.skipped)
    assert not any(r.id == "pkcs12-file" for r in ruleset.rules)


# --- humanise() -------------------------------------------------------------


@pytest.mark.parametrize(
    ("rule_id", "expected"),
    [
        ("aws-access-token", "AWS access token"),
        ("github-pat", "GitHub PAT"),
        ("jwt", "JWT"),
        ("safepaste-database-url-password", "Database URL password"),
        ("openai-api-key", "OpenAI API key"),
    ],
)
def test_humanise(rule_id: str, expected: str) -> None:
    assert humanise(rule_id) == expected


# --- classify() ---------------------------------------------------------


def test_classify_prefers_id_over_description() -> None:
    # Upstream's description for this rule talks about "AWS credentials",
    # which would file it under Passwords if description won; the id's
    # "token" must win instead.
    description = (
        "Identified a pattern that may indicate AWS credentials, risking "
        "unauthorized cloud resource access and data breaches on AWS platforms."
    )
    assert classify("aws-access-token", description) == "tokens"
    assert classify("aws-access-token", description) != "passwords"


# --- Allowlist semantics -----------------------------------------------


def test_allowlist_or_excludes_when_any_criterion_matches() -> None:
    al = Allowlist.from_toml({"stopwords": ["password"], "regexes": ["^X.*$"]})
    assert al.condition == "OR"
    assert al.excludes("mypassword123", "mypassword123", "line") is True  # stopword only
    assert al.excludes("Xabcdef", "Xabcdef", "line") is True  # regex only
    assert al.excludes("zzz999999", "zzz999999", "line") is False  # neither


def test_allowlist_and_requires_every_declared_criterion() -> None:
    al = Allowlist.from_toml(
        {"condition": "AND", "stopwords": ["password"], "regexes": ["^X.*$"]}
    )
    assert al.excludes("mypassword123", "mypassword123", "line") is False  # only 1 of 2
    assert al.excludes("Xpassword", "Xpassword", "line") is True  # both


def test_allowlist_and_with_paths_can_never_exclude() -> None:
    # `paths` constrains the *file* a finding came from; a clipboard has no
    # file, so that vote is always False. Under AND that renders the whole
    # allowlist inert — this is exactly what protects generic-api-key's
    # LICENSE-line regexes from also suppressing clipboard secrets.
    al = Allowlist.from_toml(
        {"condition": "AND", "paths": ["foo.py"], "regexes": ["^X.*$"]}
    )
    assert al.path_scoped is True
    assert al.excludes("Xabcdef", "Xabcdef", "line") is False


def test_allowlist_or_with_paths_still_excludes_on_other_criteria() -> None:
    # Under OR, the unsatisfiable `paths` vote simply contributes nothing;
    # the regex vote still carries the decision on its own.
    al = Allowlist.from_toml({"paths": ["foo.py"], "regexes": ["^X.*$"]})
    assert al.excludes("Xabcdef", "Xabcdef", "line") is True
    assert al.excludes("zzz999999", "zzz999999", "line") is False


def test_allowlist_regex_target_selects_secret_vs_match_vs_line() -> None:
    al_match = Allowlist.from_toml({"regexTarget": "match", "regexes": ["^FULLMATCH$"]})
    assert al_match.excludes("secretval", "FULLMATCH", "line") is True
    assert al_match.excludes("FULLMATCH", "notthematch", "line") is False

    al_line = Allowlist.from_toml({"regexTarget": "line", "regexes": ["forbidden-line"]})
    assert (
        al_line.excludes("secretval", "wholematch", "this has a forbidden-line in it")
        is True
    )
    assert al_line.excludes("secretval", "wholematch", "an unrelated line") is False


def test_allowlist_stopwords_always_test_the_secret_case_insensitively() -> None:
    # Even when regexTarget is 'match' (or 'line'), stopwords are still
    # checked against the *secret*, per the Allowlist docstring.
    al = Allowlist.from_toml({"regexTarget": "match", "stopwords": ["PassWord"]})
    assert al.excludes("has-password-inside", "unrelated-match-text", "line") is True
    assert al.excludes("no-hit-here", "unrelated-match-text", "line") is False


# --- user rule files ------------------------------------------------------


def test_user_rule_file_replaces_an_existing_id_and_adds_a_new_one(
    tmp_path: pathlib.Path,
) -> None:
    custom = tmp_path / "custom.toml"
    custom.write_text(
        """
[[rules]]
id = "github-pat"
description = "Retuned GitHub PAT"
regex = "ghp_CUSTOM[0-9a-zA-Z]{10}"

[[rules]]
id = "safepaste-test-custom-rule"
description = "A brand new custom rule"
category = "api_keys"
regex = "CUSTOMSECRET[0-9]{4}"
keywords = ["customsecret"]
""",
        encoding="utf-8",
    )

    rs = load_default(extra_paths=[custom])

    github_pat_rules = [r for r in rs.rules if r.id == "github-pat"]
    assert len(github_pat_rules) == 1, "the user file must replace, not duplicate"
    assert github_pat_rules[0].description == "Retuned GitHub PAT"
    assert github_pat_rules[0].pattern.pattern == "ghp_CUSTOM[0-9a-zA-Z]{10}"

    assert any(r.id == "safepaste-test-custom-rule" for r in rs.rules)


# ---------------------------------------------------------------------------
# The two off-switches are distinct, and both have to work independently.
#
# A single `enabled` flag cannot express all three states at once. An earlier
# draft tried, and the high-entropy toggle became unable to turn its own rule on.
# ---------------------------------------------------------------------------


def _veto_file(tmp_path, rule_id: str) -> pathlib.Path:
    path = tmp_path / "veto.toml"
    path.write_text(
        f'[[rules]]\nid = "{rule_id}"\ndescription = "vetoed"\n'
        'regex = "ghp_[0-9a-zA-Z]{36}"\nkeywords = ["ghp_"]\nenabled = false\n',
        encoding="utf-8",
    )
    return path


def test_enabled_false_vetoes_a_rule_whose_category_is_on(tmp_path) -> None:
    """A user's `enabled = false` must beat an enabled category.

    This is the whole point of the flag: silencing one vendored rule you
    disagree with, without switching off its entire category.
    """
    plain = load_default()
    assert "github-pat" in {r.id for r in plain.enabled_for(None)}

    vetoed = load_default(extra_paths=[_veto_file(tmp_path, "github-pat")])
    on = frozenset({"tokens", "api_keys"})
    assert "github-pat" not in {r.id for r in vetoed.enabled_for(on)}
    assert "github-pat" not in {r.id for r in vetoed.enabled_for(None)}


def test_vetoed_rule_finds_nothing(tmp_path) -> None:
    vetoed = load_default(extra_paths=[_veto_file(tmp_path, "github-pat")])
    detector = Detector(ruleset=vetoed)
    text = "GITHUB_TOKEN=ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
    assert not [f for f in detector.scan(text) if f.rule_id == "github-pat"]


def test_default_off_is_not_a_veto() -> None:
    """`default_off` withholds a rule by default but must stay switchable."""
    ruleset = load_default()
    high_entropy = next(
        r for r in ruleset.rules if r.id == "safepaste-high-entropy-string"
    )
    assert high_entropy.default_off is True
    assert high_entropy.enabled is True, (
        "must not also be enabled=false, or the Preferences toggle could never "
        "turn it on"
    )

    assert "safepaste-high-entropy-string" not in {
        r.id for r in ruleset.enabled_for(None)
    }
    assert "safepaste-high-entropy-string" in {
        r.id for r in ruleset.enabled_for(frozenset({"high_entropy"}))
    }


# ---------------------------------------------------------------------------
# Compile failures must be loud.
#
# The loader skips a rule whose regex will not compile. That is the right
# runtime behaviour -- one bad user rule should not take the whole guard down --
# but it means a missing detector has no symptom. Ubuntu 24.04's python3-regex
# 0.1.20221031 rejects Go RE2's `\z`, which four upstream rules use, so the
# shipped package ran four detectors short while every test still passed.
# ---------------------------------------------------------------------------


def test_no_rule_fails_to_compile(ruleset) -> None:
    assert ruleset.compile_failures == [], (
        "rule(s) failed to compile: "
        + ", ".join(f"{rid} ({why})" for rid, why in ruleset.compile_failures)
        + f" -- regex module version {getattr(regex, '__version__', 'unknown')}"
    )


def test_re2_end_of_text_anchor_is_translated() -> None:
    r"""`\z` is RE2's end-of-text anchor; Python spells it `\Z` and has no `\z`."""
    assert translate_re2(r"(?:\s|\z)") == r"(?:\s|\Z)"
    assert translate_re2(r"\z") == r"\Z"
    # An escaped backslash followed by a literal z must be left alone.
    assert translate_re2(r"a\\z") == r"a\\z"
    assert translate_re2(r"\Z") == r"\Z"
    assert translate_re2("no anchor") == "no anchor"


def test_rules_using_the_anchor_are_active(ruleset) -> None:
    r"""The four upstream rules that use `\z` must actually be loaded."""
    ids = {r.id for r in ruleset.rules}
    for rule_id in (
        "curl-auth-header",
        "curl-auth-user",
        "openshift-user-token",
        "sentry-org-token",
    ):
        assert rule_id in ids, f"{rule_id} is missing; did the \\z translation break?"
