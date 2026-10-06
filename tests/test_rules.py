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


def test_a_veto_needs_only_the_id(tmp_path) -> None:
    """`id` + `enabled = false` is the whole veto; copying the regex is not
    required, and a typo in such a copy is how a veto quietly fails."""
    path = tmp_path / "veto.toml"
    path.write_text('[[rules]]\nid = "github-pat"\nenabled = false\n', encoding="utf-8")

    rs = load_default(extra_paths=[path])

    assert "github-pat" not in {r.id for r in rs.enabled_for(None)}
    detector = Detector(ruleset=rs)
    text = "GITHUB_TOKEN=ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
    assert not [f for f in detector.scan(text) if f.rule_id == "github-pat"]
    # The rule is silenced, not replaced: everything else about it is intact.
    rule = next(r for r in rs.rules if r.id == "github-pat")
    assert rule.pattern.pattern == next(
        r for r in load_default().rules if r.id == "github-pat"
    ).pattern.pattern


def test_default_off_alone_makes_a_bundled_rule_opt_in(tmp_path) -> None:
    path = tmp_path / "quiet.toml"
    path.write_text('[[rules]]\nid = "github-pat"\ndefault_off = true\n', encoding="utf-8")

    rs = load_default(extra_paths=[path])

    assert "github-pat" not in {r.id for r in rs.enabled_for(None)}
    assert "github-pat" in {r.id for r in rs.enabled_for(frozenset({"tokens"}))}


def test_a_string_veto_without_a_regex_is_refused(tmp_path, caplog) -> None:
    path = tmp_path / "veto.toml"
    path.write_text('[[rules]]\nid = "github-pat"\nenabled = "false"\n', encoding="utf-8")

    rs = load_default(extra_paths=[path])

    assert next(r for r in rs.rules if r.id == "github-pat").enabled is True
    assert "enabled must be true or false" in caplog.text


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


# ---------------------------------------------------------------------------
# Malformed rule files: the bad entry is skipped and said so, never a crash.
#
# A user file is hand-written TOML, and every one of these shapes parses as
# valid TOML. They used to raise from deep inside the loader -- or worse, at
# scan time -- and one of them quietly widened an allowlist instead.
# ---------------------------------------------------------------------------

_GITHUB_TOKEN = "GITHUB_TOKEN=ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"


def _user_rules(tmp_path, body: str) -> pathlib.Path:
    path = tmp_path / "custom.toml"
    path.write_text(body, encoding="utf-8")
    return path


def test_rules_written_as_a_table_not_an_array_are_skipped(tmp_path, caplog) -> None:
    path = _user_rules(tmp_path, '[rules]\nid = "x"\nregex = "CUSTOMSECRET"\n')

    rs = load_default(extra_paths=[path])

    assert "github-pat" in {r.id for r in rs.rules}, "the bundled rules still load"
    assert "x" not in {r.id for r in rs.rules}
    assert "[[rules]]" in caplog.text


@pytest.mark.parametrize(
    ("line", "complaint"),
    [
        ("regex = 5", "regex must be a string"),
        ('regex = "CUSTOM[0-9]{4}"\nentropy = "3.0"', "entropy must be a number"),
        ('regex = "CUSTOM[0-9]{4}"\nkeywords = "custom"', "keywords must be"),
        ('regex = "CUSTOM[0-9]{4}"\nsecretGroup = 3', "secretGroup 3"),
        ('regex = "CUSTOM[0-9]{4}"\nenabled = "false"', "enabled must be"),
    ],
    ids=["regex-int", "entropy-string", "keywords-string", "group-out-of-range",
         "enabled-string"],
)
def test_a_rule_with_a_mistyped_field_is_skipped_with_a_warning(
    tmp_path, caplog, line: str, complaint: str
) -> None:
    path = _user_rules(tmp_path, f'[[rules]]\nid = "safepaste-test-bad"\n{line}\n')

    rs = load_default(extra_paths=[path])

    assert "safepaste-test-bad" not in {r.id for r in rs.rules}
    assert "safepaste-test-bad" in caplog.text and complaint in caplog.text
    # And scanning with what did load still works.
    assert Detector(ruleset=rs).scan(f"{_GITHUB_TOKEN} CUSTOM1234")


def test_a_string_enabled_does_not_replace_the_rule_it_names(tmp_path) -> None:
    """`enabled = "false"` is truthy; the vendored rule must stay as it was."""
    path = _user_rules(
        tmp_path,
        '[[rules]]\nid = "github-pat"\nregex = "ghp_[0-9a-zA-Z]{36}"\n'
        'enabled = "false"\n',
    )

    rs = load_default(extra_paths=[path])

    rule = next(r for r in rs.rules if r.id == "github-pat")
    assert rule.enabled is True
    assert rule.description != "github-pat", "the vendored rule must survive"


@pytest.mark.parametrize(
    "body",
    [
        '[allowlist]\nregexes = "abc"\n',
        '[[rules]]\nid = "github-pat"\nregex = "ghp_[0-9a-zA-Z]{36}"\n'
        '  [[rules.allowlists]]\n  regexes = "abc"\n',
        '[allowlist]\nstopwords = "abc"\n',
        '[allowlist]\ncondition = 1\nregexes = ["^ghp_"]\n',
    ],
    ids=["global-regexes-string", "rule-regexes-string", "stopwords-string",
         "condition-int"],
)
def test_a_malformed_allowlist_is_dropped_not_widened(
    tmp_path, caplog, body: str
) -> None:
    """A string where an array belongs iterates per character: "abc" became
    three one-letter patterns excusing any secret with an a, b or c in it."""
    rs = load_default(extra_paths=[_user_rules(tmp_path, body)])

    found = Detector(ruleset=rs).scan(_GITHUB_TOKEN)

    assert "github-pat" in {f.rule_id for f in found}
    assert "skipping an allowlist" in caplog.text


def test_an_and_allowlist_with_an_uncompilable_regex_is_dropped() -> None:
    """Under AND, losing a criterion means excusing more."""
    with pytest.raises(ValueError):
        Allowlist.from_toml(
            {"condition": "AND", "stopwords": ["ghp"], "regexes": ["(unclosed"]}
        )
