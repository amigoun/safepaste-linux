"""Loading a hand-edited config.toml.

The promise being pinned is the one in `Config.validated`: one bad key must not
leave the user with no clipboard protection. A value of the wrong type is the
commonest way to get a key wrong -- quoting a number, writing a single category
as a string -- and it has to cost that key its setting, never the whole daemon
its startup or a feature switch its meaning.
"""

from __future__ import annotations

import pytest

from safepaste import config as config_mod
from safepaste.detector import Detector, load_default

DEFAULTS = config_mod.Config()


@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    """A private config directory, so nothing here reads the developer's own."""
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "RULES_DIR", tmp_path / "rules")
    return tmp_path


def _load(config_dir, text: str) -> config_mod.Config:
    path = config_dir / "config.toml"
    path.write_text(text)
    return config_mod.load(path)


# ---------------------------------------------------------------------------
# values of the wrong type
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "section, key, toml_value",
    [
        ("protection", "restore_timeout_secs", '"60"'),
        ("protection", "categories", '"tokens"'),
        ("protection", "categories", "[1]"),
        ("protection", "mode", '["off"]'),
        ("redaction", "placeholder", "5"),
        ("redaction", "keep_prefix", '"2"'),
        ("redaction", "keep_prefix", "true"),
        ("redaction", "label_rules", '"no"'),
        ("detection", "regex_timeout", '"0.5"'),
        ("detection", "max_scan_bytes", "2048.5"),
        ("detection", "extra_rule_globs", '"rules/*.toml"'),
        ("exclusions", "excluded_hashes", "[1]"),
        ("input", "auto_paste", '"false"'),
    ],
)
def test_a_value_of_the_wrong_type_keeps_the_default(
    config_dir, section: str, key: str, toml_value: str
) -> None:
    cfg = _load(config_dir, f"[{section}]\n{key} = {toml_value}\n")

    assert getattr(cfg, key) == getattr(DEFAULTS, key)
    assert any(f"[{section}].{key}" in w for w in cfg._warnings)


def test_a_wrong_type_costs_only_its_own_key(config_dir) -> None:
    cfg = _load(
        config_dir,
        '[protection]\nmode = "notify"\nrestore_timeout_secs = "90"\n'
        '[redaction]\nkeep_prefix = 0\n',
    )
    assert cfg.mode == "notify"
    assert cfg.keep_prefix == 0
    assert cfg.restore_timeout_secs == DEFAULTS.restore_timeout_secs


def test_a_whole_number_is_accepted_where_a_float_is_expected(config_dir) -> None:
    cfg = _load(config_dir, "[detection]\nregex_timeout = 1\n")
    assert cfg.regex_timeout == 1.0
    assert isinstance(cfg.regex_timeout, float)
    assert cfg._warnings == []


def test_a_quoted_false_does_not_switch_a_feature_on(config_dir) -> None:
    cfg = _load(
        config_dir, '[redaction]\nlabel_rules = "false"\n[input]\nauto_paste = "no"\n'
    )
    assert cfg.label_rules is False
    assert cfg.auto_paste is False


def test_a_single_category_string_still_leaves_detection_running(config_dir) -> None:
    """Iterated as a string, "tokens" became six one-letter categories and none
    of them existed, so every rule went quiet without a crash to say so."""
    cfg = _load(config_dir, '[protection]\ncategories = "tokens"\n')
    detector = Detector(load_default(), categories=cfg.category_set)
    assert len(detector.active_rules) > 200


def test_a_wrongly_typed_config_still_builds_a_working_detector(config_dir) -> None:
    cfg = _load(
        config_dir,
        "[redaction]\nplaceholder = 5\n"
        "[detection]\nmax_scan_bytes = 2048.5\nregex_timeout = \"0.5\"\n",
    )
    detector = Detector(
        load_default(cfg.extra_rule_paths()),
        categories=cfg.category_set,
        regex_timeout=cfg.regex_timeout,
        max_scan_bytes=cfg.max_scan_bytes,
        placeholder=cfg.placeholder,
    )
    assert detector.scan("GITHUB_TOKEN=ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z")


def test_the_warning_does_not_repeat_the_value(config_dir) -> None:
    """A token pasted into the wrong key must not be copied into the log."""
    cfg = _load(config_dir, '[redaction]\nkeep_prefix = "hunter2"\n')
    assert not any("hunter2" in w for w in cfg._warnings)


# ---------------------------------------------------------------------------
# extra_rule_globs
# ---------------------------------------------------------------------------

RULE_FILE = """\
[[rules]]
id = "acme-key"
description = "Acme key"
regex = '''acme_[a-z0-9]{24}'''
"""


def test_an_absolute_rule_glob_is_honoured(config_dir, tmp_path_factory) -> None:
    elsewhere = tmp_path_factory.mktemp("shared-rules")
    (elsewhere / "acme.toml").write_text(RULE_FILE)
    cfg = _load(
        config_dir, f'[detection]\nextra_rule_globs = ["{elsewhere.as_posix()}/*.toml"]\n'
    )
    assert cfg.extra_rule_paths() == [elsewhere / "acme.toml"]


def test_a_relative_rule_glob_is_read_from_the_config_directory(config_dir) -> None:
    (config_dir / "rules").mkdir()
    (config_dir / "rules" / "acme.toml").write_text(RULE_FILE)
    cfg = _load(config_dir, "")
    assert cfg.extra_rule_paths() == [config_dir / "rules" / "acme.toml"]


@pytest.mark.parametrize("pattern", ["", "rules/"])
def test_an_unusable_rule_glob_is_skipped_not_fatal(config_dir, pattern: str) -> None:
    cfg = _load(
        config_dir, f'[detection]\nextra_rule_globs = ["{pattern}", "rules/*.toml"]\n'
    )
    assert cfg.extra_rule_paths() == []
