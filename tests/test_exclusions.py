"""Exclusions: a keyed digest, and a key that lives in its own file.

The thing being pinned here is a *negative*: config.toml on its own must not let
anyone work out which values the user excluded. A plain SHA-256 does let them --
`hunter2`, `admin` or a weak database password is a handful of guesses, offline,
with no rate limit -- so the digest is an HMAC under a key that config.toml does
not contain, and everything below is about that split staying true.
"""

from __future__ import annotations

import hashlib
import logging
import stat
import sys

import pytest

from safepaste import config as config_mod
from safepaste.detector import EXCLUSION_SCHEME, Detector, is_keyed_digest, value_hash
from safepaste.detector.rules import RuleSet

SECRET = "wJq7Kd2LmN9pRs4TvXbZ8cE1fG3hJ5kL7nQ0rS2u"
TEXT = f"AWS_SECRET_ACCESS_KEY={SECRET}"

# Two fixed keys: fixed so a failure is reproducible, distinct so "the same value
# under a different key" is a case the suite actually covers.
KEY_A = bytes(range(32))
KEY_B = bytes(range(1, 33))

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX file modes; Windows ACLs are not this"
)


# ---------------------------------------------------------------------------
# the digest
# ---------------------------------------------------------------------------


def test_digest_names_its_own_scheme() -> None:
    digest = value_hash(SECRET, KEY_A)
    scheme, _, hexpart = digest.partition(":")
    assert scheme == EXCLUSION_SCHEME
    assert len(hexpart) == 64
    assert bytes.fromhex(hexpart)  # hex, so a config file stays ASCII
    assert is_keyed_digest(digest)


def test_digest_is_stable_for_a_key_and_different_across_keys() -> None:
    assert value_hash(SECRET, KEY_A) == value_hash(SECRET, KEY_A)
    assert value_hash(SECRET, KEY_A) != value_hash(SECRET, KEY_B)


def test_digest_is_not_the_bare_hash_of_the_value() -> None:
    """The regression this whole scheme exists for.

    If the bare SHA-256 appeared anywhere in what gets stored, a reader of
    config.toml could confirm a guessed value without the key.
    """
    bare = hashlib.sha256(SECRET.encode("utf-8")).hexdigest()
    assert bare not in value_hash(SECRET, KEY_A)


def test_a_keyless_digest_is_refused_rather_than_computed() -> None:
    for empty in (b"", None):
        with pytest.raises(ValueError):
            value_hash(SECRET, empty)  # type: ignore[arg-type]


def test_the_secret_never_appears_in_its_digest() -> None:
    assert SECRET not in value_hash(SECRET, KEY_A)


# ---------------------------------------------------------------------------
# matching behaviour is preserved -- but only under the right key
# ---------------------------------------------------------------------------


def test_a_keyed_exclusion_suppresses_exactly_that_value(ruleset: RuleSet) -> None:
    d = Detector(
        ruleset=ruleset,
        excluded_hashes=frozenset({value_hash(SECRET, KEY_A)}),
        exclusion_key=KEY_A,
    )
    assert d.scan(TEXT) == []
    # An unrelated secret is not caught up in it.
    assert d.scan("GITHUB_TOKEN=ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z")


def test_an_exclusion_does_not_match_under_a_different_key(ruleset: RuleSet) -> None:
    d = Detector(
        ruleset=ruleset,
        excluded_hashes=frozenset({value_hash(SECRET, KEY_A)}),
        exclusion_key=KEY_B,
    )
    assert d.scan(TEXT), "a digest from another key must not suppress anything"


def test_a_missing_key_fails_towards_flagging(ruleset: RuleSet, caplog) -> None:
    """The lost-key case: warn, and protect rather than wave things through."""
    with caplog.at_level(logging.WARNING):
        d = Detector(
            ruleset=ruleset,
            excluded_hashes=frozenset({value_hash(SECRET, KEY_A)}),
            exclusion_key=None,
        )
    assert d.scan(TEXT)
    assert any("exclusion key" in r.getMessage() for r in caplog.records)


def test_a_bare_hash_entry_is_dropped_not_trusted(ruleset: RuleSet, caplog) -> None:
    bare = hashlib.sha256(SECRET.encode("utf-8")).hexdigest()
    with caplog.at_level(logging.WARNING):
        d = Detector(ruleset=ruleset, excluded_hashes=frozenset({bare}), exclusion_key=KEY_A)
    assert d.excluded_hashes == frozenset()
    assert d.scan(TEXT), "an older bare digest must not suppress anything"
    assert any(EXCLUSION_SCHEME in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# the key file
# ---------------------------------------------------------------------------


def test_the_key_sits_beside_the_config_file_not_inside_it(tmp_path) -> None:
    cfg = tmp_path / "config.toml"
    assert config_mod.exclusion_key_path(cfg) == tmp_path / config_mod.EXCLUSION_KEY_NAME


def test_loading_a_key_that_does_not_exist_creates_nothing(tmp_path) -> None:
    cfg = tmp_path / "config.toml"
    assert config_mod.load_exclusion_key(cfg) is None
    assert not (tmp_path / config_mod.EXCLUSION_KEY_NAME).exists()


def test_the_key_is_minted_once_and_then_reused(tmp_path) -> None:
    cfg = tmp_path / "config.toml"
    first = config_mod.ensure_exclusion_key(cfg)
    assert len(first) == config_mod.EXCLUSION_KEY_BYTES
    assert config_mod.ensure_exclusion_key(cfg) == first
    assert config_mod.load_exclusion_key(cfg) == first


def test_minting_a_key_creates_the_directory(tmp_path) -> None:
    cfg = tmp_path / "fresh" / "config.toml"
    key = config_mod.ensure_exclusion_key(cfg)
    assert (tmp_path / "fresh" / config_mod.EXCLUSION_KEY_NAME).exists()
    assert len(key) == config_mod.EXCLUSION_KEY_BYTES


@posix_only
def test_the_key_is_unreadable_to_other_users(tmp_path) -> None:
    cfg = tmp_path / "sub" / "config.toml"
    config_mod.ensure_exclusion_key(cfg)
    key_file = tmp_path / "sub" / config_mod.EXCLUSION_KEY_NAME
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(key_file.parent.stat().st_mode) == 0o700


def test_no_temporary_key_is_left_behind(tmp_path) -> None:
    cfg = tmp_path / "config.toml"
    config_mod.ensure_exclusion_key(cfg)
    assert sorted(p.name for p in tmp_path.iterdir()) == [config_mod.EXCLUSION_KEY_NAME]


def test_an_existing_key_wins_a_race(tmp_path) -> None:
    """A second process asking for a key must not replace the first one's.

    Overwriting would silently invalidate every exclusion already written under
    the key that was there.
    """
    cfg = tmp_path / "config.toml"
    incumbent = bytes(range(100, 132))
    (tmp_path / config_mod.EXCLUSION_KEY_NAME).write_text(incumbent.hex() + "\n")
    assert config_mod.ensure_exclusion_key(cfg) == incumbent


@pytest.mark.parametrize(
    "content", ["", "not hex at all", "abcd", bytes(range(16)).hex()], ids=
    ["empty", "not-hex", "too-short", "half-length"]
)
def test_an_unusable_key_reads_as_absent(tmp_path, content: str, caplog) -> None:
    cfg = tmp_path / "config.toml"
    (tmp_path / config_mod.EXCLUSION_KEY_NAME).write_text(content)
    with caplog.at_level(logging.ERROR):
        assert config_mod.load_exclusion_key(cfg) is None


# ---------------------------------------------------------------------------
# config: bare-hash entries go, keyed entries stay
# ---------------------------------------------------------------------------


def test_bare_hash_entries_are_dropped_with_a_warning() -> None:
    bare = hashlib.sha256(b"hunter2").hexdigest()
    keyed = value_hash("hunter2", KEY_A)
    cfg = config_mod.Config(excluded_hashes=(bare, keyed)).validated()

    assert cfg.excluded_hashes == (keyed,)
    assert any("ignoring 1 exclusion" in w for w in cfg._warnings)
    assert any(EXCLUSION_SCHEME in w for w in cfg._warnings)


def test_keyed_entries_survive_a_save_and_load(tmp_path) -> None:
    path = tmp_path / "config.toml"
    keyed = value_hash(SECRET, KEY_A)
    config_mod.save(config_mod.Config(excluded_hashes=(keyed,)).validated(), path)

    assert config_mod.load(path).excluded_hashes == (keyed,)


def test_a_saved_config_gives_nothing_away_on_its_own(tmp_path) -> None:
    path = tmp_path / "config.toml"
    key = config_mod.ensure_exclusion_key(path)
    config_mod.save(
        config_mod.Config(excluded_hashes=(value_hash("hunter2", key),)).validated(), path
    )

    written = path.read_text()
    assert hashlib.sha256(b"hunter2").hexdigest() not in written
    assert "hunter2" not in written
    assert key.hex() not in written, "the key must not end up in the file it protects"
