"""The command line reads the same config.toml the daemon does.

A custom rule dropped into rules/, an exclusion made with `safepaste hash`, a
placeholder or a category switched off: each has to mean the same thing to
`safepaste scan` as to the clipboard guard, or the CLI answers a different
question from the one the user configured. Every test here runs against a
private config directory, never the developer's own.

The input-handling checks at the end live here for the same reason: they need
that private directory, since `hash` reads its key from it.
"""

from __future__ import annotations

import io
import logging
import sys

import pytest

from safepaste import cli, config as config_mod

GITHUB = "ghp_A9bC2dE4fG6hJ8kL0mN1pQ3rS5tU7vW9xY1z"
ACME = "acme_q7w2e9r4t6y1u3i8o5p0a2s4"

ACME_RULE = """\
[[rules]]
id = "acme-key"
description = "Acme key"
regex = '''acme_[a-z0-9]{24}'''
category = "internal"
"""


@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config_mod, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(config_mod, "CONFIG_FILE", tmp_path / "config.toml")
    monkeypatch.setattr(config_mod, "RULES_DIR", tmp_path / "rules")
    return tmp_path


@pytest.fixture(autouse=True)
def _restore_package_logger():
    """`cli.main` takes over the shared `safepaste` logger; give it back."""
    lg = logging.getLogger("safepaste")
    handlers, level, propagate = lg.handlers[:], lg.level, lg.propagate
    yield
    lg.handlers[:] = handlers
    lg.setLevel(level)
    lg.propagate = propagate


def _run(monkeypatch, capsys, argv: list[str], stdin: str = "") -> tuple[int, str, str]:
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(stdin.encode())))
    code = cli.main(argv)
    out, err = capsys.readouterr()
    return code, out, err


def _write_config(config_dir, text: str) -> None:
    (config_dir / "config.toml").write_text(text)


def _add_acme_rule(config_dir) -> None:
    (config_dir / "rules").mkdir()
    (config_dir / "rules" / "acme.toml").write_text(ACME_RULE)


# ---------------------------------------------------------------------------
# rules and exclusions
# ---------------------------------------------------------------------------


def test_a_custom_rule_from_the_config_directory_is_used(
    config_dir, monkeypatch, capsys
) -> None:
    _add_acme_rule(config_dir)
    _write_config(config_dir, '[protection]\ncategories = ["tokens", "internal"]\n')

    code, out, _ = _run(monkeypatch, capsys, ["scan", "-"], f"key {ACME}\n")
    assert code == 1 and "acme-key" in out

    code, out, _ = _run(
        monkeypatch, capsys, ["scan", "--no-config", "-"], f"key {ACME}\n"
    )
    assert code == 0 and out == ""


def test_rules_lists_the_custom_rules_too(config_dir, monkeypatch, capsys) -> None:
    _add_acme_rule(config_dir)
    _, out, _ = _run(monkeypatch, capsys, ["rules", "--json"])
    assert "acme-key" in out
    _, out, _ = _run(monkeypatch, capsys, ["rules", "--json", "--no-config"])
    assert "acme-key" not in out


def test_an_exclusion_made_with_hash_is_honoured_by_scan(
    config_dir, monkeypatch, capsys
) -> None:
    code, digest, _ = _run(monkeypatch, capsys, ["hash"], GITHUB)
    assert code == 0
    _write_config(config_dir, f'[exclusions]\nexcluded_hashes = ["{digest.strip()}"]\n')

    code, out, _ = _run(monkeypatch, capsys, ["scan", "-"], f"token {GITHUB}\n")
    assert (code, out) == (0, "")
    code, _, _ = _run(
        monkeypatch, capsys, ["scan", "--no-config", "-"], f"token {GITHUB}\n"
    )
    assert code == 1


def test_a_category_switched_off_in_config_is_off_for_scan(
    config_dir, monkeypatch, capsys
) -> None:
    _write_config(config_dir, '[protection]\ncategories = ["passwords"]\n')
    code, _, _ = _run(monkeypatch, capsys, ["scan", "-"], f"token {GITHUB}\n")
    assert code == 0
    code, _, _ = _run(
        monkeypatch, capsys, ["scan", "--category", "tokens", "-"], f"token {GITHUB}\n"
    )
    assert code == 1, "an explicit --category overrides config"


# ---------------------------------------------------------------------------
# settings, with flags taking precedence
# ---------------------------------------------------------------------------


def test_redact_uses_the_configured_style(config_dir, monkeypatch, capsys) -> None:
    _write_config(
        config_dir,
        '[redaction]\nplaceholder = "<<HIDDEN>>"\nkeep_prefix = 0\nkeep_suffix = 0\n',
    )
    _, out, _ = _run(monkeypatch, capsys, ["redact", "-"], f"token {GITHUB}\n")
    assert out == "token <<HIDDEN>>\n"

    # Sanitised output rescans clean, because scan took the same placeholder.
    code, _, _ = _run(monkeypatch, capsys, ["scan", "-"], out)
    assert code == 0


def test_a_flag_overrides_its_config_key(config_dir, monkeypatch, capsys) -> None:
    _write_config(
        config_dir, '[redaction]\nplaceholder = "<<HIDDEN>>"\nlabel_rules = true\n'
    )
    _, out, _ = _run(
        monkeypatch,
        capsys,
        [
            "redact",
            "--placeholder",
            "[X]",
            "--no-label-rules",
            "--keep-prefix",
            "0",
            "--keep-suffix",
            "0",
            "-",
        ],
        f"token {GITHUB}\n",
    )
    assert out == "token [X]\n"


def test_detection_limits_come_from_config_unless_given(config_dir) -> None:
    _write_config(
        config_dir, "[detection]\nregex_timeout = 1.5\nmax_scan_bytes = 4096\n"
    )
    parser = cli._build_parser()

    detector = cli._make_detector(parser.parse_args(["scan", "-"]))
    assert (detector.regex_timeout, detector.max_scan_bytes) == (1.5, 4096)

    detector = cli._make_detector(
        parser.parse_args(["scan", "--timeout", "0.5", "--max-bytes", "8192", "-"])
    )
    assert (detector.regex_timeout, detector.max_scan_bytes) == (0.5, 8192)

    detector = cli._make_detector(parser.parse_args(["scan", "--no-config", "-"]))
    assert detector.max_scan_bytes == config_mod.Config().max_scan_bytes


def test_a_config_problem_is_reported_on_stderr(
    config_dir, monkeypatch, capsys
) -> None:
    _write_config(config_dir, 'mode = "off"\n')
    code, out, err = _run(monkeypatch, capsys, ["scan", "-"], f"token {GITHUB}\n")
    assert code == 1 and "github-pat" in out
    assert "belongs under [protection]" in err


@pytest.mark.parametrize("value", ["0", "-5", "1023", "lots"])
def test_a_scan_limit_below_the_floor_is_a_usage_error(
    config_dir, monkeypatch, capsys, value: str
) -> None:
    """A limit of zero scanned nothing and exited 0, which reads as clean."""
    with pytest.raises(SystemExit) as exc:
        _run(monkeypatch, capsys, ["scan", "--max-bytes", value, "-"], GITHUB)
    assert exc.value.code == 2
    assert "--max-bytes" in capsys.readouterr().err


def test_the_scan_limit_floor_itself_is_accepted(
    config_dir, monkeypatch, capsys
) -> None:
    floor = str(config_mod.MIN_SCAN_BYTES)
    code, _, _ = _run(monkeypatch, capsys, ["scan", "--max-bytes", floor, "-"], GITHUB)
    assert code == 1


# ---------------------------------------------------------------------------
# input that is not there
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("argv", [["scan", "-"], ["redact", "-"], ["hash"]])
def test_a_closed_stdin_is_unreadable_input_not_a_crash(
    config_dir, monkeypatch, capsys, argv: list[str]
) -> None:
    """`safepaste scan - <&-`: Python hands over sys.stdin as None."""
    monkeypatch.setattr(sys, "stdin", None)
    assert cli.main(argv) == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert "standard input is closed" in err
