"""scripts/sync-homebrew-resources.py, against a fake PyPI.

`--check` runs in CI on every push, so what it may fail on matters as much as
what it catches: a pinned resource whose url and sha256 are still exactly what
PyPI published for that release is not broken because upstream has since
released something newer. A pin PyPI does not vouch for is.
"""

from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import sys
import urllib.error

import pytest

SCRIPT = pathlib.Path(__file__).parent.parent / "scripts" / "sync-homebrew-resources.py"

FILES = "https://files.pythonhosted.org/packages"
PINNED_URL = f"{FILES}/b9/5c/aa/regex-2026.9.10.tar.gz"
PINNED_SHA = "1" * 64
LATEST_URL = f"{FILES}/c0/de/bb/regex-2026.9.29.tar.gz"
LATEST_SHA = "2" * 64

FORMULA = f"""\
class Safepaste < Formula
  resource "regex" do
    url "{PINNED_URL}"
    sha256 "{PINNED_SHA}"
  end
end
"""


def _release(version: str, url: str, sha: str) -> dict:
    return {
        "info": {"version": version, "yanked": False},
        "urls": [{"packagetype": "sdist", "url": url, "digests": {"sha256": sha}}],
    }


PYPI = {
    "regex": _release("2026.9.29", LATEST_URL, LATEST_SHA),
    "regex/2026.9.29": _release("2026.9.29", LATEST_URL, LATEST_SHA),
    "regex/2026.9.10": _release("2026.9.10", PINNED_URL, PINNED_SHA),
}


@pytest.fixture
def sync(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("sync_homebrew_resources", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    formula = tmp_path / "safepaste.rb"
    formula.write_text(FORMULA)
    monkeypatch.setattr(module, "FORMULA", formula)

    def urlopen(url: str, timeout: float = 0):
        project = url.removeprefix("https://pypi.org/pypi/").removesuffix("/json")
        if project not in PYPI:
            raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
        return io.BytesIO(json.dumps(PYPI[project]).encode())

    monkeypatch.setattr(module.urllib.request, "urlopen", urlopen)

    def run(*argv: str) -> int:
        monkeypatch.setattr(sys, "argv", [str(SCRIPT), *argv])
        return module.main()

    run.formula = formula
    return run


def test_check_passes_a_valid_pin_when_a_newer_release_exists(sync, capsys) -> None:
    assert sync("--check") == 0
    out = capsys.readouterr().out
    assert "2026.9.29 available" in out
    assert sync.formula.read_text() == FORMULA


def test_check_fails_a_pin_whose_hash_pypi_does_not_match(sync, capsys) -> None:
    sync.formula.write_text(FORMULA.replace(PINNED_SHA, "3" * 64))
    assert sync("--check") == 1
    assert "sha256 differs" in capsys.readouterr().out


def test_check_fails_a_pin_that_is_not_a_release(sync, capsys) -> None:
    sync.formula.write_text(FORMULA.replace("2026.9.10", "2026.9.11"))
    assert sync("--check") == 1
    assert "not a release" in capsys.readouterr().out


def test_check_fails_a_url_pypi_does_not_list(sync, capsys) -> None:
    sync.formula.write_text(FORMULA.replace("/b9/5c/aa/", "/00/00/00/"))
    assert sync("--check") == 1
    assert "lists no" in capsys.readouterr().out


def test_without_check_the_pin_moves_to_the_latest_release(sync, capsys) -> None:
    assert sync() == 0
    text = sync.formula.read_text()
    assert LATEST_URL in text and LATEST_SHA in text
    assert PINNED_URL not in text
