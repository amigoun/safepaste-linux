"""Tests for safepaste.about: the project URL, and how it gets opened.

Nothing here may open a real browser, and that is enforced rather than trusted:
`no_openers` is autouse, so a test that forgets to stub one of the three
mechanisms still cannot reach the session. Without it, adding the portal path
made the existing tests fire real `OpenURI` requests and spray tabs across the
desktop -- which is how this fixture came to exist.
"""

from __future__ import annotations

import pathlib
import tomllib

import pytest

from safepaste import about


@pytest.fixture(autouse=True)
def no_openers(monkeypatch):
    """Every mechanism refuses by default; a test opts one back in."""
    monkeypatch.setattr(about, "_open_with_portal", lambda _url: False)
    monkeypatch.setattr(about, "_open_with_gio", lambda _url: False)
    monkeypatch.setattr("webbrowser.open", lambda _url: False)


def test_the_homepage_matches_the_packaging_metadata() -> None:
    """The URL is duplicated, so this is the test that keeps it honest.

    `about.HOMEPAGE` cannot be read from package metadata at runtime -- the .deb
    copies the tree in without ever pip-installing it -- so the value is written
    out twice, here and in pyproject.toml. Two copies are fine; two *different*
    copies would point users at the wrong repository from the tray.
    """
    root = pathlib.Path(__file__).resolve().parent.parent
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    assert about.HOMEPAGE == pyproject["project"]["urls"]["Homepage"]


def test_the_portal_is_tried_first_and_ends_it(monkeypatch) -> None:
    """Order matters, not just coverage.

    The portal is first because the daemon's unit sets NoNewPrivileges, and a
    browser spawned as its child inherits that and dies -- Chrome's SUID sandbox
    helper aborts. If a refactor ever reorders these, About silently does nothing
    again under systemd, which is exactly the bug this encodes.
    """
    tried: list[str] = []
    monkeypatch.setattr(about, "_open_with_portal", lambda url: tried.append(url) or True)
    monkeypatch.setattr(
        about, "_open_with_gio", lambda _url: pytest.fail("Gio must not be reached")
    )
    monkeypatch.setattr(
        "webbrowser.open", lambda _url: pytest.fail("webbrowser must not be reached")
    )
    assert about.open_url("https://example.invalid/x") is True
    assert tried == ["https://example.invalid/x"]


def test_gio_is_the_second_choice(monkeypatch) -> None:
    """No portal -- a plain X session, a minimal container."""
    tried: list[str] = []
    monkeypatch.setattr(about, "_open_with_gio", lambda url: tried.append(url) or True)
    monkeypatch.setattr(
        "webbrowser.open", lambda _url: pytest.fail("webbrowser must not be reached")
    )
    assert about.open_url("https://example.invalid/y") is True
    assert tried == ["https://example.invalid/y"]


def test_webbrowser_is_the_last_resort(monkeypatch) -> None:
    opened: list[str] = []
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url) or True)
    assert about.open_url("https://example.invalid/z") is True
    assert opened == ["https://example.invalid/z"]


def test_open_url_reports_failure_rather_than_pretending() -> None:
    """False is load-bearing: it is what makes the front ends show the URL."""
    assert about.open_url("https://example.invalid/w") is False


def test_open_homepage_opens_the_homepage(monkeypatch) -> None:
    opened: list[str] = []
    monkeypatch.setattr(about, "open_url", lambda url: opened.append(url) or True)
    assert about.open_homepage() is True
    assert opened == [about.HOMEPAGE]
