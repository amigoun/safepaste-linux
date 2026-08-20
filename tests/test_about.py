"""Tests for safepaste.about: the project URL, and how it gets opened.

Nothing here may actually launch a browser, so every test replaces both
openers. `_open_with_gio` exists as its own function largely for that reason:
`Gio.AppInfo.launch_default_for_uri` is reached through a GI class that is
awkward to stub, and a test that failed to stub it would open a real window on
the developer's desktop rather than fail.
"""

from __future__ import annotations

import pathlib
import tomllib

import pytest

from safepaste import about


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


def test_gio_opening_the_url_is_the_end_of_it(monkeypatch) -> None:
    tried: list[str] = []
    monkeypatch.setattr(about, "_open_with_gio", lambda url: tried.append(url) or True)
    monkeypatch.setattr(
        "webbrowser.open",
        lambda *a, **k: pytest.fail("webbrowser must not be reached"),
    )
    assert about.open_url("https://example.invalid/x") is True
    assert tried == ["https://example.invalid/x"]


def test_webbrowser_is_the_fallback_when_gio_declines(monkeypatch) -> None:
    """The case a systemd user unit lands in: no GLib handler, browser instead."""
    opened: list[str] = []
    monkeypatch.setattr(about, "_open_with_gio", lambda _url: False)
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url) or True)
    assert about.open_url("https://example.invalid/y") is True
    assert opened == ["https://example.invalid/y"]


def test_open_url_reports_failure_rather_than_pretending(monkeypatch) -> None:
    """False is load-bearing: it is what makes the front ends show the URL."""
    monkeypatch.setattr(about, "_open_with_gio", lambda _url: False)
    monkeypatch.setattr("webbrowser.open", lambda _url: False)
    assert about.open_url("https://example.invalid/z") is False


def test_open_homepage_opens_the_homepage(monkeypatch) -> None:
    opened: list[str] = []
    monkeypatch.setattr(about, "open_url", lambda url: opened.append(url) or True)
    assert about.open_homepage() is True
    assert opened == [about.HOMEPAGE]
