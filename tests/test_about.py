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


# ---------------------------------------------------------------------------
# Where the installed version is visible
# ---------------------------------------------------------------------------
#
# It was readable nowhere at runtime except the Linux-only D-Bus Version
# property: no --version on either entry point, and nothing in any tray.


def test_the_cli_reports_its_version(capsys) -> None:
    from safepaste import __version__
    from safepaste.cli import main

    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])

    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"safepaste {__version__}"


def test_the_daemon_reports_its_version_without_importing_a_toolkit(
    capsys, monkeypatch
) -> None:
    """Answered before dispatch, so it works where the service cannot start.

    Pinned by pretending to be a platform with no backend at all: the version
    must still come back, and the "no SafePaste service for platform" path must
    not be reached.
    """
    from safepaste import __version__
    from safepaste.service import main

    monkeypatch.setattr("sys.platform", "aix7")
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"safepaste {__version__}"


def test_the_version_is_read_from_the_package_not_from_metadata() -> None:
    """importlib.metadata cannot be the source, and this says why.

    The .deb copies the tree in and writes its own shims, so nothing ever
    pip-installs itself and there is no distribution for metadata to find. A
    version surface built on it would work on Homebrew and Scoop and report
    nothing on the platform this project started on.
    """
    import safepaste

    assert isinstance(safepaste.__version__, str)
    assert safepaste.__version__.count(".") >= 2

    root = pathlib.Path(__file__).resolve().parent.parent
    source = (root / "safepaste" / "__init__.py").read_text(encoding="utf-8")
    assert f'__version__ = "{safepaste.__version__}"' in source


def test_the_packaged_version_matches_the_source() -> None:
    """build-deb.sh and build-exe.py both sed this line out of __init__.py."""
    import re

    import safepaste

    root = pathlib.Path(__file__).resolve().parent.parent
    source = (root / "safepaste" / "__init__.py").read_text(encoding="utf-8")
    found = re.search(r'^__version__ = "(.*)"$', source, re.MULTILINE)
    assert found is not None, "the packaging scripts' sed pattern no longer matches"
    assert found.group(1) == safepaste.__version__


def test_the_macos_about_item_shows_the_version() -> None:
    import sys

    if sys.platform != "darwin":
        pytest.skip("needs AppKit for the Tray")
    from conftest import ABOUT_LABEL
    from safepaste.backend.darwin_loop import Tray

    class _Loop:
        ready = True

    labels = [label for _k, label, _a in Tray(_Loop()).build_menu_items()]
    assert ABOUT_LABEL in labels
    assert __import__("safepaste").__version__ in ABOUT_LABEL
