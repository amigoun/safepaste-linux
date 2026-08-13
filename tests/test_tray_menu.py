"""The tray menu structure.

Only the dbusmenu tree is exercised, not the D-Bus plumbing — `_build_tree` is
pure data, so it can be checked without a session bus or a status-notifier host.

This file exists because of a bug that was invisible from every angle except
actually clicking the icon: the icon appeared, registration with the watcher
succeeded, and GetLayout returned all eleven items correctly — but clicking did
nothing, because the root item did not advertise that it had a menu.
"""

from __future__ import annotations

import pytest

# The tray needs Gio (python3-gi). Where that is absent there is no tray either,
# so skipping is the honest outcome rather than a failure.
pytest.importorskip("gi", reason="python3-gi not installed; the tray cannot exist")

from safepaste.config import MODES  # noqa: E402
from safepaste.ui.tray import TrayIndicator  # noqa: E402


@pytest.fixture
def tray() -> TrayIndicator:
    # Never started: no bus name is taken and nothing is registered.
    return TrayIndicator()


def _labels(node: dict) -> list[str]:
    return [c["props"].get("label") for c in node["children"]]


def test_the_root_advertises_a_submenu(tray: TrayIndicator) -> None:
    """The regression. Without this the icon is inert.

    A dbusmenu host decides whether to open a menu by reading
    `children-display`, *not* by noticing the item has children. An empty
    property dict on the root means GNOME concludes there is nothing to show and
    silently swallows the click — no error, no log line, nothing.
    """
    root = tray._build_tree()
    assert root["props"].get("children-display") == "submenu", (
        "the root must declare children-display=submenu, or clicking the tray "
        "icon does nothing at all"
    )
    assert root["children"], "a submenu that declares itself must have children"


def test_every_node_with_children_declares_them(tray: TrayIndicator) -> None:
    """Same rule, applied everywhere — the root is just the easiest to forget."""

    def check(node: dict, path: str) -> None:
        if node["children"]:
            assert node["props"].get("children-display") == "submenu", (
                f"{path} has children but does not declare children-display"
            )
        for child in node["children"]:
            check(child, f"{path}/{child['props'].get('label') or child['id']}")

    check(tray._build_tree(), "root")


def test_the_menu_contains_the_expected_actions(tray: TrayIndicator) -> None:
    labels = _labels(tray._build_tree())
    assert "Sanitise clipboard now" in labels
    assert "Protection" in labels
    assert "Pause 15 minutes" in labels
    assert "Preferences…" in labels
    assert "Quit" in labels


def test_the_protection_submenu_offers_every_mode(tray: TrayIndicator) -> None:
    root = tray._build_tree()
    submenu = next(c for c in root["children"] if c["props"].get("label") == "Protection")
    assert len(submenu["children"]) == len(MODES)
    # Exactly one radio item is ticked, and it is the current mode.
    ticked = [c for c in submenu["children"] if c["props"].get("toggle-state") == 1]
    assert len(ticked) == 1
    assert all(c["props"].get("toggle-type") == "radio" for c in submenu["children"])


def test_the_ticked_mode_follows_set_state(tray: TrayIndicator) -> None:
    tray.set_state("notify", False)
    root = tray._build_tree()
    submenu = next(c for c in root["children"] if c["props"].get("label") == "Protection")
    ticked = [c for c in submenu["children"] if c["props"].get("toggle-state") == 1]
    assert len(ticked) == 1
    assert ticked[0]["props"]["label"] == "Notify only"


def test_resume_is_hidden_until_paused(tray: TrayIndicator) -> None:
    def resume(node: dict) -> dict:
        return next(
            c for c in node["children"] if c["props"].get("label") == "Resume protection"
        )

    tray.set_state("redact", False)
    assert resume(tray._build_tree())["props"].get("visible") is False

    tray.set_state("redact", True)
    assert resume(tray._build_tree())["props"].get("visible") is not False


def test_the_status_line_is_present_and_not_clickable(tray: TrayIndicator) -> None:
    first = tray._build_tree()["children"][0]
    assert first["props"]["enabled"] is False
    assert first["props"]["label"]


def test_item_ids_are_unique(tray: TrayIndicator) -> None:
    """A duplicate id makes Event() ambiguous, so the wrong action fires."""
    seen: list[int] = []

    def walk(node: dict) -> None:
        seen.append(node["id"])
        for child in node["children"]:
            walk(child)

    walk(tray._build_tree())
    assert len(seen) == len(set(seen)), f"duplicate menu ids: {seen}"


def test_alert_state_does_not_break_the_structure(tray: TrayIndicator) -> None:
    tray.set_alert(2)
    root = tray._build_tree()
    assert root["props"].get("children-display") == "submenu"
    assert "2 secrets" in root["children"][0]["props"]["label"]
