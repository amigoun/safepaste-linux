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


# ---------------------------------------------------------------------------
# The D-Bus wire shape.
#
# Two bugs here left the icon inert while every hand inspection looked correct,
# so both are pinned. GNOME logged 34,962 errors in one session over the first
# of them, retrying the layout update in a loop.
# ---------------------------------------------------------------------------


def test_menu_children_are_not_double_wrapped_variants(tray: TrayIndicator) -> None:
    r"""A child of "av" must be the struct itself, not a variant holding it.

    "av" already means "array of variants", so wrapping each child in an explicit
    GLib.Variant("v", ...) produces a variant inside a variant. gdbus prints the
    difference as `<<(1, ...)>>` versus `<(1, ...)>` — trivial to read past.

    GNOME's appindicator extension does `children.map(c => c.deep_unpack())` then
    `childrenUnpacked.map(([c]) => c)`. Against a double-wrapped child that
    destructuring raises `TypeError: (destructured parameter) is not iterable`,
    the layout update aborts, and the menu never appears — while GetLayout,
    GetGroupProperties and every property still answer correctly by hand.
    """
    from gi.repository import GLib

    _id, _props, children = tray._node_tuple(tray._build_tree(), [], -1)
    assert children, "the root must have children to check"

    for child in children:
        assert isinstance(child, GLib.Variant)
        assert child.get_type_string() == "(ia{sv}av)", (
            f"child variant is {child.get_type_string()!r}; a bare 'v' here means "
            "it was wrapped twice and GNOME will refuse the whole layout"
        )


def test_nested_submenu_children_are_also_single_wrapped(tray: TrayIndicator) -> None:
    """The Protection submenu is a level deeper, so it exercises the recursion."""
    _id, _props, children = tray._node_tuple(tray._build_tree(), [], -1)
    nested = [c for c in children if c.get_child_value(2).n_children() > 0]
    assert nested, "expected at least one child with children of its own"
    for parent in nested:
        grandchildren = parent.get_child_value(2)
        for index in range(grandchildren.n_children()):
            grandchild = grandchildren.get_child_value(index)
            # Unwrap the implicit 'v' of the av slot; what is inside must be the
            # struct, not another variant.
            inner = grandchild.get_variant()
            assert inner.get_type_string() == "(ia{sv}av)", (
                f"nested child unwraps to {inner.get_type_string()!r}, i.e. it was "
                "wrapped twice"
            )


def test_window_id_is_int32_as_the_spec_requires(tray: TrayIndicator) -> None:
    """StatusNotifierItem declares WindowId as int32.

    Declaring "u" makes GNOME log `Received property WindowId with type u does
    not match expected type i in the expected interface` and discard it.
    """
    from safepaste.ui.tray import SNI_INTROSPECTION

    assert '<property name="WindowId" type="i" access="read"/>' in SNI_INTROSPECTION
    value = tray._handle_sni_get_property(None, None, None, None, "WindowId")
    assert value is not None
    assert value.get_type_string() == "i"


def test_the_declared_interface_and_the_getters_agree(tray: TrayIndicator) -> None:
    """Every declared property must be answerable, with the declared type.

    A mismatch is only visible in GNOME's journal, never as an exception here,
    which is exactly how the WindowId bug survived.
    """
    from gi.repository import Gio

    from safepaste.ui.tray import SNI_INTROSPECTION

    iface = Gio.DBusNodeInfo.new_for_xml(SNI_INTROSPECTION).interfaces[0]
    for prop in iface.properties:
        value = tray._handle_sni_get_property(None, None, None, None, prop.name)
        assert value is not None, f"{prop.name} is declared but has no getter"
        assert value.get_type_string() == prop.signature, (
            f"{prop.name} is declared {prop.signature!r} but the getter returns "
            f"{value.get_type_string()!r}"
        )


# ---------------------------------------------------------------------------
# The detection dialog's transient parent.
#
# GTK logs "AdwMessageDialog mapped without a transient parent. This is
# discouraged." for every parentless dialog -- nine times in one afternoon of real
# use, the most frequent line in the journal.
# ---------------------------------------------------------------------------


def test_the_dialog_accepts_a_transient_parent() -> None:
    # require_version before importing Adw, or PyGI warns -- and the suite runs
    # with -W error, so a warning is a failure. safepaste.ui.dialog does this
    # itself, but a test must not depend on import order to be correct.
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gtk

    Adw.init()
    from safepaste.ui.dialog import DetectionDialog

    parent = Gtk.Window()
    dialog = DetectionDialog(
        secrets=1, labels=("GitHub PAT",), chars_kept=10,
        can_restore=True, restore_seconds=60, formatting_lost=False, parent=parent,
    )
    assert dialog.get_transient_for() is parent
    # Never presented, so the parent must stay invisible; only its existence matters.
    assert parent.get_visible() is False


def test_the_dialog_still_works_without_one() -> None:
    """Degrading is required: a parentless dialog is discouraged, not broken."""
    import gi

    gi.require_version("Adw", "1")
    from gi.repository import Adw

    Adw.init()
    from safepaste.ui.dialog import DetectionDialog

    dialog = DetectionDialog(
        secrets=1, labels=("GitHub PAT",), chars_kept=10,
        can_restore=False, restore_seconds=0, formatting_lost=False, parent=None,
    )
    assert dialog.get_transient_for() is None
    assert dialog.get_heading()
