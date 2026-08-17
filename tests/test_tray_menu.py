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

from gi.repository import GLib  # noqa: E402

from safepaste.config import MODES  # noqa: E402
from safepaste.ui.tray import (  # noqa: E402
    MENU_INTERFACE,
    MENU_OBJECT_PATH,
    TrayIndicator,
)


def _can_build_widgets() -> bool:
    """Whether a GTK widget can actually be constructed here.

    Three separate things have to hold, and the first two are not enough -- learned
    one CI round trip at a time:

    1. `gi` importable. The module-level skip above covers that, and it is all the
       tray tests need, since they only touch Gio.
    2. The GTK4 and libadwaita *typelibs* present. Without them require_version
       raises ValueError: "Namespace Adw not available".
    3. GTK actually able to build a widget, which needs a display.

    Note the probe *constructs* something rather than asking Gtk.init_check(), which
    is not trustworthy for this: with GDK_BACKEND set to nonsense it returns True
    while Gtk.Window() still raises RuntimeError. Measured, not assumed. The only
    honest way to know whether a widget can be built is to build one.
    """
    try:
        import gi

        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Gtk

        Gtk.Window()
    except (ImportError, ValueError, RuntimeError):
        return False
    return True


requires_display = pytest.mark.skipif(
    not _can_build_widgets(),
    reason="no display, or GTK4/libadwaita typelibs absent: widgets cannot be built",
)


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


@requires_display
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


@requires_display
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


# ---------------------------------------------------------------------------
# Change notification
#
# The tray was announcing every runtime change with LayoutUpdated, which is the
# dbusmenu signal for a changed *item set*. GNOME's appindicator extension reads
# the layout with propertyNames=['type', 'children-display'] and copies only what
# it asked for onto items it already has, so a label change announced that way
# never reaches the screen -- "Protection active" stayed on a menu whose server
# was reporting "Paused", for the life of the session, however many times it was
# reopened. Worse, that host prefers LayoutUpdated in an `else if` and then clears
# its pending-properties flag, so sending it actively suppressed the refresh.
#
# Hence: property changes go out as ItemsPropertiesUpdated, and LayoutUpdated is
# reserved for a genuinely different set of items.
# ---------------------------------------------------------------------------


class _RecordingConnection:
    """Stands in for Gio.DBusConnection, recording only what was emitted."""

    def __init__(self) -> None:
        self.emitted: list[tuple[str, str, str, object]] = []

    def emit_signal(self, _dest, path, interface, name, params):  # noqa: ANN001
        self.emitted.append((path, interface, name, params))


class _RecordingInvocation:
    """Stands in for Gio.DBusMethodInvocation."""

    def __init__(self) -> None:
        self.value = None
        self.error = None

    def return_value(self, value) -> None:  # noqa: ANN001
        self.value = value

    def return_error_literal(self, _domain, _code, message) -> None:  # noqa: ANN001
        self.error = message


def _menu_signals(conn: _RecordingConnection) -> list[str]:
    return [name for _p, iface, name, _v in conn.emitted if iface == MENU_INTERFACE]


def _call_menu(tray: TrayIndicator, method: str, params):  # noqa: ANN001
    invocation = _RecordingInvocation()
    tray._handle_menu_method_call(
        None, None, MENU_OBJECT_PATH, MENU_INTERFACE, method, params, invocation
    )
    assert invocation.error is None, invocation.error
    return invocation.value


def test_a_state_change_announces_properties_not_a_new_layout(
    tray: TrayIndicator,
) -> None:
    tray._connection = conn = _RecordingConnection()
    tray.set_state("redact", True)

    signals = _menu_signals(conn)
    assert "ItemsPropertiesUpdated" in signals
    # The regression: this is the signal that cannot carry a label change, and
    # whose presence stops the host asking for one.
    assert "LayoutUpdated" not in signals


def test_the_property_signal_carries_the_visible_change(tray: TrayIndicator) -> None:
    tray._connection = conn = _RecordingConnection()
    tray.set_state("redact", True)

    params = next(
        v for _p, _i, name, v in conn.emitted if name == "ItemsPropertiesUpdated"
    )
    updated, removed = params.unpack()
    props = dict(updated)

    assert props[TrayIndicator._ID_STATUS]["label"] == "Paused"
    assert props[TrayIndicator._ID_RESUME]["visible"] is True
    # Every item always carries the same key set, so nothing is ever "removed";
    # a host that trusted a non-empty removal list would drop live properties.
    assert removed == []


def test_resuming_reverts_both_the_label_and_the_visibility(
    tray: TrayIndicator,
) -> None:
    tray._connection = conn = _RecordingConnection()
    tray.set_state("redact", True)
    tray.set_state("redact", False)

    params = [v for _p, _i, name, v in conn.emitted if name == "ItemsPropertiesUpdated"]
    updated, _removed = params[-1].unpack()
    props = dict(updated)
    assert props[TrayIndicator._ID_STATUS]["label"] != "Paused"
    assert props[TrayIndicator._ID_RESUME]["visible"] is False


def test_about_to_show_reports_whether_the_host_is_behind(
    tray: TrayIndicator,
) -> None:
    # Reading the layout brings the host up to date...
    _call_menu(tray, "GetLayout", GLib.Variant("(iias)", (0, -1, [])))
    assert _call_menu(tray, "AboutToShow", GLib.Variant("(i)", (0,))).unpack() == (
        False,
    )

    # ...and a state change leaves it behind again. Answering False here is what
    # let hosts that refresh lazily on open render a stale menu.
    tray.set_state("redact", True)
    assert _call_menu(tray, "AboutToShow", GLib.Variant("(i)", (0,))).unpack() == (
        True,
    )


def test_the_layout_and_the_property_signal_cannot_disagree(
    tray: TrayIndicator,
) -> None:
    # Both are built from the same tree on demand, and this is the assertion that
    # keeps it that way: whatever the signal claims, GetLayout must confirm.
    tray._connection = conn = _RecordingConnection()
    tray.set_state("notify", True)

    params = next(
        v for _p, _i, name, v in conn.emitted if name == "ItemsPropertiesUpdated"
    )
    announced = dict(params.unpack()[0])

    _revision, root = _call_menu(
        tray, "GetLayout", GLib.Variant("(iias)", (0, -1, []))
    ).unpack()

    def walk(node) -> None:  # noqa: ANN001
        ident, props, children = node
        for key, value in props.items():
            assert announced[ident][key] == value, (ident, key)
        for child in children:
            walk(child)

    walk(root)


# ---------------------------------------------------------------------------
# The detection notice vs. the protection state
#
# `set_alert` shows "N secrets removed". It used to outrank everything, and
# `clear_alert()` had no caller anywhere in the project -- so one detection pinned
# that line to the menu for the rest of the session, and pausing protection left it
# reading "1 secret removed" above a guard that had stopped guarding. Of all the
# things this menu can get wrong, implying protection is working when it is off is
# the one that costs something.
# ---------------------------------------------------------------------------


def _status_line(tray: TrayIndicator) -> str:
    return TrayIndicator._flatten(tray._build_tree())[TrayIndicator._ID_STATUS][
        "props"
    ]["label"]


def test_the_alert_shows_while_protection_is_engaged(tray: TrayIndicator) -> None:
    tray.set_state("redact", False)
    tray.set_alert(1)
    assert _status_line(tray) == "1 secret removed"


def test_pausing_outranks_the_alert(tray: TrayIndicator) -> None:
    tray.set_alert(1)
    tray.set_state("redact", True)
    assert _status_line(tray) == "Paused"
    assert tray._tooltip_body() == "Paused"
    # And the icon must not keep asking for attention on a paused guard.
    assert tray._status() == "Active"


def test_mode_off_outranks_the_alert(tray: TrayIndicator) -> None:
    tray.set_alert(2)
    tray.set_state("off", False)
    assert _status_line(tray) == "Protection off"
    assert tray._status() == "Active"


def test_the_alert_returns_once_protection_resumes(tray: TrayIndicator) -> None:
    # Resuming does not resurrect it in practice, because the front end clears the
    # notice on any deliberate state change -- but the tray is dumb by design, so
    # what it does on its own is worth pinning down.
    tray.set_alert(1)
    tray.set_state("redact", True)
    assert _status_line(tray) == "Paused"
    tray.set_state("redact", False)
    assert _status_line(tray) == "1 secret removed"


def test_clearing_the_alert_reverts_to_the_mode_line(tray: TrayIndicator) -> None:
    tray.set_alert(3)
    assert _status_line(tray) != "Protected"
    tray.clear_alert()
    assert _status_line(tray) == "Protected"
    assert tray._status() == "Active"


def test_the_alert_says_found_not_removed_when_nothing_was_removed(
    tray: TrayIndicator,
) -> None:
    # notify mode leaves the secret on the clipboard; claiming it was removed
    # would be the same class of lie as the paused case.
    tray.set_state("notify", False)
    tray.set_alert(1)
    assert _status_line(tray) == "1 secret found"
