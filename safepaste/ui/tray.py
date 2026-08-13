"""System-tray indicator, spoken directly over D-Bus.

SafePaste is GTK4 (see `safepaste/ui/dialog.py`), but the only tray protocol
GNOME Shell actually renders -- StatusNotifierItem -- has no GTK4-native
binding on this system. The obvious shortcut, `gir1.2-ayatanaappindicator3-
0.1`, is a GTK3 library end to end: it depends on `gir1.2-gtk-3.0`, and
`libayatana-appindicator3-1` depends on `libgtk-3-0t64` plus
`libdbusmenu-gtk3-4`. `AppIndicator.set_menu()` takes a `Gtk.Menu` -- a GTK3
widget. GTK3 and GTK4 cannot both be loaded into one process, so pulling in
AppIndicator here would mean running the tray in a second process, which is
not worth it when the alternative is to speak the two protocols AppIndicator
itself only wraps: `org.kde.StatusNotifierItem` (the tray icon) and
`com.canonical.dbusmenu` (its menu). Both are plain D-Bus, both fully
reachable from `Gio`/`GLib` alone, no new package.

This module registers with `org.kde.StatusNotifierWatcher`, which on this
system is provided by the GNOME Shell extension `ubuntu-appindicators@ubuntu
.com`. If no such watcher is running -- a TTY session, a non-GNOME
compositor without AppIndicator support, a locked-down kiosk -- `start()`
returns False and logs a warning rather than raising. SafePaste's clipboard
protection does not depend on having a tray icon.

Kept deliberately dumb: this class only renders the state it is handed and
forwards clicks through plain callables (`on_mode`, `on_pause`, ...). It has
no opinion on what a mode change *does* -- that decision, and any
consequence of it, belongs to whoever constructs this object. It imports
nothing from `daemon`, and only `MODES` from `config`, to keep that
decoupling real rather than aspirational.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable

import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

from ..config import MODES

log = logging.getLogger(__name__)

# -- StatusNotifierWatcher (the thing we register with) ---------------------

WATCHER_BUS_NAME = "org.kde.StatusNotifierWatcher"
WATCHER_OBJECT_PATH = "/StatusNotifierWatcher"
WATCHER_INTERFACE = "org.kde.StatusNotifierWatcher"

# -- our own two objects ------------------------------------------------------

SNI_INTERFACE = "org.kde.StatusNotifierItem"
SNI_OBJECT_PATH = "/StatusNotifierItem"
MENU_INTERFACE = "com.canonical.dbusmenu"
MENU_OBJECT_PATH = "/MenuBar"

# Icon names, verified present on THIS system (Ubuntu 24.04) by listing the
# theme directories directly (`find /usr/share/icons -iname '*security*'`):
#   /usr/share/icons/Adwaita/symbolic/status/security-high-symbolic.svg
#   /usr/share/icons/Adwaita/symbolic/status/security-low-symbolic.svg
#   /usr/share/icons/Adwaita/symbolic/status/security-medium-symbolic.svg
#   /usr/share/icons/Yaru/scalable/status/security-{high,low,medium}-symbolic.svg
# Present in both the upstream Adwaita theme and Yaru (the active default on
# this machine), so they resolve regardless of which one the panel is
# actually using. These are freedesktop stock "Status Icons" names, not
# SafePaste-specific -- we ship no icon file of our own.
ICON_ACTIVE = "security-high-symbolic"  # protection engaged, not paused
ICON_LOW = "security-low-symbolic"  # paused, or mode "off"
ICON_ALERT = "security-medium-symbolic"  # AttentionIconName: secrets just found

SNI_INTROSPECTION = f"""
<node>
  <interface name="{SNI_INTERFACE}">
    <property name="Category" type="s" access="read"/>
    <property name="Id" type="s" access="read"/>
    <property name="Title" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="WindowId" type="u" access="read"/>
    <property name="IconThemePath" type="s" access="read"/>
    <property name="IconName" type="s" access="read"/>
    <property name="OverlayIconName" type="s" access="read"/>
    <property name="AttentionIconName" type="s" access="read"/>
    <!-- (icon name, icon pixmap list [unused, always empty], title, body) -->
    <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
    <property name="ItemIsMenu" type="b" access="read"/>
    <property name="Menu" type="o" access="read"/>
    <method name="Activate">
      <arg type="i" name="x" direction="in"/>
      <arg type="i" name="y" direction="in"/>
    </method>
    <method name="SecondaryActivate">
      <arg type="i" name="x" direction="in"/>
      <arg type="i" name="y" direction="in"/>
    </method>
    <method name="ContextMenu">
      <arg type="i" name="x" direction="in"/>
      <arg type="i" name="y" direction="in"/>
    </method>
    <method name="Scroll">
      <arg type="i" name="delta" direction="in"/>
      <arg type="s" name="orientation" direction="in"/>
    </method>
    <!-- Per spec, only NewStatus carries its new value; the others are
         "go re-read the property" pokes with no payload. -->
    <signal name="NewTitle"/>
    <signal name="NewIcon"/>
    <signal name="NewToolTip"/>
    <signal name="NewStatus">
      <arg type="s" name="status"/>
    </signal>
  </interface>
</node>
"""

MENU_INTROSPECTION = f"""
<node>
  <interface name="{MENU_INTERFACE}">
    <property name="Version" type="u" access="read"/>
    <property name="TextDirection" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="IconThemePath" type="as" access="read"/>
    <method name="GetLayout">
      <arg type="i" name="parentId" direction="in"/>
      <arg type="i" name="recursionDepth" direction="in"/>
      <arg type="as" name="propertyNames" direction="in"/>
      <arg type="u" name="revision" direction="out"/>
      <!-- (id, properties, children) -- children is an array of THIS SAME
           struct, each one individually wrapped as a variant. Recursive
           D-Bus types must bottom out in "v" precisely because a struct
           cannot directly contain its own type. -->
      <arg type="(ia{{sv}}av)" name="layout" direction="out"/>
    </method>
    <method name="GetGroupProperties">
      <arg type="ai" name="ids" direction="in"/>
      <arg type="as" name="propertyNames" direction="in"/>
      <arg type="a(ia{{sv}})" name="properties" direction="out"/>
    </method>
    <method name="GetProperty">
      <arg type="i" name="id" direction="in"/>
      <arg type="s" name="name" direction="in"/>
      <arg type="v" name="value" direction="out"/>
    </method>
    <method name="Event">
      <arg type="i" name="id" direction="in"/>
      <arg type="s" name="eventId" direction="in"/>
      <arg type="v" name="data" direction="in"/>
      <arg type="u" name="timestamp" direction="in"/>
    </method>
    <method name="EventGroup">
      <arg type="a(isvu)" name="events" direction="in"/>
      <arg type="ai" name="idErrors" direction="out"/>
    </method>
    <method name="AboutToShow">
      <arg type="i" name="id" direction="in"/>
      <arg type="b" name="needUpdate" direction="out"/>
    </method>
    <method name="AboutToShowGroup">
      <arg type="ai" name="ids" direction="in"/>
      <arg type="ai" name="updatesNeeded" direction="out"/>
      <arg type="ai" name="idErrors" direction="out"/>
    </method>
    <signal name="LayoutUpdated">
      <arg type="u" name="revision"/>
      <arg type="i" name="parent"/>
    </signal>
    <signal name="ItemsPropertiesUpdated">
      <arg type="a(ia{{sv}})" name="updatedProps"/>
      <arg type="a(ias)" name="removedProps"/>
    </signal>
  </interface>
</node>
"""

# D-Bus signature for each dbusmenu item property we ever set. Needed because
# the "a{{sv}}" property dict has to be built with each value pre-wrapped as
# its own concrete-typed Variant (see `_wrap_props`).
_PROP_SIG: dict[str, str] = {
    "label": "s",
    "enabled": "b",
    "visible": "b",
    "type": "s",
    "children-display": "s",
    "toggle-type": "s",
    "toggle-state": "i",
}

_MODE_LABELS: dict[str, str] = {
    "redact": "Redact automatically",
    "ask": "Ask every time",
    "notify": "Notify only",
    "off": "Off",
}

# The status line and tooltip both describe "what's true right now"; the
# tray has no reference to the daemon or its rule count by design (see the
# module docstring), so these are deliberately count-free -- unlike, say,
# "Protected -- 231 rules active", which would need a channel this class does
# not have.
_MODE_STATUS: dict[str, str] = {
    "redact": "Protected",
    "ask": "Protected (asks first)",
    "notify": "Notify only",
    "off": "Protection off",
}
_MODE_TOOLTIP: dict[str, str] = {
    "redact": "Protected — redacting automatically",
    "ask": "Protected — asks before redacting",
    "notify": "Notify only",
    "off": "Protection off",
}


class TrayIndicator:
    """A StatusNotifierItem + com.canonical.dbusmenu pair, hand-rolled.

    Construct with plain callables, call `start()` once a main loop is
    running, and drive it afterwards with `set_state()` / `set_alert()` /
    `clear_alert()`. Nothing here touches the clipboard or the detector;
    it only renders whatever it is told and reports clicks upward.
    """

    # Menu item ids. Stable for the process lifetime -- Event()/EventGroup()
    # key off these, so they must not be renumbered per rebuild.
    _ID_ROOT = 0
    _ID_STATUS = 1
    _ID_SEP_1 = 2
    _ID_SAFE_PASTE = 3
    _ID_SEP_2 = 4
    _ID_PROTECTION = 5
    _ID_MODE_BASE = 6  # + enumerate(MODES): redact=6, ask=7, notify=8, off=9
    _ID_PAUSE_15 = 10
    _ID_PAUSE_60 = 11
    _ID_RESUME = 12
    _ID_SEP_3 = 13
    _ID_PREFERENCES = 14
    _ID_QUIT = 15

    def __init__(
        self,
        *,
        on_mode: Callable[[str], None] | None = None,
        on_pause: Callable[[int], None] | None = None,
        on_resume: Callable[[], None] | None = None,
        on_safe_paste: Callable[[], None] | None = None,
        on_preferences: Callable[[], None] | None = None,
        on_quit: Callable[[], None] | None = None,
    ) -> None:
        self._on_mode = on_mode
        self._on_pause = on_pause
        self._on_resume = on_resume
        self._on_safe_paste = on_safe_paste
        self._on_preferences = on_preferences
        self._on_quit = on_quit

        # Rendered state. `set_state` is the only way these two change;
        # `_alert_secrets` is the transient overlay `set_alert`/`clear_alert`
        # control independently of them (see the docstrings below).
        self._mode = "redact"
        self._paused = False
        self._alert_secrets: int | None = None
        self._revision = 1  # dbusmenu layout revision; 0 would mean "never set"

        # A unique bus name per process, as the spec requires -- not the
        # well-known BUS_NAME style daemon.py uses, since many SafePaste
        # processes (and other apps' indicators) share the session bus.
        self._bus_name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"

        self._connection: Gio.DBusConnection | None = None
        self._owner_id: int | None = None
        self._watch_id: int | None = None
        self._sni_registration_id: int | None = None
        self._menu_registration_id: int | None = None
        self._watcher_present = False
        self._registered_with_watcher = False
        self._started = False

        # id -> zero-arg callable. Built once: which id maps to which action
        # never changes, only the label/enabled/visible/toggle-state seen by
        # GetLayout does (computed fresh in `_build_tree` from the fields
        # above). Items with no entry here (status line, separators, the
        # "Protection" submenu parent) are simply not actionable.
        self._actions: dict[int, Callable[[], None]] = {
            self._ID_SAFE_PASTE: self._bound(self._on_safe_paste),
            self._ID_PAUSE_15: self._bound(self._on_pause, 900),
            self._ID_PAUSE_60: self._bound(self._on_pause, 3600),
            self._ID_RESUME: self._bound(self._on_resume),
            self._ID_PREFERENCES: self._bound(self._on_preferences),
            self._ID_QUIT: self._bound(self._on_quit),
        }
        for index, mode in enumerate(MODES):
            self._actions[self._ID_MODE_BASE + index] = self._bound(self._on_mode, mode)

    # -- public API ----------------------------------------------------------

    def start(self) -> bool:
        """Own our bus name, export both objects, and watch for the host.

        Returns False (never raises) only when there is no session bus at all,
        which is genuinely hopeless. A *missing watcher* is not: we still set
        everything up and let `bus_watch_name` attach the moment a host appears.

        That distinction matters on GNOME, which unloads shell extensions while
        the screen is locked. The AppIndicator extension provides the watcher, so
        a daemon that starts while locked — autostart at login, or any restart
        before the first unlock — sees no watcher at all. Bailing out here would
        mean no tray icon for the rest of the session, even after unlocking.
        Nothing about clipboard protection depends on this either way.
        """
        if self._started:
            return True

        try:
            conn = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        except GLib.Error as exc:
            log.warning("tray: no D-Bus session bus available (%s); no tray icon", exc)
            return False

        if not self._watcher_has_owner(conn):
            log.info(
                "tray: %s has no owner yet (the shell extension is unloaded, which "
                "GNOME does while the screen is locked); will attach when it appears",
                WATCHER_BUS_NAME,
            )

        self._started = True
        # Must own our name before RegisterStatusNotifierItem is called, or
        # the watcher rejects it -- registration only happens once BOTH this
        # completes AND the watcher is known present (`_maybe_register_with_watcher`).
        self._owner_id = Gio.bus_own_name(
            Gio.BusType.SESSION,
            self._bus_name,
            Gio.BusNameOwnerFlags.NONE,
            self._on_bus_acquired,
            None,
            self._on_name_lost,
        )
        # bus_watch_name fires name_appeared immediately if the watcher is
        # already there, and again every time it comes back -- which is what
        # lets us re-register after GNOME Shell restarts (e.g. on unlock)
        # drop every StatusNotifierItem registration.
        self._watch_id = Gio.bus_watch_name(
            Gio.BusType.SESSION,
            WATCHER_BUS_NAME,
            Gio.BusNameWatcherFlags.NONE,
            self._on_watcher_appeared,
            self._on_watcher_vanished,
        )
        return True

    def stop(self) -> None:
        """Undo `start()`. Safe to call even if `start()` was never called
        or returned False."""
        if self._watch_id is not None:
            Gio.bus_unwatch_name(self._watch_id)
            self._watch_id = None
        if self._connection is not None:
            if self._sni_registration_id is not None:
                self._connection.unregister_object(self._sni_registration_id)
            if self._menu_registration_id is not None:
                self._connection.unregister_object(self._menu_registration_id)
        self._sni_registration_id = None
        self._menu_registration_id = None
        if self._owner_id is not None:
            Gio.bus_unown_name(self._owner_id)
            self._owner_id = None
        self._connection = None
        self._watcher_present = False
        self._registered_with_watcher = False
        self._started = False

    def set_state(self, mode: str, paused: bool) -> None:
        """Reflect the daemon's actual mode/pause state in the icon and menu."""
        if mode not in MODES:
            log.warning("tray: ignoring unknown mode %r", mode)
            return
        if (mode, paused) == (self._mode, self._paused):
            return
        self._mode = mode
        self._paused = paused
        self._notify_change()

    def set_alert(self, secrets: int) -> None:
        """Show a transient "secrets were just found" state.

        Overlays the status line/icon/tooltip until `clear_alert()`; it does
        not touch `mode`/`paused`, so the Protection submenu's radio tick and
        the Resume item's visibility stay accurate underneath it.
        """
        self._alert_secrets = secrets
        self._notify_change()

    def clear_alert(self) -> None:
        """End the transient alert state, reverting to mode/paused display."""
        if self._alert_secrets is None:
            return
        self._alert_secrets = None
        self._notify_change()

    # -- bus / watcher lifecycle ----------------------------------------------

    def _watcher_has_owner(self, conn: Gio.DBusConnection) -> bool:
        """Synchronous existence check, so `start()` can return a plain bool.

        Bounded to 2s: a wedged session bus should make us degrade, not hang
        whatever is constructing the tray.
        """
        try:
            result = conn.call_sync(
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "NameHasOwner",
                GLib.Variant("(s)", (WATCHER_BUS_NAME,)),
                GLib.VariantType.new("(b)"),
                Gio.DBusCallFlags.NONE,
                2000,
                None,
            )
        except GLib.Error as exc:
            log.debug("tray: NameHasOwner(%s) failed: %s", WATCHER_BUS_NAME, exc)
            return False
        (has_owner,) = result.unpack()
        return has_owner

    def _on_bus_acquired(self, connection: Gio.DBusConnection, name: str) -> None:
        self._connection = connection
        sni_node = Gio.DBusNodeInfo.new_for_xml(SNI_INTROSPECTION)
        self._sni_registration_id = connection.register_object(
            SNI_OBJECT_PATH,
            sni_node.interfaces[0],
            self._handle_sni_method_call,
            self._handle_sni_get_property,
            None,
        )
        menu_node = Gio.DBusNodeInfo.new_for_xml(MENU_INTROSPECTION)
        self._menu_registration_id = connection.register_object(
            MENU_OBJECT_PATH,
            menu_node.interfaces[0],
            self._handle_menu_method_call,
            self._handle_menu_get_property,
            None,
        )
        log.debug("tray: exported %s and %s on %s", SNI_OBJECT_PATH, MENU_OBJECT_PATH, name)
        self._maybe_register_with_watcher()

    def _on_name_lost(self, _connection: Gio.DBusConnection | None, name: str) -> None:
        # Our bus name is pid-suffixed, so losing it means the session bus
        # connection itself went away, not a naming collision.
        log.warning("tray: lost bus name %s", name)
        self._connection = None

    def _on_watcher_appeared(
        self, _connection: Gio.DBusConnection, name: str, owner: str
    ) -> None:
        log.debug("tray: %s appeared (owned by %s)", name, owner)
        self._watcher_present = True
        self._maybe_register_with_watcher()

    def _on_watcher_vanished(self, _connection: Gio.DBusConnection, name: str) -> None:
        log.debug("tray: %s vanished", name)
        self._watcher_present = False
        self._registered_with_watcher = False

    def _maybe_register_with_watcher(self) -> None:
        if self._connection is None or not self._watcher_present:
            return
        if self._registered_with_watcher:
            return
        # Passing just our bus name (not "busname/objectpath") is correct
        # here because our item lives at the default /StatusNotifierItem
        # path -- the alternate form is only needed for a custom path.
        self._connection.call(
            WATCHER_BUS_NAME,
            WATCHER_OBJECT_PATH,
            WATCHER_INTERFACE,
            "RegisterStatusNotifierItem",
            GLib.Variant("(s)", (self._bus_name,)),
            GLib.VariantType.new("()"),
            Gio.DBusCallFlags.NONE,
            -1,
            None,
            self._on_register_reply,
            None,
        )

    def _on_register_reply(
        self, connection: Gio.DBusConnection, res: Gio.AsyncResult, _user_data: object
    ) -> None:
        try:
            connection.call_finish(res)
        except GLib.Error as exc:
            log.warning("tray: RegisterStatusNotifierItem failed: %s", exc)
            return
        self._registered_with_watcher = True
        log.info("tray: registered %s with the StatusNotifierWatcher", self._bus_name)

    # -- change notification ---------------------------------------------------

    def _notify_change(self) -> None:
        self._emit_sni_update()
        self._emit_layout_updated()

    def _emit_sni_update(self) -> None:
        if self._connection is None:
            return
        try:
            # NewIcon/NewToolTip carry no payload -- hosts are expected to
            # re-fetch IconName/ToolTip via Properties.Get in response.
            self._connection.emit_signal(None, SNI_OBJECT_PATH, SNI_INTERFACE, "NewIcon", None)
            self._connection.emit_signal(
                None, SNI_OBJECT_PATH, SNI_INTERFACE, "NewToolTip", None
            )
            self._connection.emit_signal(
                None,
                SNI_OBJECT_PATH,
                SNI_INTERFACE,
                "NewStatus",
                GLib.Variant("(s)", (self._status(),)),
            )
        except GLib.Error as exc:
            log.debug("tray: could not emit SNI update signal(s): %s", exc)

    def _emit_layout_updated(self) -> None:
        self._revision += 1
        if self._connection is None:
            return
        try:
            self._connection.emit_signal(
                None,
                MENU_OBJECT_PATH,
                MENU_INTERFACE,
                "LayoutUpdated",
                GLib.Variant("(ui)", (self._revision, self._ID_ROOT)),
            )
        except GLib.Error as exc:
            log.debug("tray: could not emit LayoutUpdated: %s", exc)

    # -- StatusNotifierItem: properties and methods -----------------------------

    def _status(self) -> str:
        return "NeedsAttention" if self._alert_secrets is not None else "Active"

    def _icon_name(self) -> str:
        if self._paused or self._mode == "off":
            return ICON_LOW
        return ICON_ACTIVE

    def _status_line_text(self) -> str:
        if self._alert_secrets is not None:
            n = self._alert_secrets
            noun = "secret" if n == 1 else "secrets"
            # Only "redact" mode actually changes the clipboard. Saying "removed"
            # in ask/notify mode would be a plain untruth: the secret is still
            # sitting there, which is precisely what the user needs to know.
            verb = "removed" if self._mode == "redact" else "found"
            return f"{n} {noun} {verb}"
        if self._paused:
            return "Paused"
        return _MODE_STATUS.get(self._mode, self._mode)

    def _tooltip_body(self) -> str:
        if self._alert_secrets is not None:
            n = self._alert_secrets
            noun = "secret" if n == 1 else "secrets"
            if self._mode == "redact":
                return f"{n} {noun} removed from the clipboard"
            return f"{n} {noun} still on the clipboard"
        if self._paused:
            return "Paused"
        return _MODE_TOOLTIP.get(self._mode, self._mode)

    def _handle_sni_get_property(
        self, _connection, _sender, _path, _interface, prop: str
    ) -> GLib.Variant | None:
        getters: dict[str, Callable[[], GLib.Variant]] = {
            "Category": lambda: GLib.Variant("s", "SystemServices"),
            "Id": lambda: GLib.Variant("s", "safepaste"),
            "Title": lambda: GLib.Variant("s", "SafePaste"),
            "Status": lambda: GLib.Variant("s", self._status()),
            "WindowId": lambda: GLib.Variant("u", 0),
            "IconThemePath": lambda: GLib.Variant("s", ""),
            "IconName": lambda: GLib.Variant("s", self._icon_name()),
            "OverlayIconName": lambda: GLib.Variant("s", ""),
            "AttentionIconName": lambda: GLib.Variant("s", ICON_ALERT),
            "ToolTip": lambda: GLib.Variant(
                "(sa(iiay)ss)", (self._icon_name(), [], "SafePaste", self._tooltip_body())
            ),
            "ItemIsMenu": lambda: GLib.Variant("b", True),
            "Menu": lambda: GLib.Variant("o", MENU_OBJECT_PATH),
        }
        return getters.get(prop, lambda: None)()

    def _handle_sni_method_call(
        self,
        _connection,
        _sender,
        _path,
        _interface,
        method: str,
        params: GLib.Variant,
        invocation: Gio.DBusMethodInvocation,
    ) -> None:
        try:
            if method == "Activate":
                # Left-click: sanitise now. GNOME normally shows the Menu
                # instead of calling Activate (ItemIsMenu=True), but some
                # hosts call both, so this stays cheap/idempotent.
                self._fire(self._on_safe_paste)
                invocation.return_value(None)
            elif method == "SecondaryActivate":
                # No distinct secondary action is defined for SafePaste;
                # the method still has to exist and reply.
                invocation.return_value(None)
            elif method == "ContextMenu":
                # No-op: ItemIsMenu=True means the host renders our Menu
                # itself rather than calling this.
                invocation.return_value(None)
            elif method == "Scroll":
                invocation.return_value(None)
            else:
                invocation.return_error_literal(
                    Gio.DBusError.quark(),
                    Gio.DBusError.UNKNOWN_METHOD,
                    f"unknown method {method}",
                )
        except Exception as exc:  # noqa: BLE001 - a bad call must not kill the tray
            log.exception("StatusNotifierItem call %s failed", method)
            invocation.return_error_literal(
                Gio.DBusError.quark(), Gio.DBusError.FAILED, str(exc)
            )

    # -- com.canonical.dbusmenu: menu tree ---------------------------------------
    #
    # The tree is rebuilt on demand from current state (self._mode,
    # self._paused, self._alert_secrets) rather than cached, since it is a
    # handful of nodes and this keeps "what GetLayout returns" and "what the
    # icon/tooltip say" impossible to let drift apart.
    #
    # Node shape: {"id": int, "props": dict[str, object], "children": [Node]}.
    # `props` holds raw Python values; `_wrap_props` applies `_PROP_SIG` to
    # produce the GLib.Variant each key needs. Absent keys mean "default"
    # (enabled/visible default True per the dbusmenu spec), kept sparse
    # rather than restating the default on every node.

    def _build_tree(self) -> dict:
        mode_children = [
            {
                "id": self._ID_MODE_BASE + index,
                "props": {
                    "label": _MODE_LABELS.get(mode, mode.capitalize()),
                    "toggle-type": "radio",
                    "toggle-state": 1 if mode == self._mode else 0,
                },
                "children": [],
            }
            for index, mode in enumerate(MODES)
        ]

        return {
            "id": self._ID_ROOT,
            "props": {},
            "children": [
                {
                    "id": self._ID_STATUS,
                    "props": {"label": self._status_line_text(), "enabled": False},
                    "children": [],
                },
                {"id": self._ID_SEP_1, "props": {"type": "separator"}, "children": []},
                {
                    "id": self._ID_SAFE_PASTE,
                    "props": {"label": "Sanitise clipboard now"},
                    "children": [],
                },
                {"id": self._ID_SEP_2, "props": {"type": "separator"}, "children": []},
                {
                    "id": self._ID_PROTECTION,
                    "props": {"label": "Protection", "children-display": "submenu"},
                    "children": mode_children,
                },
                {
                    "id": self._ID_PAUSE_15,
                    "props": {"label": "Pause 15 minutes"},
                    "children": [],
                },
                {
                    "id": self._ID_PAUSE_60,
                    "props": {"label": "Pause 1 hour"},
                    "children": [],
                },
                {
                    "id": self._ID_RESUME,
                    # Only this item's visibility depends on paused state;
                    # the pause items above stay visible even while paused.
                    "props": {"label": "Resume protection", "visible": self._paused},
                    "children": [],
                },
                {"id": self._ID_SEP_3, "props": {"type": "separator"}, "children": []},
                {
                    "id": self._ID_PREFERENCES,
                    "props": {"label": "Preferences…"},
                    "children": [],
                },
                {"id": self._ID_QUIT, "props": {"label": "Quit"}, "children": []},
            ],
        }

    @staticmethod
    def _find(node: dict, target_id: int) -> dict | None:
        if node["id"] == target_id:
            return node
        for child in node["children"]:
            found = TrayIndicator._find(child, target_id)
            if found is not None:
                return found
        return None

    @staticmethod
    def _flatten(node: dict) -> dict[int, dict]:
        flat = {node["id"]: node}
        for child in node["children"]:
            flat.update(TrayIndicator._flatten(child))
        return flat

    @staticmethod
    def _wrap_props(props: dict[str, object], names: list[str]) -> dict[str, GLib.Variant]:
        return {
            key: GLib.Variant(_PROP_SIG[key], value)
            for key, value in props.items()
            if not names or key in names
        }

    def _node_tuple(
        self, node: dict, names: list[str], depth: int
    ) -> tuple[int, dict[str, GLib.Variant], list[GLib.Variant]]:
        """Build the (id, properties, children) tuple GetLayout needs.

        `children` must be a list of GLib.Variant("v", ...) -- each wrapping
        a full (ia{sv}av) struct -- because "av" is an array of variants, and
        a variant value can only be supplied pre-built; every other level
        here is passed as plain dict/list/tuple in one top-level
        GLib.Variant(...) call, which is the only combination PyGObject's
        recursive Variant builder accepts (verified empirically: handing it
        an already-built Variant at a *non*-"v" position raises TypeError).
        """
        props = self._wrap_props(node["props"], names)
        if depth == 0:
            children: list[GLib.Variant] = []
        else:
            next_depth = depth if depth < 0 else depth - 1
            children = [
                GLib.Variant("v", GLib.Variant("(ia{sv}av)", self._node_tuple(child, names, next_depth)))
                for child in node["children"]
            ]
        return (node["id"], props, children)

    def _handle_menu_get_property(
        self, _connection, _sender, _path, _interface, prop: str
    ) -> GLib.Variant | None:
        getters: dict[str, Callable[[], GLib.Variant]] = {
            "Version": lambda: GLib.Variant("u", 3),
            "TextDirection": lambda: GLib.Variant("s", "ltr"),
            "Status": lambda: GLib.Variant("s", "normal"),
            "IconThemePath": lambda: GLib.Variant("as", []),
        }
        return getters.get(prop, lambda: None)()

    def _handle_menu_method_call(
        self,
        _connection,
        _sender,
        _path,
        _interface,
        method: str,
        params: GLib.Variant,
        invocation: Gio.DBusMethodInvocation,
    ) -> None:
        try:
            if method == "GetLayout":
                parent_id, recursion_depth, names = params.unpack()
                root = self._build_tree()
                node = root if parent_id == self._ID_ROOT else self._find(root, parent_id)
                if node is None:
                    raise LookupError(f"no such menu item: {parent_id}")
                layout = self._node_tuple(node, names, recursion_depth)
                invocation.return_value(
                    GLib.Variant("(u(ia{sv}av))", (self._revision, layout))
                )
            elif method == "GetGroupProperties":
                ids, names = params.unpack()
                flat = self._flatten(self._build_tree())
                # Empty `ids` conventionally means "every item" (matches
                # libdbusmenu-glib's server behaviour).
                targets = ids if ids else list(flat)
                properties = [
                    (item_id, self._wrap_props(flat[item_id]["props"], names))
                    for item_id in targets
                    if item_id in flat
                ]
                invocation.return_value(GLib.Variant("(a(ia{sv}))", (properties,)))
            elif method == "GetProperty":
                item_id, name = params.unpack()
                invocation.return_value(GLib.Variant("(v)", (self._get_property(item_id, name),)))
            elif method == "Event":
                item_id, event_id, _data, _timestamp = params.unpack()
                # `_data` is deliberately never logged or inspected: this
                # handler must not become a place clipboard-adjacent content
                # could leak through, even though in practice hosts send a
                # meaningless int here for "clicked".
                if event_id == "clicked":
                    self._fire_action(item_id)
                invocation.return_value(None)
            elif method == "EventGroup":
                (events,) = params.unpack()
                flat = self._flatten(self._build_tree())
                errors = []
                for item_id, event_id, _data, _timestamp in events:
                    if item_id not in flat:
                        errors.append(item_id)
                        continue
                    if event_id == "clicked":
                        self._fire_action(item_id)
                invocation.return_value(GLib.Variant("(ai)", (errors,)))
            elif method == "AboutToShow":
                (_item_id,) = params.unpack()
                # Layout is always pushed proactively via LayoutUpdated (see
                # `_notify_change`), so there is never a lazy update to do here.
                invocation.return_value(GLib.Variant("(b)", (False,)))
            elif method == "AboutToShowGroup":
                (ids,) = params.unpack()
                flat = self._flatten(self._build_tree())
                errors = [item_id for item_id in ids if item_id not in flat]
                invocation.return_value(GLib.Variant("(aiai)", ([], errors)))
            else:
                invocation.return_error_literal(
                    Gio.DBusError.quark(),
                    Gio.DBusError.UNKNOWN_METHOD,
                    f"unknown method {method}",
                )
        except Exception as exc:  # noqa: BLE001 - a bad call must not kill the tray
            log.exception("dbusmenu call %s failed", method)
            invocation.return_error_literal(
                Gio.DBusError.quark(), Gio.DBusError.FAILED, str(exc)
            )

    def _get_property(self, item_id: int, name: str) -> GLib.Variant:
        flat = self._flatten(self._build_tree())
        node = flat.get(item_id)
        if node is None:
            raise LookupError(f"no such menu item: {item_id}")
        if name not in node["props"]:
            # Unset "enabled"/"visible" default true per spec; anything else
            # unset falls back to an empty string rather than erroring the
            # whole call over a property a real host will rarely ask for
            # individually (GetLayout/GetGroupProperties cover the normal path).
            return GLib.Variant("b", True) if name in ("enabled", "visible") else GLib.Variant("s", "")
        return GLib.Variant(_PROP_SIG[name], node["props"][name])

    def _fire_action(self, item_id: int) -> None:
        action = self._actions.get(item_id)
        if action is not None:
            action()

    # -- callback plumbing --------------------------------------------------

    def _fire(self, callback: Callable[..., None] | None, *args: object) -> None:
        if callback is None:
            return
        try:
            callback(*args)
        except Exception:  # noqa: BLE001 - a broken UI callback must not kill the tray
            log.exception("tray: callback raised")

    def _bound(self, callback: Callable[..., None] | None, *args: object) -> Callable[[], None]:
        """A zero-arg closure over `_fire(callback, *args)`, for `_actions`."""
        return lambda: self._fire(callback, *args)
