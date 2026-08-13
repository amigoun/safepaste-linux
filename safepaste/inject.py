"""Completing the paste for the user, via the RemoteDesktop portal.

Strictly optional and off by default. Without it, Ctrl+Alt+V sanitises the
clipboard and the user presses Ctrl+V themselves; with it, the keystroke is sent
for them.

Why the portal and not uinput: `/dev/uinput` is root-only here and the user is not
in the `input` group, so `ydotool` is unavailable. `org.freedesktop.portal.
RemoteDesktop` is version 2 on this system with `AvailableDeviceTypes = 7`, so
keyboard injection is offered — at the cost of a one-time consent dialog.
`persist_mode = 2` plus a stored `restore_token` means that consent is asked once
rather than on every paste.

Why Shift+Insert rather than Ctrl+V: Shift+Insert is the other universal paste
binding, understood by GTK, Qt, terminals and browsers alike, and nothing grabs
it. Injecting Ctrl+V would risk re-triggering whatever grabbed Ctrl+V in the
first place.

This only ever runs on the on-demand path, where SafePaste shows no window, so
the target application keeps keyboard focus throughout and there is no focus
restoration to get wrong.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from gi.repository import Gio, GLib

log = logging.getLogger(__name__)

PORTAL_BUS = "org.freedesktop.portal.Desktop"
PORTAL_PATH = "/org/freedesktop/portal/desktop"
REMOTE_DESKTOP_IFACE = "org.freedesktop.portal.RemoteDesktop"
REQUEST_IFACE = "org.freedesktop.portal.Request"

DEVICE_KEYBOARD = 1

# 0 = do not persist, 1 = persist while the app runs, 2 = persist until revoked.
PERSIST_UNTIL_REVOKED = 2

# X11 keysyms. Shift+Insert is the portable "paste" chord.
KEYSYM_SHIFT_L = 0xFFE1
KEYSYM_INSERT = 0xFF63

STATE_RELEASED = 0
STATE_PRESSED = 1


class PasteInjector:
    """Holds a RemoteDesktop session and types a paste chord into it.

    The session is established lazily on first use, because doing it at start-up
    would pop a permission dialog at login for a feature the user may never
    trigger.
    """

    def __init__(
        self,
        restore_token: str | None = None,
        on_restore_token: Callable[[str], None] | None = None,
    ) -> None:
        self.restore_token = restore_token
        # Called with a fresh token so the caller can persist it; that is what
        # makes consent a one-time cost.
        self.on_restore_token = on_restore_token
        self._session: str | None = None
        self._starting = False
        self._pending: list[Callable[[bool], None]] = []
        self._serial = 0

    # -- public API --------------------------------------------------------

    @property
    def ready(self) -> bool:
        return self._session is not None

    def paste(self, done: Callable[[bool], None] | None = None) -> None:
        """Send the paste chord, establishing a session first if needed."""
        if self._session is not None:
            self._send_chord()
            if done:
                done(True)
            return

        def after_session(ok: bool) -> None:
            if ok:
                self._send_chord()
            if done:
                done(ok)

        self._ensure_session(after_session)

    def close(self) -> None:
        if self._session is None:
            return
        try:
            self._bus().call_sync(
                PORTAL_BUS,
                self._session,
                "org.freedesktop.portal.Session",
                "Close",
                None,
                None,
                Gio.DBusCallFlags.NONE,
                2000,
                None,
            )
        except GLib.Error as exc:
            log.debug("closing the portal session failed: %s", exc.message)
        self._session = None

    # -- portal handshake ---------------------------------------------------

    def _bus(self) -> Gio.DBusConnection:
        return Gio.bus_get_sync(Gio.BusType.SESSION, None)

    def _token(self, prefix: str) -> str:
        self._serial += 1
        return f"safepaste_{prefix}_{self._serial}"

    def _request_path(self, bus: Gio.DBusConnection, handle_token: str) -> str:
        """Predict the Request object path so we can subscribe before calling.

        The portal spec documents this path precisely so callers can avoid the
        race where the Response signal arrives before the subscription exists.
        """
        unique = bus.get_unique_name() or ""
        sender = unique.lstrip(":").replace(".", "_")
        return f"{PORTAL_PATH}/request/{sender}/{handle_token}"

    def _call_with_response(
        self,
        bus: Gio.DBusConnection,
        method: str,
        build_args: Callable[[str], GLib.Variant],
        on_response: Callable[[int, dict], None],
    ) -> None:
        handle_token = self._token(method.lower())
        path = self._request_path(bus, handle_token)
        subscription: list[int] = []

        # Gio.DBusConnection.signal_subscribe delivers SEVEN arguments:
        # (connection, sender, path, interface, signal, parameters, user_data).
        # Omitting the trailing user_data raises TypeError inside the callback,
        # where it surfaces as the handshake mysteriously stalling rather than as
        # an obvious error — CreateSession's reply is non-interactive and arrives
        # at once, so the chain dies before the consent dialog is ever requested.
        def handler(_conn, _sender, _path, _iface, _signal, params, _user_data) -> None:
            code, results = params.unpack()
            if subscription:
                bus.signal_unsubscribe(subscription[0])
            on_response(code, results)

        subscription.append(
            bus.signal_subscribe(
                PORTAL_BUS,
                REQUEST_IFACE,
                "Response",
                path,
                None,
                Gio.DBusSignalFlags.NONE,
                handler,
                None,
            )
        )

        try:
            bus.call_sync(
                PORTAL_BUS,
                PORTAL_PATH,
                REMOTE_DESKTOP_IFACE,
                method,
                build_args(handle_token),
                GLib.VariantType("(o)"),
                Gio.DBusCallFlags.NONE,
                5000,
                None,
            )
        except GLib.Error as exc:
            log.error("portal %s failed: %s", method, exc.message)
            bus.signal_unsubscribe(subscription[0])
            on_response(2, {})

    def _ensure_session(self, done: Callable[[bool], None]) -> None:
        self._pending.append(done)
        if self._starting:
            return  # a handshake is already in flight; ride along with it
        self._starting = True

        bus = self._bus()

        def finish(ok: bool) -> None:
            self._starting = False
            waiters, self._pending = self._pending, []
            for waiter in waiters:
                waiter(ok)

        def on_create(code: int, results: dict) -> None:
            if code != 0 or "session_handle" not in results:
                log.warning("portal session was not created (code %d)", code)
                finish(False)
                return
            self._session = results["session_handle"]
            select_devices()

        def select_devices() -> None:
            def on_select(code: int, _results: dict) -> None:
                if code != 0:
                    log.warning("portal SelectDevices refused (code %d)", code)
                    finish(False)
                    return
                start()

            options: dict[str, GLib.Variant] = {
                "handle_token": GLib.Variant("s", ""),
                "types": GLib.Variant("u", DEVICE_KEYBOARD),
                "persist_mode": GLib.Variant("u", PERSIST_UNTIL_REVOKED),
            }
            if self.restore_token:
                options["restore_token"] = GLib.Variant("s", self.restore_token)

            def build(handle_token: str) -> GLib.Variant:
                options["handle_token"] = GLib.Variant("s", handle_token)
                return GLib.Variant("(oa{sv})", (self._session, options))

            self._call_with_response(bus, "SelectDevices", build, on_select)

        def start() -> None:
            def on_start(code: int, results: dict) -> None:
                if code != 0:
                    # Code 1 is the user cancelling the consent dialog. That is a
                    # decision, not a fault: fall back to leaving the sanitised
                    # text on the clipboard for a manual Ctrl+V.
                    log.info(
                        "screen-sharing permission not granted (code %d); "
                        "automatic pasting stays off",
                        code,
                    )
                    self._session = None
                    finish(False)
                    return
                token = results.get("restore_token")
                if token and self.on_restore_token is not None:
                    self.restore_token = token
                    self.on_restore_token(token)
                log.info("portal input session established")
                finish(True)

            def build(handle_token: str) -> GLib.Variant:
                return GLib.Variant(
                    "(osa{sv})",
                    (
                        self._session,
                        "",  # no parent window: this path shows no UI of our own
                        {"handle_token": GLib.Variant("s", handle_token)},
                    ),
                )

            self._call_with_response(bus, "Start", build, on_start)

        def build_create(handle_token: str) -> GLib.Variant:
            return GLib.Variant(
                "(a{sv})",
                (
                    {
                        "handle_token": GLib.Variant("s", handle_token),
                        "session_handle_token": GLib.Variant(
                            "s", self._token("session")
                        ),
                    },
                ),
            )

        self._call_with_response(bus, "CreateSession", build_create, on_create)

    # -- injection ---------------------------------------------------------

    def _notify_keysym(self, keysym: int, state: int) -> None:
        self._bus().call_sync(
            PORTAL_BUS,
            PORTAL_PATH,
            REMOTE_DESKTOP_IFACE,
            "NotifyKeyboardKeysym",
            GLib.Variant("(oa{sv}iu)", (self._session, {}, keysym, state)),
            None,
            Gio.DBusCallFlags.NONE,
            2000,
            None,
        )

    def _send_chord(self) -> None:
        if self._session is None:
            return
        try:
            # Press and release in strict order; a stuck modifier would be worse
            # than a missed paste.
            self._notify_keysym(KEYSYM_SHIFT_L, STATE_PRESSED)
            self._notify_keysym(KEYSYM_INSERT, STATE_PRESSED)
            self._notify_keysym(KEYSYM_INSERT, STATE_RELEASED)
            self._notify_keysym(KEYSYM_SHIFT_L, STATE_RELEASED)
            log.debug("injected Shift+Insert")
        except GLib.Error as exc:
            log.warning("could not inject the paste keystroke: %s", exc.message)
            # The session has probably been revoked; force a fresh handshake next
            # time rather than silently failing forever.
            self._session = None


def available() -> bool:
    """True if the RemoteDesktop portal offers keyboard injection."""
    try:
        bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        result = bus.call_sync(
            PORTAL_BUS,
            PORTAL_PATH,
            "org.freedesktop.DBus.Properties",
            "Get",
            GLib.Variant("(ss)", (REMOTE_DESKTOP_IFACE, "AvailableDeviceTypes")),
            GLib.VariantType("(v)"),
            Gio.DBusCallFlags.NONE,
            2000,
            None,
        )
    except GLib.Error as exc:
        log.debug("RemoteDesktop portal unavailable: %s", exc.message)
        return False
    types = result.unpack()[0]
    return bool(int(types) & DEVICE_KEYBOARD)
