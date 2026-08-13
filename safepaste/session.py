"""Session lock awareness.

This exists because of a concrete, measured failure mode. wl-clipboard has no
clipboard-management protocol to use on Mutter, so it falls back to creating a
surface and waiting for keyboard focus before it can touch the selection. While
the session is locked, the lock screen holds that focus and never yields it, so
`wl-copy` and `wl-paste` block in poll() indefinitely — confirmed by strace, and
reproducible by locking the screen and running `wl-paste`.

The daemon's subprocess timeouts already stop that from wedging anything, but
paying a multi-second timeout per clipboard event while locked is pointless work.
Skipping outright is also the behaviourally correct answer: nothing can paste
while the screen is locked.

Note X11 selections are *not* focus-gated, which is why `xclip` keeps working
throughout — a useful escape hatch, but not one worth taking when the right
answer is simply to wait.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from gi.repository import Gio, GLib

log = logging.getLogger(__name__)

SCREENSAVER_NAMES = (
    # GNOME first, then the common alternatives, so this degrades on other desktops.
    ("org.gnome.ScreenSaver", "/org/gnome/ScreenSaver", "org.gnome.ScreenSaver"),
    ("org.freedesktop.ScreenSaver", "/ScreenSaver", "org.freedesktop.ScreenSaver"),
)


class LockWatcher:
    """Tracks whether the session is locked, if the desktop will tell us.

    If no screensaver interface answers, `locked` stays False forever and the
    daemon behaves exactly as it did before — the subprocess timeouts remain the
    backstop.
    """

    def __init__(self, on_change: Callable[[bool], None] | None = None) -> None:
        self.locked = False
        self.on_change = on_change
        self._proxy: Gio.DBusProxy | None = None
        self._available = False

    def start(self) -> bool:
        for name, path, interface in SCREENSAVER_NAMES:
            try:
                proxy = Gio.DBusProxy.new_for_bus_sync(
                    Gio.BusType.SESSION,
                    Gio.DBusProxyFlags.DO_NOT_AUTO_START,
                    None,
                    name,
                    path,
                    interface,
                    None,
                )
                result = proxy.call_sync(
                    "GetActive", None, Gio.DBusCallFlags.NONE, 2000, None
                )
            except GLib.Error as exc:
                log.debug("%s unavailable: %s", name, exc.message)
                continue

            self._proxy = proxy
            self._available = True
            self.locked = bool(result.unpack()[0])
            proxy.connect("g-signal", self._on_signal)
            log.info(
                "session lock tracking via %s (currently %s)",
                name,
                "locked" if self.locked else "unlocked",
            )
            return True

        log.info("no screensaver interface found; lock tracking disabled")
        return False

    @property
    def available(self) -> bool:
        return self._available

    def _on_signal(self, _proxy, _sender, signal: str, params: GLib.Variant) -> None:
        if signal != "ActiveChanged":
            return
        locked = bool(params.unpack()[0])
        if locked == self.locked:
            return
        self.locked = locked
        log.info("session %s", "locked" if locked else "unlocked")
        if self.on_change is not None:
            self.on_change(locked)

    def refresh(self) -> bool:
        """Re-query, for the case where we missed a signal."""
        if self._proxy is None:
            return self.locked
        try:
            result = self._proxy.call_sync(
                "GetActive", None, Gio.DBusCallFlags.NONE, 2000, None
            )
        except GLib.Error:
            return self.locked
        self.locked = bool(result.unpack()[0])
        return self.locked
