"""The Linux/GNOME/Wayland backend.

A thin adapter: the substantive implementations stay in the modules that already
own them (`safepaste.clipboard`, `safepaste.session`, `safepaste.hotkey`,
`safepaste.inject`, `safepaste.ui.tray`), and this file only declares which of
them satisfies which protocol.

Every import is deferred into the accessor that needs it, for two reasons. The
tray and injector pull in `gi`, and the CLI — which is pure detection and runs
happily on a headless box — must not import GTK just by importing the package.
And a session without a status-notifier host should lose only its tray icon, not
clipboard protection.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from . import Backend, ClipboardEvent, ClipboardMonitor, ClipboardWriter
from . import HotkeyBinder, Injector, LockWatcher, Tray

log = logging.getLogger(__name__)


class _GsettingsHotkeyBinder:
    """Adapter over safepaste.hotkey, which is module-level rather than a class.

    GNOME 46 has no GlobalShortcuts portal, so the binding goes through
    gnome-settings-daemon's custom-keybindings list — a compositor-level grab,
    which is exactly why it works in every application.
    """

    def available(self) -> bool:
        from .. import hotkey

        return hotkey.available()

    def install(self, binding: str) -> bool:
        from .. import hotkey

        return hotkey.install(binding)

    def uninstall(self) -> bool:
        from .. import hotkey

        return hotkey.uninstall()

    def installed(self) -> bool:
        from .. import hotkey

        return hotkey.installed()

    def conflicts(self, binding: str) -> list[str]:
        from .. import hotkey

        return hotkey.conflicts(binding)


class LinuxBackend(Backend):
    name = "linux"

    def config_dir_name(self) -> tuple[str, ...]:
        # XDG puts everything directly under ~/.config.
        return ("safepaste",)

    # -- mandatory ---------------------------------------------------------

    def clipboard_monitor(
        self, on_change: Callable[[ClipboardEvent], None]
    ) -> ClipboardMonitor:
        from ..clipboard.monitor import XFixesMonitor

        return XFixesMonitor(on_change=on_change)

    def clipboard_writer(self) -> ClipboardWriter:
        from ..clipboard.writer import FallbackWriter

        return FallbackWriter()

    # -- optional ----------------------------------------------------------

    def lock_watcher(self) -> LockWatcher | None:
        # Needed here specifically: wl-clipboard blocks in poll() for as long as
        # the lock screen holds keyboard focus, so the daemon must not even try.
        from ..session import LockWatcher as GnomeLockWatcher

        return GnomeLockWatcher()

    def hotkey_binder(
        self, on_pressed: Callable[[], None] | None = None
    ) -> HotkeyBinder | None:
        # on_pressed is ignored here by design: the binding carries a command line
        # that the desktop launches, so the press arrives over D-Bus rather than as
        # a callback. See Backend.hotkey_binder.
        return _GsettingsHotkeyBinder()

    def injector(
        self,
        restore_token: str | None = None,
        on_restore_token: Callable[[str], None] | None = None,
    ) -> Injector | None:
        from ..inject import PasteInjector, available

        if not available():
            log.info("no RemoteDesktop portal offering keyboard injection")
            return None
        return PasteInjector(
            restore_token=restore_token, on_restore_token=on_restore_token
        )

    def tray(self, **callbacks: Callable) -> Tray | None:
        try:
            from ..ui.tray import TrayIndicator
        except ImportError as exc:
            log.info("tray unavailable (%s)", exc)
            return None
        return TrayIndicator(**callbacks)
