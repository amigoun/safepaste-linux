"""The graphical front end.

This process owns the Adw.Application main loop and drives a `Daemon` inside it,
which is why Daemon.start() is separate from Daemon.run(): two GLib main loops in
one process would fight over the same file descriptors.

It is a background application with no primary window. `hold()` keeps it alive
without one, and the dialog and preferences window are created on demand. The
daemon remains fully usable headless — `python -m safepaste.daemon` needs none of
this — so a broken toolkit cannot take clipboard protection down with it.
"""

from __future__ import annotations

import logging
import pathlib

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gio, GLib, Gtk  # noqa: E402

from . import config as config_mod
from .daemon import Daemon
from .ui.dialog import present_detection

log = logging.getLogger(__name__)

APP_ID = "dev.safepaste.SafePaste"


class SafePasteApp(Adw.Application):
    def __init__(self, cfg: config_mod.Config | None = None) -> None:
        super().__init__(
            application_id=APP_ID,
            # No window to open, and we must not exit when the last dialog closes.
            flags=Gio.ApplicationFlags.DEFAULT_FLAGS,
        )
        self.config = cfg or config_mod.load()
        self.daemon = Daemon(self.config, on_detection=self._on_detection)
        self.tray = None
        self._prefs_window = None
        self._current_dialog = None
        # A window that is never presented, existing only to be the dialogs'
        # transient parent. SafePaste has no primary window, and GTK complains about
        # every parentless dialog; this is the cheapest thing that satisfies it.
        # Deliberately not associated with the application, so it cannot influence
        # the application's lifecycle.
        self._dialog_parent: Gtk.Window | None = None

    # -- lifecycle ---------------------------------------------------------

    def do_startup(self) -> None:
        Adw.Application.do_startup(self)
        # Keep running with no window on screen.
        self.hold()

        if not self.daemon.start():
            log.error("clipboard protection could not start")
            self.quit()
            return

        self._dialog_parent = Gtk.Window()
        self._dialog_parent.set_default_size(1, 1)
        self._install_actions()
        self._start_tray()

    def do_activate(self) -> None:
        # Re-launching a background app should show its settings rather than
        # silently doing nothing.
        self.show_preferences()

    def do_shutdown(self) -> None:
        if self.tray is not None:
            self.tray.stop()
        self.daemon.shutdown()
        Adw.Application.do_shutdown(self)

    def _install_actions(self) -> None:
        for name, handler in (
            ("safe-paste", lambda *_: self.daemon.safe_paste()),
            ("preferences", lambda *_: self.show_preferences()),
            ("quit", lambda *_: self.quit()),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", handler)
            self.add_action(action)

    # -- tray --------------------------------------------------------------

    def _start_tray(self) -> None:
        # Asked of the backend rather than imported: a platform with no status-icon
        # mechanism returns None, and a desktop with the mechanism but no host
        # running returns False from start(). Neither may stop clipboard
        # protection, which is the part that matters.
        try:
            self.tray = self.daemon.guard.backend.tray(
                on_mode=self._set_mode,
                on_pause=lambda secs: self._set_paused(True, secs),
                on_resume=lambda: self._set_paused(False, 0),
                on_safe_paste=lambda: self.daemon.safe_paste(),
                on_preferences=self.show_preferences,
                on_quit=self.quit,
            )
            if self.tray is None:
                log.info("this platform offers no status icon; running without one")
                return
            if self.tray.start():
                self.tray.set_state(self.config.mode, self.daemon.paused)
            else:
                log.info("no status-notifier host; running without a status icon")
                self.tray = None
        except Exception as exc:  # noqa: BLE001 - the tray is strictly optional
            log.warning("tray failed to start: %s", exc)
            self.tray = None

    def _refresh_tray(self) -> None:
        if self.tray is not None:
            self.tray.set_state(self.config.mode, self.daemon.paused)

    def _set_mode(self, mode: str) -> None:
        self.daemon.set_mode(mode)
        self._refresh_tray()

    def _set_paused(self, paused: bool, seconds: int) -> None:
        self.daemon.set_paused(paused, seconds)
        self._refresh_tray()
        if paused and seconds:
            # Come back and repaint once the pause lapses, so the icon does not
            # sit there claiming to be paused after protection has resumed.
            GLib.timeout_add_seconds(seconds + 1, self._on_pause_lapsed)

    def _on_pause_lapsed(self) -> bool:
        self._refresh_tray()
        return False

    # -- detection presentation --------------------------------------------

    def _on_detection(self, findings: list, result, event) -> None:
        """Called by the daemon after a scan that found something."""
        secrets = result.secrets_removed if result.changed else len(findings)
        if self.tray is not None:
            self.tray.set_alert(secrets)

        mode = self.config.mode
        if mode == "notify":
            self._notify(secrets, result.labels)
            return
        if mode == "off":
            return

        # In redact mode the clipboard has already been replaced; the dialog
        # reports a completed action and offers the undo.
        self._present_dialog(result, event)

    def _present_dialog(self, result, event) -> None:
        if self._current_dialog is not None:
            # A second copy while the first dialog is still open: replace it, so
            # dialogs cannot stack up faster than they are dismissed.
            self._current_dialog.destroy()
            self._current_dialog = None

        self._current_dialog = present_detection(
            secrets=result.secrets_removed,
            labels=result.labels,
            chars_kept=result.chars_kept,
            can_restore=self.config.restore_timeout_secs > 0,
            restore_seconds=self.config.restore_timeout_secs,
            formatting_lost=getattr(event, "has_rich_flavours", False),
            parent=self._dialog_parent,
            on_restore=self._on_restore,
            on_exclude=self._on_exclude,
        )
        self._current_dialog.connect("destroy", self._on_dialog_destroyed)

    def _on_dialog_destroyed(self, *_args) -> None:
        self._current_dialog = None

    def _on_restore(self) -> None:
        if not self.daemon.restore_original():
            self._notify_simple(
                "Could not restore",
                "The original value is no longer being held.",
            )

    def _on_exclude(self) -> None:
        self.daemon.exclude_last_value()

    def _notify(self, secrets: int, labels: tuple[str, ...]) -> None:
        noun = "secret" if secrets == 1 else "secrets"
        body = ", ".join(labels[:3])
        if len(labels) > 3:
            body += f", and {len(labels) - 3} more"
        self._notify_simple(f"{secrets} {noun} on the clipboard", body)

    def _notify_simple(self, title: str, body: str) -> None:
        note = Gio.Notification.new(title)
        note.set_body(body)
        note.set_priority(Gio.NotificationPriority.HIGH)
        # A stable id replaces the previous notification instead of stacking.
        self.send_notification("safepaste-detection", note)

    # -- preferences -------------------------------------------------------

    def show_preferences(self) -> None:
        if self._prefs_window is not None:
            self._prefs_window.present()
            return
        try:
            from .ui.prefs import PreferencesWindow
        except ImportError as exc:
            log.warning("preferences window unavailable: %s", exc)
            return
        self._prefs_window = PreferencesWindow(
            config=self.config, on_changed=self._on_config_changed
        )
        self._prefs_window.connect("close-request", self._on_prefs_closed)
        self._prefs_window.present()

    def _on_prefs_closed(self, *_args) -> bool:
        self._prefs_window = None
        return False

    def _on_config_changed(self) -> None:
        config_mod.save(self.config)
        self.daemon.reload()
        self._refresh_tray()


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(
        prog="safepaste", description="Guard the clipboard against pasted secrets."
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--config", type=pathlib.Path, help="alternative config file")
    args, rest = ap.parse_known_args(argv if argv is not None else sys.argv[1:])

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    cfg = config_mod.load(args.config)
    return SafePasteApp(cfg).run([sys.argv[0], *rest])


if __name__ == "__main__":
    raise SystemExit(main())
